import { decodeFunctionData, formatUnits, getAddress, parseAbi, type Address, type Hex } from "viem";
import { decodeCalldata } from "../../yusa/src/engine/policy.ts";

const abi = parseAbi([
  "function approve(address spender, uint256 amount)",
  "function increaseAllowance(address spender, uint256 addedValue)",
  "function transfer(address to, uint256 amount)",
  "function transferFrom(address from, address to, uint256 amount)",
  "function setApprovalForAll(address operator, bool approved)",
  "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)",
  "function approve(address token, address spender, uint160 amount, uint48 expiration)",
]);

const UNLIMITED = 2n ** 128n;

export interface TokenMeta {
  symbol?: string;
  decimals?: number;
}

export interface TxReader {
  /** null = no transaction with that hash. */
  transaction(hash: Hex): Promise<{ from: Address; to: Address | null; input: Hex; value: bigint } | null>;
  isContract(address: Address): Promise<boolean>;
  token(address: Address): Promise<TokenMeta>;
}

export interface Explained {
  lines: string[];
  verdict: "allow" | "review" | "block";
}

const short = (a: string) => `${a.slice(0, 8)}…${a.slice(-4)}`;

/** Address-shaped 32-byte words at the top level and in nested calls whose bytes start 4 past a word boundary. */
export function alignedAddresses(data: Hex): Address[] {
  const h = data.slice(2).toLowerCase();
  const out = new Set<Address>();
  for (const base of [8, 16]) {
    for (let p = base; p + 64 <= h.length; p += 64) {
      const a = h.slice(p + 24, p + 64);
      // 6+ zero bytes in a row is a packed number, not an address (vanity ones like Permit2 have 5).
      if (/^0{24}/.test(h.slice(p, p + 64)) && !/0{12}/.test(a) && !/0{8}$/.test(a) && !/^f{40}$/.test(a)) out.add(getAddress("0x" + a));
    }
  }
  // Reading at the wrong 4-byte offset yields a shifted copy of a real address; keep the one with fewer leading zeros.
  const lead = (x: string) => x.slice(2).match(/^0*/)![0].length;
  const all = [...out];
  return all.filter((a) => {
    const core = a.slice(2).toLowerCase().replace(/^0+/, "").slice(0, 24);
    return !all.some((b) => b !== a && lead(b) < lead(a) && b.toLowerCase().includes(core));
  });
}

function amount(v: bigint, meta: TokenMeta): string {
  if (v >= UNLIMITED) return "UNLIMITED";
  if (meta.decimals === undefined) return `${v} (raw units)`;
  return `${Number(formatUnits(v, meta.decimals)).toLocaleString("en-US", { maximumFractionDigits: 6 })}${meta.symbol ? " " + meta.symbol : ""}`;
}

/**
 * Plain-language read of what a transaction does to your tokens. Approvals and transfers to
 * a wallet (not a contract) are the classic drainer pattern, so that is called out.
 */
export async function explain(input: { to: Address | null; data: Hex; value?: bigint }, r: TxReader): Promise<Explained> {
  const lines: string[] = [];
  let verdict: Explained["verdict"] = "allow";
  const raise = (v: Explained["verdict"]) => {
    if (v === "block" || (v === "review" && verdict === "allow")) verdict = v;
  };
  const meta: TokenMeta = input.to ? await r.token(input.to).catch((): TokenMeta => ({})) : {};
  const tokenName = input.to ? `${meta.symbol ? "$" + meta.symbol + " " : ""}${short(input.to)}` : "(contract creation)";

  if (input.value && input.value > 0n) lines.push(`Sends ${formatUnits(input.value, 18)} ETH to ${input.to ? short(input.to) : "a new contract"}.`);
  if (input.data === "0x" || input.data.length < 10) {
    if (!lines.length) lines.push("No calldata and no value: does nothing to your tokens.");
    return { lines, verdict };
  }

  const spenderCheck = async (who: Address, role: string) => {
    const contract = await r.isContract(who).catch(() => true);
    if (!contract) {
      lines.push(`⚠ The ${role} ${who} is a wallet, not a contract. Approving or sending to a plain wallet is how drainers take tokens.`);
      raise("block");
    } else lines.push(`The ${role} ${who} is a contract. Check it is the app you meant to use.`);
  };

  let decoded: { functionName: string; args?: readonly unknown[] } | null = null;
  try {
    decoded = decodeFunctionData({ abi, data: input.data });
  } catch {
    decoded = null;
  }

  if (decoded) {
    const a = decoded.args ?? [];
    switch (decoded.functionName) {
      case "approve":
        if (a.length === 4) {
          const [token, spender, amt] = a as [Address, Address, bigint];
          const tm = await r.token(token).catch((): TokenMeta => ({}));
          lines.push(`Permit2 approve: lets ${spender} spend ${amount(amt, tm)} of ${tm.symbol ? "$" + tm.symbol + " " : ""}${short(token)}.`);
          if (amt >= 2n ** 159n) raise("review");
          await spenderCheck(spender, "spender");
        } else {
          const [spender, amt] = a as [Address, bigint];
          lines.push(`approve: lets ${spender} spend ${amount(amt, meta)} of ${tokenName}.`);
          if (amt >= UNLIMITED) {
            lines.push("Unlimited: that address can take every one of these tokens you hold now or later, until you revoke it.");
            raise("review");
          }
          await spenderCheck(spender, "spender");
        }
        break;
      case "increaseAllowance": {
        const [spender, amt] = a as [Address, bigint];
        lines.push(`increaseAllowance: lets ${spender} spend ${amount(amt, meta)} more of ${tokenName}.`);
        if (amt >= UNLIMITED) raise("review");
        await spenderCheck(spender, "spender");
        break;
      }
      case "transfer": {
        const [to, amt] = a as [Address, bigint];
        lines.push(`transfer: sends ${amount(amt, meta)} of ${tokenName} to ${to}.`);
        break;
      }
      case "transferFrom": {
        const [from, to, amt] = a as [Address, Address, bigint];
        lines.push(`transferFrom: moves ${amount(amt, meta)} of ${tokenName} from ${from} to ${to}.`);
        break;
      }
      case "setApprovalForAll": {
        const [operator, approved] = a as [Address, boolean];
        if (approved) {
          lines.push(`setApprovalForAll: hands ${operator} control of EVERY item you own in collection ${short(input.to ?? "0x")}.`);
          raise("review");
          await spenderCheck(operator, "operator");
        } else lines.push(`setApprovalForAll(false): revokes ${operator}. This is safe.`);
        break;
      }
      case "permit": {
        const [owner, spender, value, deadline] = a as [Address, Address, bigint, bigint];
        lines.push(`permit: ${short(owner)} lets ${spender} spend ${amount(value, meta)} of ${tokenName}, valid until ${new Date(Number(deadline) * 1000).toISOString().slice(0, 10)}.`);
        if (value >= UNLIMITED) raise("review");
        await spenderCheck(spender, "spender");
        break;
      }
    }
  } else {
    const d = decodeCalldata(input.data);
    const sel = input.data.slice(0, 10);
    lines.push(`Function ${sel} is not one this bot decodes (approve, transfer, setApprovalForAll, permit). It may be a swap, a mint or anything else.`);
    raise("review");
    // Show only 32-byte-aligned address words: the engine's 4-byte scan also hits ABI offsets
    // straddling an address (0x00000040…4337112c), which is fine for blocking but noise to a reader.
    const aligned = alignedAddresses(input.data).filter((x) => !input.to || x.toLowerCase() !== input.to.toLowerCase());
    if (aligned.length) {
      const named: string[] = [];
      for (const x of aligned.slice(0, 6)) {
        const isC = await r.isContract(x).catch(() => true);
        const t = isC ? await r.token(x).catch((): TokenMeta => ({})) : {};
        named.push(`${x} (${t.symbol ? "$" + t.symbol + " token" : isC ? "contract" : "wallet"})`);
      }
      lines.push(`Addresses it passes: ${named.join(", ")}${aligned.length > 6 ? ` and ${aligned.length - 6} more` : ""}.`);
    }
    if (d?.unlimited) {
      lines.push("Contains an unlimited approval.");
      raise("block");
    }
    if (d?.approvalForAll) {
      lines.push("Contains setApprovalForAll(true).");
      raise("review");
    }
  }
  return { lines, verdict };
}
