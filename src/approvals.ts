import { decodeFunctionResult, encodeFunctionData, formatUnits, getAddress, parseAbi, type Address, type Hex } from "viem";

const APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925";
const APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31";
const MULTICALL3: Address = "0xcA11bde05977b3631167028862bE2a173976CA11";
const UNLIMITED = 2n ** 128n;

const abi = parseAbi([
  "function allowance(address owner, address spender) view returns (uint256)",
  "function isApprovedForAll(address owner, address operator) view returns (bool)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "struct Call3 { address target; bool allowFailure; bytes callData; }",
  "struct Result { bool success; bytes returnData; }",
  "function aggregate3(Call3[] calls) payable returns (Result[] returnData)",
]);

export interface Log {
  address: Address;
  topics: Hex[];
}

export interface ApprovalSource {
  head(): Promise<bigint>;
  /** Approval and ApprovalForAll logs for `owner` in [from, to]. Throws TooManyLogs with a range that fits. */
  logs(owner: Address, from: bigint, to: bigint): Promise<Log[]>;
  call(to: Address, data: Hex): Promise<Hex>;
  isContract(a: Address): Promise<boolean>;
}

export class TooManyLogs extends Error {
  /** Largest `to` the provider says fits, if it said. */
  fitsTo?: bigint;
  constructor(fitsTo?: bigint) {
    super("too many logs");
    this.fitsTo = fitsTo;
  }
}

export interface OpenApproval {
  token: Address;
  spender: Address;
  kind: "erc20" | "forAll";
  amount?: bigint;
  symbol?: string;
  decimals?: number;
  unlimited: boolean;
  spenderIsWallet: boolean;
}

export interface ApprovalReport {
  open: OpenApproval[];
  scannedFrom: bigint;
  head: bigint;
  /** Scanned back to block 0. */
  historyComplete: boolean;
  pairsChecked: number;
  /** Distinct token/spender pairs seen; above pairsChecked when the cap cut the list. */
  pairsSeen: number;
}

// Contracts whose unlimited approvals are routine. Permit2 verified on Robinhood Chain (code + DOMAIN_SEPARATOR).
const KNOWN_SPENDERS: Record<string, string> = {
  "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2 (Uniswap)",
};

const addrOf = (topic: Hex) => getAddress("0x" + topic.slice(26));

/**
 * Finds approvals still open for `owner`, newest history first. Busy wallets are scanned until
 * `maxLogCalls` runs out, and the report says how far back it got rather than pretending to be complete.
 */
export async function openApprovals(owner: Address, src: ApprovalSource, opts = { maxLogCalls: 12, maxPairs: 300 }): Promise<ApprovalReport> {
  const head = await src.head();
  const seen = new Map<string, { token: Address; spender: Address; kind: "erc20" | "forAll" }>();
  let to = head;
  let from = 0n;
  let calls = 0;
  let complete = false;
  let lowest = head + 1n;
  // Walk backwards so the most recent approvals are always found first.
  let span = head + 1n;
  while (calls < opts.maxLogCalls) {
    from = to + 1n > span ? to + 1n - span : 0n;
    calls++;
    let logs: Log[];
    try {
      logs = await src.logs(owner, from, to);
    } catch (e) {
      if (!(e instanceof TooManyLogs)) throw e;
      // Halve the window; the provider hint is for forward scans, so it only bounds the size.
      const hinted = e.fitsTo !== undefined && e.fitsTo > from ? e.fitsTo - from : span / 2n;
      span = hinted < span / 2n ? hinted : span / 2n;
      if (span < 1000n) span = 1000n;
      continue;
    }
    // Windows go newest to oldest; reversing each keeps the map in true newest-first order for the pair cap.
    for (const l of [...logs].reverse()) {
      if (l.topics.length < 3) continue;
      const kind = l.topics[0] === APPROVAL_FOR_ALL ? "forAll" : l.topics[0] === APPROVAL && l.topics.length === 3 ? "erc20" : null;
      if (!kind) continue;
      const token = getAddress(l.address);
      const spender = addrOf(l.topics[2]);
      seen.set(`${kind}:${token}:${spender}`.toLowerCase(), { token, spender, kind });
    }
    lowest = from;
    if (from === 0n) {
      complete = true;
      break;
    }
    to = from - 1n;
    if (logs.length < 2000) span *= 2n;
  }

  const pairs = [...seen.values()].slice(0, opts.maxPairs);
  const open = await currentState(owner, pairs, src);
  open.sort((a, b) => Number(b.spenderIsWallet) - Number(a.spenderIsWallet) || Number(b.unlimited) - Number(a.unlimited));
  return { open, scannedFrom: lowest, head, historyComplete: complete, pairsChecked: pairs.length, pairsSeen: seen.size };
}

async function currentState(owner: Address, pairs: { token: Address; spender: Address; kind: "erc20" | "forAll" }[], src: ApprovalSource): Promise<OpenApproval[]> {
  if (!pairs.length) return [];
  const calls = pairs.map((p) => ({
    target: p.token,
    allowFailure: true,
    callData: p.kind === "erc20"
      ? encodeFunctionData({ abi, functionName: "allowance", args: [owner, p.spender] })
      : encodeFunctionData({ abi, functionName: "isApprovedForAll", args: [owner, p.spender] }),
  }));
  const results = await multicall(calls, src);
  const open: OpenApproval[] = [];
  for (let i = 0; i < pairs.length; i++) {
    const r = results[i];
    if (!r?.success || r.returnData === "0x") continue;
    const p = pairs[i];
    if (p.kind === "erc20") {
      const amount = decodeFunctionResult({ abi, functionName: "allowance", data: r.returnData });
      if (amount > 0n) open.push({ ...p, amount, unlimited: amount >= UNLIMITED, spenderIsWallet: false });
    } else if (decodeFunctionResult({ abi, functionName: "isApprovedForAll", data: r.returnData })) {
      open.push({ ...p, unlimited: true, spenderIsWallet: false });
    }
  }
  const tokens = [...new Set(open.map((o) => o.token))];
  const meta = await multicall(tokens.flatMap((t) => [
    { target: t, allowFailure: true, callData: encodeFunctionData({ abi, functionName: "symbol" }) },
    { target: t, allowFailure: true, callData: encodeFunctionData({ abi, functionName: "decimals" }) },
  ]), src);
  const info = new Map<string, { symbol?: string; decimals?: number }>();
  tokens.forEach((t, i) => {
    const s = meta[2 * i], d = meta[2 * i + 1];
    const symbol = s?.success && s.returnData !== "0x" ? safe(() => decodeFunctionResult({ abi, functionName: "symbol", data: s.returnData })) : undefined;
    const decimals = d?.success && d.returnData !== "0x" ? safe(() => decodeFunctionResult({ abi, functionName: "decimals", data: d.returnData })) : undefined;
    info.set(t, { symbol, decimals });
  });
  const spenders = [...new Set(open.map((o) => o.spender))];
  const isContract = new Map<string, boolean>();
  for (const s of spenders) isContract.set(s, await src.isContract(s).catch(() => true));
  for (const o of open) {
    Object.assign(o, info.get(o.token));
    o.spenderIsWallet = !isContract.get(o.spender);
  }
  return open;
}

function safe<T>(f: () => T): T | undefined {
  try {
    return f();
  } catch {
    return undefined;
  }
}

async function multicall(calls: { target: Address; allowFailure: boolean; callData: Hex }[], src: ApprovalSource) {
  const out: { success: boolean; returnData: Hex }[] = [];
  for (let i = 0; i < calls.length; i += 150) {
    const data = encodeFunctionData({ abi, functionName: "aggregate3", args: [calls.slice(i, i + 150)] });
    const ret = await src.call(MULTICALL3, data);
    out.push(...decodeFunctionResult({ abi, functionName: "aggregate3", data: ret }));
  }
  return out;
}

const short = (a: string) => `${a.slice(0, 6)}…${a.slice(-4)}`;

const tokenLabel = (o: OpenApproval) => (o.symbol ? "$" + o.symbol : short(o.token));
const amountLabel = (o: OpenApproval) =>
  o.kind === "forAll" ? `all of ${short(o.token)}`
  : o.unlimited ? `${tokenLabel(o)} unlimited`
  : `${o.decimals !== undefined ? Number(formatUnits(o.amount!, o.decimals)).toLocaleString("en-US", { maximumFractionDigits: 4 }) : o.amount} ${tokenLabel(o)}`;

export function formatApprovals(owner: Address, r: ApprovalReport): string {
  const lines = [`Open approvals for ${owner}`, ""];
  if (!r.open.length) lines.push("None found. No token can be spent from this wallet by another address.");

  const bySpender = new Map<string, OpenApproval[]>();
  for (const o of r.open) bySpender.set(o.spender, [...(bySpender.get(o.spender) ?? []), o]);
  const groups = [...bySpender.entries()].map(([spender, list]) => ({ spender, list, wallet: list[0].spenderIsWallet, known: KNOWN_SPENDERS[spender.toLowerCase()] }));
  // Wallets first, then unknown contracts, then known routers; bigger groups first within each.
  groups.sort((a, b) => Number(b.wallet) - Number(a.wallet) || Number(!!a.known) - Number(!!b.known) || b.list.length - a.list.length);

  let wallets = 0;
  let unknownUnlimited = 0;
  for (const g of groups.slice(0, 8)) {
    const shown = g.list.slice(0, 6).map(amountLabel).join(", ");
    const more = g.list.length > 6 ? ` and ${g.list.length - 6} more` : "";
    const head = g.wallet
      ? `⚠ ${g.spender}: a WALLET, not a contract. This is the drainer pattern; revoke it.`
      : g.known ? `${g.known} ${short(g.spender)}: routine for swaps, revoke if you stop trading.`
      : `${g.spender} (contract): check it is an app you use.`;
    lines.push(`- ${head}`, `  ${g.list.length} token${g.list.length === 1 ? "" : "s"}: ${shown}${more}`);
  }
  if (groups.length > 8) lines.push(`- …and ${groups.length - 8} more spenders`);
  for (const g of groups) {
    if (g.wallet) wallets += g.list.length;
    else if (!g.known) unknownUnlimited += g.list.filter((o) => o.unlimited).length;
  }

  if (wallets || unknownUnlimited) {
    const parts = [wallets ? `${wallets} to plain wallets` : "", unknownUnlimited ? `${unknownUnlimited} unlimited to other contracts` : ""].filter(Boolean);
    lines.push("", `Worth a look: ${parts.join(", ")}. Revoke what you don't use at revoke.cash.`);
  } else if (r.open.length) {
    lines.push("", "Nothing unusual. Revoke anything you no longer use at revoke.cash.");
  }

  const coverage = !r.historyComplete
    ? `This wallet has a long history. Checked approvals made since block ${r.scannedFrom}, newest first. Older ones may still be open; revoke.cash shows all of them.`
    : r.pairsSeen > r.pairsChecked
      ? `Checked the full history, and the newest ${r.pairsChecked} of ${r.pairsSeen} token/spender pairs. revoke.cash shows all of them.`
      : "Checked the wallet's full approval history.";
  lines.push("", coverage, "Read-only: this never asks for a signature or a transaction.");
  return lines.join("\n");
}
