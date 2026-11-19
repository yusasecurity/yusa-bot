import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeFunctionData, encodeFunctionResult, parseAbi, type Address, type Hex } from "viem";
import { formatApprovals, openApprovals, TooManyLogs, type ApprovalSource, type Log } from "./approvals.ts";

const abi = parseAbi([
  "function allowance(address owner, address spender) view returns (uint256)",
  "function isApprovedForAll(address owner, address operator) view returns (bool)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "struct Call3 { address target; bool allowFailure; bytes callData; }",
  "struct Result { bool success; bytes returnData; }",
  "function aggregate3(Call3[] calls) payable returns (Result[] returnData)",
]);
const APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925" as Hex;
const FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31" as Hex;
const OWNER = "0x1111111111111111111111111111111111111111" as Address;
const USDG = "0xAaAaAaAaaAaAaaaAaAAAAAAAAaaaAaAaAaaAaaAa" as Address;
const NFT = "0xBbBbBbBbBBbbbBbBbBbbbBBbbbBbBbbbBBBbbBbB" as Address;
const ROUTER = "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" as Address;
const DRAINER = "0x9f2C6E0B5A1D4C7E8F3a2b1c0d9E8f7a6B5c4d3E" as Address;
const pad = (a: string) => ("0x" + a.slice(2).toLowerCase().padStart(64, "0")) as Hex;

function source(logsByBlock: { block: bigint; log: Log }[], state: Record<string, bigint | boolean>, contracts: Address[], maxPerQuery = Infinity) {
  let logCalls = 0;
  const src: ApprovalSource = {
    head: async () => 1_000_000n,
    logs: async (_o, from, to) => {
      logCalls++;
      const hit = logsByBlock.filter((x) => x.block >= from && x.block <= to).map((x) => x.log);
      if (hit.length > maxPerQuery) throw new TooManyLogs();
      return hit;
    },
    call: async (_to, data) => {
      const { args } = decodeFunctionData({ abi, data });
      const calls = args![0] as readonly { target: Address; callData: Hex }[];
      const results = calls.map((c) => {
        const d = decodeFunctionData({ abi, data: c.callData });
        const key = `${d.functionName}:${c.target}:${(d.args ?? []).join(":")}`.toLowerCase();
        const isUsdg = c.target.toLowerCase() === USDG.toLowerCase();
        if (d.functionName === "symbol") return { success: true, returnData: encodeFunctionResult({ abi, functionName: "symbol", result: isUsdg ? "USDG" : "NFT" }) };
        if (d.functionName === "decimals") return isUsdg ? { success: true, returnData: encodeFunctionResult({ abi, functionName: "decimals", result: 6 }) } : { success: false, returnData: "0x" as Hex };
        const v = state[key];
        if (v === undefined) return { success: false, returnData: "0x" as Hex };
        return { success: true, returnData: typeof v === "boolean" ? encodeFunctionResult({ abi, functionName: "isApprovedForAll", result: v }) : encodeFunctionResult({ abi, functionName: "allowance", result: v }) };
      });
      return encodeFunctionResult({ abi, functionName: "aggregate3", result: results });
    },
    isContract: async (a) => contracts.map((c) => c.toLowerCase()).includes(a.toLowerCase()),
  };
  return { src, logCalls: () => logCalls };
}
const erc20Log = (token: Address, spender: Address): Log => ({ address: token, topics: [APPROVAL, pad(OWNER), pad(spender)] });
const forAllLog = (token: Address, op: Address): Log => ({ address: token, topics: [FOR_ALL, pad(OWNER), pad(op)] });

test("approvals: reports only what is still open, flags wallets and unlimited, reads current state", async () => {
  const { src } = source(
    [
      { block: 10n, log: erc20Log(USDG, ROUTER) },
      { block: 20n, log: erc20Log(USDG, DRAINER) },
      { block: 30n, log: forAllLog(NFT, DRAINER) },
      { block: 40n, log: erc20Log(USDG, ROUTER) },
    ],
    {
      [`allowance:${USDG}:${OWNER}:${ROUTER}`.toLowerCase()]: 250_000_000n,
      [`allowance:${USDG}:${OWNER}:${DRAINER}`.toLowerCase()]: 2n ** 256n - 1n,
      [`isApprovedForAll:${NFT}:${OWNER}:${DRAINER}`.toLowerCase()]: false,
    },
    [USDG, NFT, ROUTER],
  );
  const r = await openApprovals(OWNER, src);
  assert.equal(r.historyComplete, true);
  assert.equal(r.open.length, 2, "revoked setApprovalForAll is not listed");
  assert.equal(r.open[0].spender.toLowerCase(), DRAINER.toLowerCase(), "wallet spender sorts first");
  assert.equal(r.open[0].unlimited, true);
  assert.equal(r.open[0].spenderIsWallet, true);
  const out = formatApprovals(OWNER, r);
  const lines = out.split("\n");
  assert.match(lines[2], /^- ⚠ 0x9f2c.*WALLET, not a contract/i, "wallet group is listed first");
  assert.match(out, /\$USDG unlimited/);
  assert.match(out, /250 \$USDG/);
  assert.match(out, /Worth a look: 1 to plain wallets\./);
  assert.match(out, /full approval history/);
});

test("approvals: empty wallet says so plainly", async () => {
  const { src } = source([], {}, []);
  const out = formatApprovals(OWNER, await openApprovals(OWNER, src));
  assert.match(out, /None found/);
  assert.match(out, /never asks for a signature/);
});

test("approvals: too many logs shrinks the window, and a long history is reported as partial", async () => {
  const many = Array.from({ length: 50 }, (_, i) => ({ block: 999_000n + BigInt(i), log: erc20Log(USDG, ROUTER) }));
  const old = { block: 5n, log: erc20Log(USDG, DRAINER) };
  const { src, logCalls } = source([...many, old], { [`allowance:${USDG}:${OWNER}:${ROUTER}`.toLowerCase()]: 1n }, [USDG, ROUTER], 10);
  const r = await openApprovals(OWNER, src, { maxLogCalls: 6, maxPairs: 300 });
  assert.ok(logCalls() <= 6, "never more log calls than the budget");
  assert.equal(r.historyComplete, false);
  assert.match(formatApprovals(OWNER, r), /long history.*since block/s);
});

test("approvals: Permit2 is grouped as routine, the pair cap is reported honestly", async () => {
  const PERMIT2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3" as Address;
  const { src } = source(
    [{ block: 10n, log: erc20Log(NFT, ROUTER) }, { block: 11n, log: erc20Log(USDG, PERMIT2) }],
    {
      [`allowance:${USDG}:${OWNER}:${PERMIT2}`.toLowerCase()]: 2n ** 256n - 1n,
      [`allowance:${NFT}:${OWNER}:${ROUTER}`.toLowerCase()]: 5n,
    },
    [USDG, NFT, ROUTER, PERMIT2],
  );
  const r = await openApprovals(OWNER, src, { maxLogCalls: 12, maxPairs: 1 });
  assert.equal(r.historyComplete, true);
  assert.equal(r.pairsSeen, 2);
  assert.equal(r.pairsChecked, 1);
  assert.equal(r.open.length, 1, "only the newest pair (block 11) is checked");
  assert.equal(r.open[0].spender.toLowerCase(), PERMIT2.toLowerCase());
  const out = formatApprovals(OWNER, r);
  assert.match(out, /Permit2 \(Uniswap\) 0x0000…8BA3: routine for swaps/);
  assert.match(out, /Nothing unusual/);
  assert.match(out, /newest 1 of 2 token\/spender pairs/);
  assert.ok(!/since block 0/.test(out));
});
