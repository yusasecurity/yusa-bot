import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeFunctionData, maxUint256, parseAbi, type Address, type Hex } from "viem";
import { explain, type TxReader } from "./tx.ts";

const TOKEN: Address = "0x1111111111111111111111111111111111111111";
const ROUTER: Address = "0x2222222222222222222222222222222222222222";
const WALLET: Address = "0x9f2c6e0b5a1d4c7e8f3a2b1c0d9e8f7a6b5c4d3e";
const NFT: Address = "0x3333333333333333333333333333333333333333";
const abi = parseAbi([
  "function approve(address spender, uint256 amount)",
  "function transfer(address to, uint256 amount)",
  "function setApprovalForAll(address operator, bool approved)",
  "function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)",
]);
const contracts = new Set([TOKEN, ROUTER, NFT].map((a) => a.toLowerCase()));
const reader: TxReader = {
  transaction: async () => null,
  isContract: async (a) => contracts.has(a.toLowerCase()),
  token: async (a) => (a.toLowerCase() === TOKEN.toLowerCase() ? { symbol: "USDG", decimals: 6 } : {}),
};
const run = (to: Address, data: Hex, value = 0n) => explain({ to, data, value }, reader);

test("unlimited approve to a plain wallet is DANGER and says why", async () => {
  const r = await run(TOKEN, encodeFunctionData({ abi, functionName: "approve", args: [WALLET, maxUint256] }));
  assert.equal(r.verdict, "block");
  assert.match(r.lines.join("\n"), /spend UNLIMITED of \$USDG/);
  assert.match(r.lines.join("\n"), /is a wallet, not a contract/);
});

test("bounded approve to a contract is shown with real decimals and stays routine", async () => {
  const r = await run(TOKEN, encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, 25_000_000n] }));
  assert.equal(r.verdict, "allow");
  assert.match(r.lines[0], /spend 25 USDG/);
});

test("unlimited approve to a contract asks you to check", async () => {
  const r = await run(TOKEN, encodeFunctionData({ abi, functionName: "approve", args: [ROUTER, maxUint256] }));
  assert.equal(r.verdict, "review");
  assert.match(r.lines.join("\n"), /every one of these tokens/);
});

test("setApprovalForAll true to a wallet is DANGER, false is a safe revoke", async () => {
  assert.equal((await run(NFT, encodeFunctionData({ abi, functionName: "setApprovalForAll", args: [WALLET, true] }))).verdict, "block");
  const off = await run(NFT, encodeFunctionData({ abi, functionName: "setApprovalForAll", args: [WALLET, false] }));
  assert.equal(off.verdict, "allow");
  assert.match(off.lines[0], /revokes/);
});

test("permit to a wallet is DANGER", async () => {
  const z = `0x${"0".repeat(64)}` as Hex;
  const r = await run(TOKEN, encodeFunctionData({ abi, functionName: "permit", args: [ROUTER, WALLET, maxUint256, 1900000000n, 27, z, z] }));
  assert.equal(r.verdict, "block");
  assert.match(r.lines[0], /valid until 2030-03-17/);
});

test("plain transfer is described, not alarmed", async () => {
  const r = await run(TOKEN, encodeFunctionData({ abi, functionName: "transfer", args: [WALLET, 1_500_000n] }));
  assert.equal(r.verdict, "allow");
  assert.match(r.lines[0], /sends 1\.5 USDG/);
});

test("unknown function lists the addresses inside and flags wallets", async () => {
  const data = (`0xdeadbeef${WALLET.slice(2).padStart(64, "0")}${"0".repeat(63)}1`) as Hex;
  const r = await run(ROUTER, data);
  assert.equal(r.verdict, "review");
  assert.match(r.lines.join("\n"), /not one this bot decodes/);
  assert.match(r.lines.join("\n"), new RegExp(`${WALLET} \\(wallet\\)`, "i"));
  assert.ok(!/0x0{8}/.test(r.lines.join("\n")), "no padded-number fake addresses");
});

test("ETH value and empty calldata", async () => {
  const r = await run(WALLET, "0x", 10n ** 17n);
  assert.match(r.lines[0], /Sends 0\.1 ETH/);
  assert.equal((await run(WALLET, "0x")).lines[0], "No calldata and no value: does nothing to your tokens.");
});
