import {
  createPublicClient,
  decodeFunctionData,
  getAddress,
  http,
  parseAbi,
  parseAbiItem,
  type Address,
  type Hex,
} from "viem";

export const FACTORY: Address = "0x7eD598BcEf8bd9Edd8C97A195C6d13f40801EC7e";
const LOG_WINDOW = 10_000_000n; // public RPC limit per eth_getLogs

const STRUCTS = [
  "struct Socials { string twitter; string telegram; string discord; string website; string farcaster; }",
  "struct TokenParams { string name; string symbol; string logo; string description; Socials socials; address creatorFeeRecipient; uint16 creatorTaxBps; bool buybackEnabled; bytes32 expectedEconomics; bytes32 salt; }",
];
const launchAbi = parseAbi([
  ...STRUCTS,
  "function launchToken(TokenParams params, uint256 launchConfigId, address pairToken, address[] snipeTaxExemptions) payable returns (address token, address curve)",
  "function launchAndBuy(TokenParams params, uint256 launchConfigId, address pairToken, uint256 quoteIn, uint256 minTokensOut, address recipient, address[] snipeTaxExemptions) payable returns (address token, address curve, uint256 tokensOut)",
]);
const factoryAbi = parseAbi([
  "struct LaunchedToken { address token; address curve; address deployer; address creatorFeeRecipient; address pairToken; uint256 graduationThreshold; uint24 poolFee; int24 tickSpacing; uint16 creatorTaxBps; bool buybackEnabled; uint8 phase; uint256 sweptQuote; uint256 sweptTokens; uint256 sweptAt; bool exists; }",
  "function getLaunchedToken(address token) view returns (LaunchedToken)",
]);
const launchedEvent = parseAbiItem(
  "event TokenLaunched(address indexed token, address indexed curve, address indexed deployer, address pairToken, uint256 launchConfigId, uint256 graduationThreshold)",
);
const erc20 = parseAbi([
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function balanceOf(address) view returns (uint256)",
]);

export const client = createPublicClient({ transport: http(process.env.RPC_URL || "https://rpc.mainnet.chain.robinhood.com") });

export interface PonsInfo {
  phase: number;
  creatorTaxBps: number;
  deployer: Address;
  curve: Address;
  launch?: { description: string; logo: string; socials: Record<string, string> };
}

export interface TokenInfo {
  address: Address;
  contract: boolean;
  name?: string;
  symbol?: string;
  pons?: PonsInfo;
}

interface LaunchParams {
  description: string;
  logo: string;
  socials: Record<string, string>;
}

const launchCache = new Map<string, PonsInfo["launch"] | null>();

async function launchParams(token: Address): Promise<PonsInfo["launch"] | null> {
  const key = token.toLowerCase();
  if (launchCache.has(key)) return launchCache.get(key) ?? null;
  const head = await client.getBlockNumber();
  let result: PonsInfo["launch"] | null = null;
  for (let to = head; to >= 0n; to -= LOG_WINDOW) {
    const from = to >= LOG_WINDOW ? to - LOG_WINDOW + 1n : 0n;
    const logs = await client.getLogs({ address: FACTORY, event: launchedEvent, args: { token }, fromBlock: from, toBlock: to });
    if (logs.length) {
      const tx = await client.getTransaction({ hash: logs[0].transactionHash! });
      try {
        const p = decodeFunctionData({ abi: launchAbi, data: tx.input }).args?.[0] as LaunchParams | undefined;
        if (p) result = { description: p.description, logo: p.logo, socials: { ...p.socials } };
      } catch {
        // Launched through some other contract; the metadata is not in this calldata.
      }
      break;
    }
    if (from === 0n) break;
  }
  launchCache.set(key, result);
  return result;
}

export async function tokenInfo(address: string): Promise<TokenInfo> {
  const token = getAddress(address);
  const code = await client.getCode({ address: token });
  if (!code || code === "0x") return { address: token, contract: false };
  const [name, symbol, launched] = await Promise.allSettled([
    client.readContract({ address: token, abi: erc20, functionName: "name" }),
    client.readContract({ address: token, abi: erc20, functionName: "symbol" }),
    client.readContract({ address: FACTORY, abi: factoryAbi, functionName: "getLaunchedToken", args: [token] }),
  ]);
  const info: TokenInfo = {
    address: token,
    contract: true,
    name: name.status === "fulfilled" ? name.value : undefined,
    symbol: symbol.status === "fulfilled" ? symbol.value : undefined,
  };
  if (launched.status === "fulfilled" && launched.value.exists) {
    const l = launched.value;
    info.pons = { phase: l.phase, creatorTaxBps: l.creatorTaxBps, deployer: l.deployer, curve: l.curve };
    info.pons.launch = (await launchParams(token)) ?? undefined;
  }
  return info;
}

let decimalsCache: number | undefined;

/** Whole-token balance of `holder` in the gating token, rounded down. */
export async function holdings(gatingToken: Address, holder: Address): Promise<number> {
  decimalsCache ??= await client.readContract({ address: gatingToken, abi: erc20, functionName: "decimals" });
  const raw = await client.readContract({ address: gatingToken, abi: erc20, functionName: "balanceOf", args: [holder] });
  return Number(raw / 10n ** BigInt(decimalsCache));
}

export const txReader = {
  async transaction(hash: Hex) {
    try {
      const t = await client.getTransaction({ hash });
      return { from: t.from, to: t.to ?? null, input: t.input, value: t.value };
    } catch (e) {
      if ((e as Error).name === "TransactionNotFoundError") return null;
      throw e;
    }
  },
  async isContract(address: Address) {
    const code = await client.getCode({ address });
    return !!code && code !== "0x";
  },
  async token(address: Address) {
    const [symbol, decimals] = await Promise.allSettled([
      client.readContract({ address, abi: erc20, functionName: "symbol" }),
      client.readContract({ address, abi: erc20, functionName: "decimals" }),
    ]);
    return {
      symbol: symbol.status === "fulfilled" ? symbol.value : undefined,
      decimals: decimals.status === "fulfilled" ? decimals.value : undefined,
    };
  },
};

/** EIP-191 signature check; also accepts ERC-1271 smart wallets. */
export function verifySignature(address: Address, message: string, signature: Hex): Promise<boolean> {
  return client.verifyMessage({ address, message, signature });
}
