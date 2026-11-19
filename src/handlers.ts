import { randomBytes } from "node:crypto";
import { getAddress, isAddress, type Address, type Hex } from "viem";
import { english as BIP39 } from "viem/accounts";
import { maskSecrets, scan, type ScanResult } from "../../yusa/src/engine/scan.ts";
import type { TokenInfo } from "./chain.ts";
import { agentView, FetchError, type Page } from "./page.ts";
import { explain, type TxReader } from "./tx.ts";
import { formatApprovals, openApprovals, type ApprovalSource } from "./approvals.ts";
import type { Store } from "./store.ts";

export interface Config {
  gatingToken: Address;
  minHold: number;
  freePerDay: number;
  holderPerDay: number;
  linkPage: string;
}

export interface Chain {
  tokenInfo(address: string): Promise<TokenInfo>;
  holdings(token: Address, holder: Address): Promise<number>;
  verifySignature(address: Address, message: string, signature: Hex): Promise<boolean>;
  fetchPage(url: string): Promise<Page>;
  tx: TxReader;
  /** Null when no log-capable RPC is configured; /approvals then says it is off. */
  approvals?: ApprovalSource | null;
}

export interface Ctx {
  userId: number;
  private: boolean;
  chatId?: number;
  /** Group admin or creator; set by the transport for group messages. */
  isAdmin?: () => Promise<boolean>;
}

const CHALLENGE_TTL_MS = 15 * 60_000;
const BALANCE_TTL_MS = 5 * 60_000;
const MAX_TEXT = 20_000;
// Passive checks a guarded group gets per day; each CA, link or hidden-text scan uses one.
const GROUP_CHECKS_PER_DAY = 200;
const MAX_ITEMS_PER_MESSAGE = 3;
// /approvals runs many paid RPC calls, so one per user per minute.
const APPROVALS_COOLDOWN_MS = 60_000;
// Keys pasted by mistake: 64 hex without 0x (tx hashes carry 0x), or a 12/24-word phrase on its own.
const BARE_KEY = /(?<![0-9a-fx])[0-9a-f]{64}(?![0-9a-f])/i;
const BIP39_WORDS = new Set(BIP39);
function looksLikeSeed(text: string): boolean {
  const words = text.trim().toLowerCase().split(/\s+/);
  return [12, 15, 18, 21, 24].includes(words.length) && words.every((w) => BIP39_WORDS.has(w));
}

export function linkMessage(userId: number, address: string, nonce: string, expires: string): string {
  return `YUSA bot wallet link\nTelegram user: ${userId}\nWallet: ${address}\nNonce: ${nonce}\nExpires: ${expires}\nThis signature moves nothing and costs nothing.`;
}

export class Bot {
  private challenges = new Map<number, { address: Address; message: string; exp: number }>();
  private lastApprovals = new Map<number, number>();
  private balances = new Map<string, { n: number; at: number }>();

  private store: Store;
  private chain: Chain;
  private cfg: Config;
  private now: () => number;

  constructor(store: Store, chain: Chain, cfg: Config, now = () => Date.now()) {
    this.store = store;
    this.chain = chain;
    this.cfg = cfg;
    this.now = now;
  }

  async handle(ctx: Ctx, input: string): Promise<string | null> {
    const text = input.trim();
    const m = text.match(/^\/([a-z_]+)(?:@\w+)?(?:\s+([\s\S]*))?$/i);
    const cmd = m?.[1].toLowerCase();
    const arg = (m?.[2] ?? "").trim();

    if (!cmd) {
      if (!ctx.private) return ctx.chatId !== undefined && this.store.group(ctx.chatId).guard ? this.guardMessage(ctx.chatId, text) : null;
      if (/^0x[0-9a-f]{130}$/i.test(text)) return this.verify(ctx, text);
      if (/^0x[0-9a-f]{64}$/i.test(text)) return this.metered(ctx, () => this.tx(text));
      if (/^0x[0-9a-f]{40}$/i.test(text)) return this.metered(ctx, () => this.ca(text));
      if (/^https?:\/\/\S+$/i.test(text)) return this.metered(ctx, () => this.url(text));
      return this.metered(ctx, () => this.scanText(text));
    }

    switch (cmd) {
      case "start":
      case "help":
        return this.help();
      case "scan":
        if (!arg) return "Usage: /scan <text>\nOr in a private chat, just send the text.";
        return this.metered(ctx, () => this.scanText(arg));
      case "ca":
        if (!isAddress(arg, { strict: false })) return "Usage: /ca <0x token address>";
        return this.metered(ctx, () => this.ca(arg));
      case "url":
        if (!/^https?:\/\/\S+$/i.test(arg)) return "Usage: /url <https://link>\nOr in a private chat, just send the link.";
        return this.metered(ctx, () => this.url(arg));
      case "tx":
        if (!/^0x[0-9a-f]{64}$/i.test(arg) && !/^0x[0-9a-f]{40}\s+0x[0-9a-f]{8,}$/i.test(arg)) {
          return "Usage:\n/tx <tx hash>  explain a Robinhood Chain transaction\n/tx <contract> <calldata>  explain a transaction before you sign it (paste the 'to' address and the hex 'data' your wallet shows)";
        }
        return this.metered(ctx, () => this.tx(arg));
      case "approvals": {
        const target = arg || this.store.user(ctx.userId).address || "";
        if (!isAddress(target, { strict: false })) return "Usage: /approvals <wallet>\nOr link a wallet first with /link, then just /approvals.";
        if (!this.chain.approvals) return "Approval checks are switched off on this bot right now.";
        const last = this.lastApprovals.get(ctx.userId) ?? 0;
        if (this.now() - last < APPROVALS_COOLDOWN_MS) return `One approval check per minute. Try again in ${Math.ceil((APPROVALS_COOLDOWN_MS - (this.now() - last)) / 1000)} s.`;
        this.lastApprovals.set(ctx.userId, this.now());
        return this.metered(ctx, () => this.approvals(getAddress(target)));
      }
      case "link":
        return this.link(ctx, arg);
      case "verify":
        return this.verify(ctx, arg);
      case "unlink": {
        const u = this.store.user(ctx.userId);
        delete u.address;
        delete u.linkedAt;
        this.store.save();
        return "Wallet unlinked. You are on the free tier.";
      }
      case "me":
        return this.me(ctx);
      case "guard":
        return this.guardCommand(ctx, arg.toLowerCase());
      default:
        return null;
    }
  }

  private help(): string {
    return [
      "YUSA scans text for prompt injection: hidden Unicode, look-alike letters, fake system prompts, drain and exfiltration orders.",
      "",
      "/scan <text>  scan any text (in a private chat, just send it)",
      "/ca <address>  scan a Robinhood Chain token: name, symbol, and for Pons launches the description and socials your agent would read",
      "/url <link>  fetch a web page and scan what an agent would read from it, including comments and CSS-hidden text",
      "/tx <hash>  explain what a Robinhood Chain transaction does to your tokens. Before signing: /tx <contract> <calldata>",
      "/approvals <wallet>  list token approvals still open on a wallet, and flag unlimited ones and approvals to plain wallets",
      "/me  your tier and scans left today",
      "/guard on  (group admins) check every token address, link and hidden text members post; the bot stays quiet unless something is wrong",
      "/link <wallet>  link a wallet to get the holder tier",
      "/unlink",
      "",
      `Free: ${this.cfg.freePerDay} scans a day. Holding ${this.cfg.minHold.toLocaleString("en-US")}+ $YUSA in a linked wallet: ${this.cfg.holderPerDay} a day.`,
      "YUSA itself stays free and open source: github.com/yusasecurity/yusa",
      "The bot never asks for a private key, a seed phrase or a transaction.",
    ].join("\n");
  }

  private day(): string {
    return new Date(this.now()).toISOString().slice(0, 10);
  }

  private async tier(ctx: Ctx): Promise<{ holder: boolean; balance?: number; limit: number }> {
    const u = this.store.user(ctx.userId);
    if (!u.address) return { holder: false, limit: this.cfg.freePerDay };
    const cached = this.balances.get(u.address);
    let balance: number;
    if (cached && this.now() - cached.at < BALANCE_TTL_MS) balance = cached.n;
    else {
      balance = await this.chain.holdings(this.cfg.gatingToken, u.address as Address);
      this.balances.set(u.address, { n: balance, at: this.now() });
    }
    const holder = balance >= this.cfg.minHold;
    return { holder, balance, limit: holder ? this.cfg.holderPerDay : this.cfg.freePerDay };
  }

  private async metered(ctx: Ctx, run: () => Promise<string>): Promise<string> {
    const u = this.store.user(ctx.userId);
    const today = this.day();
    if (u.day !== today) {
      u.day = today;
      u.used = 0;
    }
    const t = await this.tier(ctx);
    if ((u.used ?? 0) >= t.limit) {
      return t.holder
        ? `Daily limit reached (${t.limit}). Resets at 00:00 UTC.`
        : `Free limit reached (${t.limit} a day, resets 00:00 UTC). Holders of ${this.cfg.minHold.toLocaleString("en-US")}+ $YUSA get ${this.cfg.holderPerDay} a day: /link <wallet>`;
    }
    const out = await run();
    u.used = (u.used ?? 0) + 1;
    this.store.save();
    return out;
  }

  private scanText(text: string): Promise<string> {
    if (text.length > MAX_TEXT) return Promise.resolve(`Too long: ${text.length} characters, max ${MAX_TEXT}.`);
    return Promise.resolve(report(scan(text)));
  }

  private async ca(address: string): Promise<string> {
    let info: TokenInfo;
    try {
      info = await this.chain.tokenInfo(address);
    } catch (e) {
      return `Could not read ${address} from Robinhood Chain: ${(e as Error).message.split("\n")[0]}`;
    }
    if (!info.contract) return `${info.address} is not a contract on Robinhood Chain.`;
    const parts: [string, string][] = [];
    if (info.name) parts.push(["name", info.name]);
    if (info.symbol) parts.push(["symbol", info.symbol]);
    const launch = info.pons?.launch;
    if (launch) {
      parts.push(["description", launch.description], ["logo", launch.logo]);
      for (const [k, v] of Object.entries(launch.socials)) if (v) parts.push([k, v]);
    }
    const head = [`${info.name ?? "?"} ($${info.symbol ?? "?"})`, info.address];
    if (info.pons) {
      const p = info.pons;
      head.push(`Pons launch · phase ${p.phase}${p.phase === 0 ? " (bonding curve)" : ""} · creator tax ${p.creatorTaxBps / 100}% · deployer ${p.deployer}`);
      if (!launch) head.push("Launch metadata not found in the launch transaction; scanned name and symbol only.");
    }
    head.push(`Scanned: ${parts.map(([k]) => k).join(", ") || "nothing readable"}`, "");
    return head.join("\n") + report(scan(parts.map(([k, v]) => `${k}: ${v}`).join("\n")));
  }

  private async url(raw: string): Promise<string> {
    let page: Page;
    try {
      page = await this.chain.fetchPage(raw);
    } catch (e) {
      return e instanceof FetchError ? `Could not scan that link: ${e.message}` : "Could not fetch that page.";
    }
    const view = agentView(page.body, page.contentType);
    const combined = [view.title, view.text, view.hidden].filter(Boolean).join("\n");
    if (!combined.trim()) return `${page.url}\nHTTP ${page.status} · no readable text on the page.`;
    const r = scan(combined.slice(0, 200_000));
    // UI panels hidden until a click are normal; only show hidden text that triggered a finding.
    const flaggedLayers = new Set(r.findings.map((f) => f.layer));
    r.hiddenText = r.hiddenText.filter((h) => flaggedLayers.has(h.layer));
    const head = [
      view.title ? `${view.title.slice(0, 120)}` : page.url,
      `${page.url}`,
      `HTTP ${page.status} · ${(page.bytes / 1024).toFixed(0)} KB${page.truncated ? " (first 1 MB only)" : ""} · ${view.text.length.toLocaleString("en-US")} characters an agent would read${view.hidden ? " + hidden HTML" : ""}`,
      "",
    ];
    const note = r.verdict !== "allow" && r.findings.every((f) => f.layer === "visible")
      ? "\nEvery finding is in text a reader can see. Articles about prompt injection quote these phrases; check whether the page is quoting an attack or making one."
      : "";
    return head.join("\n") + report(r) + note;
  }

  private async tx(arg: string): Promise<string> {
    const parts = arg.trim().split(/\s+/);
    let to: Address | null, data: Hex, value = 0n, head: string;
    const sent = parts.length === 1;
    if (sent) {
      let t;
      try {
        t = await this.chain.tx.transaction(parts[0] as Hex);
      } catch (e) {
        return `Could not read that transaction from Robinhood Chain: ${(e as Error).message.split("\n")[0]}`;
      }
      if (!t) return "No transaction with that hash on Robinhood Chain. A wallet address or a token address is 40 hex characters; use /ca for a token.";
      ({ to, input: data, value } = t);
      head = `Transaction ${parts[0].slice(0, 10)}… from ${t.from}${to ? ` to ${to}` : ""}`;
    } else {
      to = getAddress(parts[0]);
      data = parts[1] as Hex;
      head = `Unsigned call to ${to}`;
    }
    try {
      const r = await explain({ to, data, value }, this.chain.tx);
      const label = sent
        ? r.verdict === "block" ? "DANGER: ALREADY SENT" : r.verdict === "review" ? "NEEDS A CLOSER LOOK" : "LOOKS ROUTINE"
        : r.verdict === "block" ? "DANGER: DO NOT SIGN" : r.verdict === "review" ? "CHECK BEFORE SIGNING" : "LOOKS ROUTINE";
      const after = sent && r.verdict === "block"
        ? ["", "If this was your wallet, revoke the approval now (for example with revoke.cash) and move what is left to a fresh wallet."]
        : [];
      return [head, "", label, ...r.lines.map((l) => `- ${l}`), ...after, "", "This reads the calldata only. It does not simulate the call or vouch for the contract."].join("\n");
    } catch (e) {
      return `Could not read that transaction: ${(e as Error).message.split("\n")[0]}`;
    }
  }

  private async approvals(owner: Address): Promise<string> {
    try {
      return formatApprovals(owner, await openApprovals(owner, this.chain.approvals!));
    } catch (e) {
      return `Could not read approvals for ${owner}: ${(e as Error).message.split("\n")[0].slice(0, 140)}`;
    }
  }

  private async guardCommand(ctx: Ctx, arg: string): Promise<string> {
    if (ctx.private || ctx.chatId === undefined) return "Add me to a group, then a group admin sends /guard on there.";
    const g = this.store.group(ctx.chatId);
    if (arg === "" || arg === "status") {
      const used = g.day === this.day() ? (g.used ?? 0) : 0;
      return g.guard
        ? `Guard is ON. ${Math.max(0, GROUP_CHECKS_PER_DAY - used)} of ${GROUP_CHECKS_PER_DAY} checks left today. An admin can turn it off with /guard off.`
        : "Guard is OFF. A group admin can turn it on with /guard on.";
    }
    if (arg !== "on" && arg !== "off") return "Usage: /guard on | off | status";
    if (!ctx.isAdmin || !(await ctx.isAdmin().catch(() => false))) return "Only a group admin can change the guard.";
    g.guard = arg === "on";
    if (g.guard) g.enabledBy = ctx.userId;
    this.store.save();
    return g.guard
      ? [
          "Guard is ON for this group.",
          "",
          "I check token addresses, links and transaction hashes members post, plus any hidden text in a message. I only reply when something looks wrong, so a clean chat stays quiet.",
          "I also warn if someone pastes what looks like a private key or seed phrase.",
          "",
          "For me to see normal messages, Privacy Mode must be off: @BotFather > /mybots > this bot > Bot Settings > Group Privacy > Turn off, or make me a group admin.",
        ].join("\n")
      : "Guard is OFF for this group. Commands still work.";
  }

  private takeGroupCheck(chatId: number): boolean {
    const g = this.store.group(chatId);
    const today = this.day();
    if (g.day !== today) {
      g.day = today;
      g.used = 0;
    }
    if ((g.used ?? 0) >= GROUP_CHECKS_PER_DAY) return false;
    g.used = (g.used ?? 0) + 1;
    return true;
  }

  /** Passive check of a group message. Returns a warning, or null to stay quiet. */
  private async guardMessage(chatId: number, text: string): Promise<string | null> {
    const keyWarning = "Careful: this looks like a private key or a seed phrase. Anyone in this chat can use it to empty that wallet. Delete the message now and move your funds to a new wallet.";
    if (BARE_KEY.test(text) || looksLikeSeed(text)) return keyWarning;
    const warnings: string[] = [];
    const before = this.store.group(chatId).used ?? 0;

    if (text.length <= MAX_TEXT && this.takeGroupCheck(chatId)) {
      const r = scan(text);
      if (r.findings.some((f) => f.category === "secret")) return keyWarning;
      // People discuss prompt injection out loud in chats, so visible text is never reported here;
      // text hidden from the reader is.
      const hidden = r.findings.filter((f) => f.layer !== "visible");
      if (hidden.length) warnings.push(report({ ...r, findings: hidden }));
      else this.refund(chatId);
    }

    const items = [
      ...[...text.matchAll(/(?<![0-9a-fx])0x[0-9a-f]{64}(?![0-9a-f])/gi)].map((m) => ({ kind: "tx" as const, v: m[0] })),
      ...[...text.matchAll(/(?<![0-9a-fx])0x[0-9a-f]{40}(?![0-9a-f])/gi)].map((m) => ({ kind: "ca" as const, v: m[0] })),
      ...[...text.matchAll(/https?:\/\/[^\s<>"']+/gi)].map((m) => ({ kind: "url" as const, v: m[0].replace(/[).,;!?]+$/, "") })),
    ];
    const seen = new Set<string>();
    for (const it of items) {
      if (seen.size >= MAX_ITEMS_PER_MESSAGE || seen.has(it.v.toLowerCase())) continue;
      seen.add(it.v.toLowerCase());
      if (!this.takeGroupCheck(chatId)) break;
      const out = it.kind === "ca" ? await this.ca(it.v) : it.kind === "url" ? await this.url(it.v) : await this.tx(it.v);
      if (/(^|\n)(BLOCK|REVIEW) ·|\n(DANGER|NEEDS A CLOSER LOOK)/.test(out)) warnings.push(out);
    }
    if ((this.store.group(chatId).used ?? 0) !== before) this.store.save();
    return warnings.length ? `YUSA guard\n\n${warnings.join("\n\n---\n\n")}` : null;
  }

  private refund(chatId: number) {
    const g = this.store.group(chatId);
    g.used = Math.max(0, (g.used ?? 1) - 1);
  }

  private link(ctx: Ctx, arg: string): string {
    if (!ctx.private) return "Link your wallet in a private chat with the bot.";
    if (!isAddress(arg, { strict: false })) return "Usage: /link <0x wallet address>";
    const address = getAddress(arg);
    const nonce = randomBytes(8).toString("hex");
    const exp = this.now() + CHALLENGE_TTL_MS;
    const message = linkMessage(ctx.userId, address, nonce, new Date(exp).toISOString());
    this.challenges.set(ctx.userId, { address, message, exp });
    const url = `${this.cfg.linkPage}#m=${Buffer.from(message).toString("base64url")}`;
    return [
      "Sign this message with that wallet to prove you own it. It is a signature only: no transaction, no gas, no approval.",
      "",
      message,
      "",
      `Sign in your browser wallet: ${url}`,
      "",
      "Then send the signature here (0x…, 132 characters). Expires in 15 minutes.",
    ].join("\n");
  }

  private async verify(ctx: Ctx, arg: string): Promise<string> {
    const c = this.challenges.get(ctx.userId);
    if (!c || this.now() > c.exp) return "No pending link, or it expired. Start again with /link <wallet>.";
    const sig = arg.trim();
    if (!/^0x[0-9a-f]{130}$/i.test(sig)) return "That is not a signature (expected 0x followed by 130 hex characters).";
    let ok = false;
    try {
      ok = await this.chain.verifySignature(c.address, c.message, sig as Hex);
    } catch {
      ok = false;
    }
    if (!ok) return "Signature does not match that wallet and message. Nothing was linked.";
    this.challenges.delete(ctx.userId);
    for (const [id, other] of Object.entries(this.store.state.users)) {
      if (id !== String(ctx.userId) && other.address?.toLowerCase() === c.address.toLowerCase()) {
        delete other.address;
        delete other.linkedAt;
      }
    }
    const u = this.store.user(ctx.userId);
    u.address = c.address;
    u.linkedAt = new Date(this.now()).toISOString();
    this.balances.delete(c.address);
    this.store.save();
    return `Linked ${c.address}.\n\n${await this.me(ctx)}`;
  }

  private async me(ctx: Ctx): Promise<string> {
    const u = this.store.user(ctx.userId);
    const t = await this.tier(ctx);
    const used = u.day === this.day() ? (u.used ?? 0) : 0;
    const lines = [
      u.address ? `Wallet: ${u.address}` : "Wallet: not linked (/link <wallet>)",
      u.address ? `Balance: ${t.balance!.toLocaleString("en-US")} $YUSA` : "",
      `Tier: ${t.holder ? "holder" : "free"} · ${Math.max(0, t.limit - used)} of ${t.limit} scans left today`,
    ];
    if (u.address && !t.holder) lines.push(`Holder tier needs ${this.cfg.minHold.toLocaleString("en-US")} $YUSA. Balance is rechecked every few minutes.`);
    return lines.filter(Boolean).join("\n");
  }
}

export function report(r: ScanResult): string {
  const lines = [`${r.verdict.toUpperCase()} · score ${r.score}/100 · ${r.findings.length} finding(s)`];
  for (const f of r.findings.slice(0, 12)) lines.push(`- ${f.id} [${f.layer}] ${f.why}`);
  if (r.findings.length > 12) lines.push(`- …and ${r.findings.length - 12} more`);
  for (const h of r.hiddenText.slice(0, 3)) lines.push(`Hidden (${h.layer}): ${maskSecrets(h.text).slice(0, 300)}`);
  if (r.verdict === "block") lines.push("", "Do not let an agent act on this text.");
  else if (r.verdict === "review") lines.push("", "Suspicious. Read it yourself before an agent acts on it.");
  return lines.join("\n");
}
