import { readFileSync } from "node:fs";
import { getAddress } from "viem";
import { holdings, tokenInfo, txReader, verifySignature } from "./chain.ts";
import { Bot } from "./handlers.ts";
import { fetchPage } from "./page.ts";
import { Store } from "./store.ts";

// Long-polling Telegram bot. Config in .env next to package.json (never committed).
const ROOT = new URL("..", import.meta.url).pathname;
for (const line of readFileSync(ROOT + ".env", "utf8").split("\n")) {
  const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
  if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
}
const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
if (!TOKEN) throw new Error("TELEGRAM_BOT_TOKEN missing in .env");
const API = `https://api.telegram.org/bot${TOKEN}`;

const store = new Store(ROOT + "data/state.json");
const bot = new Bot(store, { tokenInfo, holdings, verifySignature, fetchPage: (u) => fetchPage(u), tx: txReader }, {
  gatingToken: getAddress(process.env.YUSA_TOKEN || "0x1fb8D9A8d1CEEB4C8d3C766C19a9473e53A43B0C"),
  minHold: Number(process.env.YUSA_MIN_HOLD || 100_000),
  freePerDay: Number(process.env.FREE_PER_DAY || 5),
  holderPerDay: Number(process.env.HOLDER_PER_DAY || 300),
  linkPage: process.env.LINK_PAGE || "https://yusasecurity.xyz/link.html",
});

const POLL_TIMEOUT_S = 50;

async function tg<T>(method: string, body: unknown): Promise<T> {
  // A hung socket must not freeze the bot: long polls get the poll window plus slack, everything else 15s.
  const ms = method === "getUpdates" ? (POLL_TIMEOUT_S + 15) * 1000 : 15_000;
  const res = await fetch(`${API}/${method}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body), signal: AbortSignal.timeout(ms) });
  const json = (await res.json()) as { ok: boolean; result: T; description?: string };
  if (!json.ok) throw new Error(`${method}: ${json.description}`);
  return json.result;
}

function why(e: unknown): string {
  const err = e as Error & { cause?: { code?: string; message?: string } };
  return [err.name === "TimeoutError" ? "timeout" : err.message, err.cause?.code ?? err.cause?.message].filter(Boolean).join(" / ");
}

// Plain text only: no parse_mode, so scanned content cannot inject Telegram markup.
async function send(chatId: number, text: string, replyTo?: number) {
  for (let i = 0; i < text.length; i += 4000) {
    await tg("sendMessage", { chat_id: chatId, text: text.slice(i, i + 4000), disable_web_page_preview: true, reply_parameters: replyTo && i === 0 ? { message_id: replyTo, allow_sending_without_reply: true } : undefined });
  }
}

type Update = { update_id: number; message?: { message_id: number; chat: { id: number; type: string }; from?: { id: number; is_bot: boolean }; text?: string; caption?: string; sender_chat?: { id: number } } };

const adminCache = new Map<string, { ok: boolean; at: number }>();
async function isAdmin(chatId: number, userId: number): Promise<boolean> {
  const key = `${chatId}:${userId}`;
  const c = adminCache.get(key);
  if (c && Date.now() - c.at < 5 * 60_000) return c.ok;
  const m = await tg<{ status: string }>("getChatMember", { chat_id: chatId, user_id: userId });
  const ok = m.status === "creator" || m.status === "administrator";
  adminCache.set(key, { ok, at: Date.now() });
  return ok;
}

await tg("setMyCommands", {
  commands: [
    { command: "scan", description: "Scan text for prompt injection" },
    { command: "ca", description: "Scan a Robinhood Chain token" },
    { command: "url", description: "Scan a web page as an agent reads it" },
    { command: "tx", description: "Explain a transaction before you sign it" },
    { command: "me", description: "Your tier and scans left" },
    { command: "guard", description: "Group admins: auto-check links and token addresses" },
    { command: "link", description: "Link a wallet for the holder tier" },
    { command: "help", description: "How it works" },
  ],
});
const me = await tg<{ username: string }>("getMe", {});
console.log(`yusa-bot @${me.username} running`);

for (;;) {
  let updates: Update[] = [];
  try {
    updates = await tg<Update[]>("getUpdates", { offset: store.state.offset, timeout: POLL_TIMEOUT_S, allowed_updates: ["message"] });
  } catch (e) {
    console.error(new Date().toISOString(), "poll", why(e));
    await new Promise((r) => setTimeout(r, 5000));
    continue;
  }
  for (const u of updates) {
    store.state.offset = u.update_id + 1;
    const msg = u.message;
    const text = msg?.text ?? msg?.caption;
    if (!msg || !text || !msg.from || msg.from.is_bot) continue;
    try {
      const priv = msg.chat.type === "private";
      // Anonymous admins post as the group itself (sender_chat), which Telegram vouches is an admin.
      const anonAdmin = msg.sender_chat?.id === msg.chat.id;
      const out = await bot.handle({
        userId: msg.from.id,
        private: priv,
        chatId: priv ? undefined : msg.chat.id,
        isAdmin: priv ? undefined : () => (anonAdmin ? Promise.resolve(true) : isAdmin(msg.chat.id, msg.from!.id)),
      }, text);
      if (out) await send(msg.chat.id, out, msg.message_id);
    } catch (e) {
      console.error(new Date().toISOString(), "handle", why(e));
      await send(msg.chat.id, "Something went wrong on our side. Try again in a minute.", msg.message_id).catch(() => {});
    }
  }
  store.save();
}
