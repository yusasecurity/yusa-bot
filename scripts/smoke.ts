import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { holdings, tokenInfo, verifySignature } from "../src/chain.ts";
import { Bot } from "../src/handlers.ts";
import { fetchPage } from "../src/page.ts";
import { Store } from "../src/store.ts";

// Read-only smoke test against live Telegram + chain. Sends no messages.
const env = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n").map((l) => l.match(/^([A-Z_]+)=(.*)$/)).filter(Boolean).map((m) => [m![1], m![2]]));
const api = (m: string) => fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${m}`).then((r) => r.json());
const me = await api("getMe");
console.log("getMe:", me.result.username, "| can join groups:", me.result.can_join_groups, "| reads all group msgs:", me.result.can_read_all_group_messages);
const cmds = await api("getMyCommands");
console.log("commands:", cmds.result.map((c: any) => "/" + c.command).join(" "));
const wh = await api("getWebhookInfo");
console.log("webhook:", wh.result.url || "none (long polling)", "| pending:", wh.result.pending_update_count);

const store = new Store(join(mkdtempSync(join(tmpdir(), "yb-")), "s.json"));
const bot = new Bot(store, { tokenInfo, holdings, verifySignature, fetchPage: (u) => fetchPage(u) }, {
  gatingToken: env.YUSA_TOKEN as `0x${string}`, minHold: Number(env.YUSA_MIN_HOLD), freePerDay: Number(env.FREE_PER_DAY), holderPerDay: Number(env.HOLDER_PER_DAY), linkPage: env.LINK_PAGE,
});
const dm = { userId: 1, private: true };
console.log("\n/ca $YUSA ->\n" + (await bot.handle(dm, `/ca ${env.YUSA_TOKEN}`)));
console.log("\n/me ->\n" + (await bot.handle(dm, "/me")));
const link = (await bot.handle(dm, "/link 0x2EA951DA0Cdd767658f2C1d2c6849cd813F91496"))!;
const url = link.match(/https:\S+/)![0];
const page = await fetch(url.split("#")[0], { headers: { "user-agent": "Mozilla/5.0" } });
console.log("\n/link -> signing page", page.status, (await page.text()).includes("YUSA bot · wallet link") ? "(correct page)" : "(WRONG PAGE)");

const urls = (process.argv[2] ?? "").split(",").filter(Boolean);
for (const u of urls) {
  const t = Date.now();
  const out = (await new Bot(new Store(join(mkdtempSync(join(tmpdir(), "yb-")), "s.json")), { tokenInfo, holdings, verifySignature, fetchPage: (x) => fetchPage(x) }, { gatingToken: env.YUSA_TOKEN as `0x${string}`, minHold: 1, freePerDay: 99, holderPerDay: 99, linkPage: env.LINK_PAGE }).handle(dm, `/url ${u}`))!;
  console.log(`\n/url ${u}  [${Date.now() - t} ms]\n${out.split("\n").slice(0, 7).join("\n")}`);
}
