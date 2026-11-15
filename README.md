# YUSA bot

Telegram bot for [YUSA](https://github.com/yusasecurity/yusa), the prompt-injection firewall for AI agents. Live at [@yusasecuritybot](https://t.me/yusasecuritybot).

| Command | What it does |
|---|---|
| `/scan <text>` | Scans text for prompt injection: hidden Unicode, look-alike letters, fake system prompts, drain and exfiltration orders. In a private chat, just send the text. |
| `/ca <address>` | Scans a Robinhood Chain token. For Pons launches it reads the description and socials from the launch transaction, the text an agent would read. |
| `/url <link>` | Fetches a public web page and scans what an agent would read from it, including HTML comments and text hidden with CSS. In a private chat, just send the link. |
| `/me` | Your tier and scans left today. |
| `/link <wallet>` | Links a wallet for the holder tier. |

Free: 5 scans a day. Holding the configured amount of $YUSA in a linked wallet raises the limit. YUSA itself stays free and open source; holding the token is not required to use it.

## Wallet linking

The bot asks for a signature, never a transaction, approval, private key or seed phrase. `/link` returns a message and a link to [yusasecurity.xyz/link.html](https://yusasecurity.xyz/link.html), which only calls `personal_sign`, only signs the bot's exact message template, and makes no network requests. The bot checks the signature with `verifyMessage` (EOA and ERC-1271), then reads the balance on-chain. A signature is bound to one Telegram user, one wallet, a nonce and a 15-minute expiry, and one wallet links to one Telegram account at a time.

## `/url` and fetching untrusted links

Anyone can send the bot a link, so the fetcher refuses anything a public page has no business reaching:

- http and https only, ports 80 and 443, no credentials in the URL;
- no private, loopback, link-local, CGNAT, multicast or reserved addresses, including IPv4-mapped IPv6 and this host's own addresses, and no local names (`localhost`, `.local`, `.internal`);
- the check runs on the resolved address at connect time, so a public name that resolves to a private address (`localtest.me`, DNS rebinding) is refused, and so is a name with any private record;
- every redirect is checked again (at most 3), the body is capped at 1 MB and 8 seconds, and only text content types are read.

Script, style and inline SVG bodies are not scanned, because browsing tools do not hand them to the model. Pages that write about prompt injection quote attack phrases and will score high; when every finding is in visible text, the reply says so.

## Run it

The bot imports the YUSA engine from a sibling checkout, so clone both side by side:

```bash
git clone https://github.com/yusasecurity/yusa
git clone https://github.com/yusasecurity/yusa-bot
cd yusa-bot && npm install
cp .env.example .env   # add TELEGRAM_BOT_TOKEN from @BotFather
npm test
node src/bot.ts        # Node 22.6+ runs the TypeScript directly
```

`.env` keys: `TELEGRAM_BOT_TOKEN`, `YUSA_TOKEN` (gating token address), `YUSA_MIN_HOLD`, `FREE_PER_DAY`, `HOLDER_PER_DAY`, `LINK_PAGE`, optional `RPC_URL`. State (update offset, linked wallets, daily counts) lives in `data/state.json`, written atomically with mode 600. One runtime dependency: [viem](https://viem.sh).

Typecheck (the test runner strips types without checking them): `npx tsc -p .` with `@types/node` available.

## License

MIT
