import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { networkInterfaces } from "node:os";

// Blocks every address a public web page has no business resolving to, so /url cannot reach this server or its network.
const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [
  ["::", 128], ["::1", 128], ["64:ff9b::", 96], ["64:ff9b:1::", 48], ["100::", 64], ["2001::", 23], ["2001:db8::", 32],
  ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(net, bits, "ipv6");
// This host's own public addresses: services bound to 0.0.0.0 answer on them.
for (const addrs of Object.values(networkInterfaces())) {
  for (const a of addrs ?? []) blocked.addAddress(a.address, a.family === "IPv6" ? "ipv6" : "ipv4");
}

export function isBlockedAddress(address: string): boolean {
  const fam = isIP(address);
  if (fam === 0) return true;
  if (fam === 6) {
    const mapped = address.toLowerCase().match(/^::ffff:(?:0:)?(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return blocked.check(mapped[1], "ipv4");
    return blocked.check(address, "ipv6");
  }
  return blocked.check(address, "ipv4");
}

export class FetchError extends Error {}

export interface Page {
  url: string;
  status: number;
  contentType: string;
  bytes: number;
  truncated: boolean;
  body: string;
}

export interface FetchOptions {
  maxBytes?: number;
  timeoutMs?: number;
  maxRedirects?: number;
  /** Tests only: resolve hostnames without DNS. */
  resolve?: (host: string) => Promise<string[]>;
}

const TEXT_TYPES = /^(?:text\/|application\/(?:xhtml\+xml|json|ld\+json|xml|rss\+xml|atom\+xml|markdown))/i;

export function checkUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new FetchError("Not a valid URL.");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") throw new FetchError("Only http and https links.");
  if (u.username || u.password) throw new FetchError("Links with a username or password are refused.");
  if (u.port && u.port !== "80" && u.port !== "443") throw new FetchError("Only the standard web ports (80, 443).");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host) && isBlockedAddress(host)) throw new FetchError("That address is private or reserved.");
  if (!isIP(host) && (!host.includes(".") || /\.(?:local|localhost|internal|home|lan|corp|intranet)$/i.test(host) || host === "localhost")) {
    throw new FetchError("That host is not a public name.");
  }
  return u;
}

function guardedLookup(resolve?: FetchOptions["resolve"]): LookupFunction {
  return (hostname, options, callback) => {
    const done = (err: Error | null, addrs: string[]) => {
      if (err) return callback(err, "", 4);
      if (addrs.length === 0) return callback(new FetchError("Host has no address."), "", 4);
      // Refuse if ANY address is private: a host that mixes public and private records is a rebinding setup.
      const bad = addrs.find(isBlockedAddress);
      if (bad) return callback(new FetchError("That host resolves to a private or reserved address."), "", 4);
      const list: LookupAddress[] = addrs.map((a) => ({ address: a, family: isIP(a) }));
      if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, l: LookupAddress[]) => void)(null, list);
      callback(null, list[0].address, list[0].family);
    };
    if (resolve) resolve(hostname).then((a) => done(null, a), (e) => done(e, []));
    else dnsLookup(hostname, { all: true, verbatim: true }, (err, list) => done(err, (list ?? []).map((x) => x.address)));
  };
}

function once(u: URL, opt: Required<Omit<FetchOptions, "resolve">> & Pick<FetchOptions, "resolve">): Promise<{ status: number; location?: string; contentType: string; body: Buffer; truncated: boolean }> {
  return new Promise((resolvePromise, reject) => {
    const mod = u.protocol === "https:" ? https : http;
    const req = mod.request(u, {
      method: "GET",
      lookup: guardedLookup(opt.resolve),
      agent: false,
      headers: {
        "user-agent": "YUSA-bot/1.0 (+https://yusasecurity.xyz; prompt-injection scan)",
        accept: "text/html,application/xhtml+xml,text/plain,text/markdown,application/json;q=0.9,*/*;q=0.1",
        "accept-encoding": "identity",
      },
      timeout: opt.timeoutMs,
    });
    const timer = setTimeout(() => req.destroy(new FetchError("The page took too long to answer.")), opt.timeoutMs);
    req.on("timeout", () => req.destroy(new FetchError("The page took too long to answer.")));
    req.on("error", (e) => {
      clearTimeout(timer);
      reject(e instanceof FetchError ? e : new FetchError(`Could not reach the page (${(e as NodeJS.ErrnoException).code ?? e.message}).`));
    });
    req.on("response", (res) => {
      const remote = res.socket.remoteAddress;
      if (remote && isBlockedAddress(remote)) {
        req.destroy(new FetchError("That host resolves to a private or reserved address."));
        return;
      }
      const status = res.statusCode ?? 0;
      const contentType = String(res.headers["content-type"] ?? "");
      if (status >= 300 && status < 400 && res.headers.location) {
        clearTimeout(timer);
        res.resume();
        resolvePromise({ status, location: res.headers.location, contentType, body: Buffer.alloc(0), truncated: false });
        return;
      }
      if (contentType && !TEXT_TYPES.test(contentType)) {
        clearTimeout(timer);
        req.destroy();
        reject(new FetchError(`Not a text page (${contentType.split(";")[0]}).`));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      res.on("data", (c: Buffer) => {
        if (truncated) return;
        const room = opt.maxBytes - size;
        if (c.length >= room) {
          chunks.push(c.subarray(0, room));
          size += room;
          truncated = true;
          res.destroy();
          clearTimeout(timer);
          resolvePromise({ status, contentType, body: Buffer.concat(chunks), truncated });
          return;
        }
        chunks.push(c);
        size += c.length;
      });
      res.on("end", () => {
        clearTimeout(timer);
        resolvePromise({ status, contentType, body: Buffer.concat(chunks), truncated });
      });
      res.on("error", (e) => {
        clearTimeout(timer);
        if (!truncated) reject(new FetchError(`The page stopped mid-download (${e.message}).`));
      });
    });
    req.end();
  });
}

function decode(body: Buffer, contentType: string): string {
  const charset = contentType.match(/charset=["']?([\w-]+)/i)?.[1] ?? body.subarray(0, 2048).toString("latin1").match(/<meta[^>]+charset=["']?([\w-]+)/i)?.[1] ?? "utf-8";
  try {
    return new TextDecoder(charset).decode(body);
  } catch {
    return new TextDecoder("utf-8").decode(body);
  }
}

export async function fetchPage(raw: string, options: FetchOptions = {}): Promise<Page> {
  const opt = { maxBytes: 1_000_000, timeoutMs: 8000, maxRedirects: 3, ...options };
  let u = checkUrl(raw);
  for (let hop = 0; ; hop++) {
    const r = await once(u, opt);
    if (r.location !== undefined) {
      if (hop >= opt.maxRedirects) throw new FetchError(`Too many redirects (more than ${opt.maxRedirects}).`);
      u = checkUrl(new URL(r.location, u).toString());
      continue;
    }
    return { url: u.toString(), status: r.status, contentType: r.contentType, bytes: r.body.length, truncated: r.truncated, body: decode(r.body, r.contentType) };
  }
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", "#39": "'" };

function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return n > 0 && n <= 0x10ffff ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

export interface AgentView {
  title: string;
  text: string;
  hidden: string;
}

/**
 * What an agent that "reads the page" gets: visible text, meta descriptions and alt text,
 * plus comments and CSS-hidden elements kept as HTML so the engine reports them as hidden.
 * Script, style and inline SVG bodies are dropped: browsing tools do not hand them to the model.
 */
export function agentView(body: string, contentType: string): AgentView {
  if (!/html|xml/i.test(contentType) && !/^\s*<(?:!doctype|html)/i.test(body)) return { title: "", text: body, hidden: "" };
  let html = body.replace(/<(script|style|svg|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ");
  html = html.replace(/\bdata:[a-z/+.-]+;base64,[A-Za-z0-9+/=]+/gi, "data:");
  const title = decodeEntities(html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? "").replace(/\s+/g, " ").trim();
  const extra: string[] = [];
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/(?:name|property)\s*=\s*["'](?:description|og:description|og:title|twitter:description|twitter:title|keywords)["']/i.test(tag)) continue;
    const c = tag.match(/content\s*=\s*"([^"]*)"|content\s*=\s*'([^']*)'/i);
    if (c) extra.push(decodeEntities(c[1] ?? c[2]));
  }
  for (const m of html.matchAll(/\b(?:alt|title|aria-label)\s*=\s*"([^"]{8,})"/gi)) extra.push(decodeEntities(m[1]));
  const hidden: string[] = [];
  // Framework markers (`<!-- -->`, `<!--&-->`) and empty hidden widgets carry no words; skip them.
  const words = (s: string) => (s.replace(/<[^>]+>/g, " ").match(/\p{L}{2,}/gu) ?? []).length;
  for (const m of html.matchAll(/<!--([\s\S]*?)-->/g)) if (words(m[1]) >= 3) hidden.push(m[0]);
  const hiddenStyle = /<(\w+)[^>]*style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0(?:\.0+)?\b)[^"']*["'][^>]*>([\s\S]*?)<\/\1>/gi;
  for (const m of html.matchAll(hiddenStyle)) if (words(m[2]) >= 3) hidden.push(m[0]);
  for (const m of html.matchAll(/<(\w+)\b[^>]*\s(?:hidden|aria-hidden\s*=\s*["']true["'])[^>]*>([\s\S]*?)<\/\1>/gi)) {
    const t = m[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    if (t.length > 20) hidden.push(`<span style="display:none">${t}</span>`);
  }
  const visible = decodeEntities(
    html
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(?:br|\/p|\/div|\/li|\/h\d|\/tr|\/section|\/article)\b[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t\f\v\r]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
  return { title, text: [visible, ...extra].join("\n"), hidden: hidden.join("\n") };
}
