import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const ROOT = path.resolve("dist");
const CSP = "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self' data:; connect-src 'self' ipc: http://ipc.localhost";
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".woff": "font/woff", ".woff2": "font/woff2" };

const server = http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split("?")[0]);
  if (p === "/") p = "/index.html";
  const f = path.join(ROOT, p);
  fs.readFile(f, (e, data) => {
    if (e) { res.writeHead(404); res.end("nf"); return; }
    res.writeHead(200, { "Content-Type": MIME[path.extname(f)] || "application/octet-stream", "Content-Security-Policy": CSP });
    res.end(data);
  });
});
await new Promise((r) => server.listen(4180, "127.0.0.1", r));

const browser = await puppeteer.launch({
  executablePath: "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-gpu"],
});
const page = await browser.newPage();
await page.setViewport({ width: 430, height: 900 });
const violations = [];
page.on("console", (m) => {
  const t = m.text();
  if (/Content Security Policy|Refused to/i.test(t)) violations.push(t);
});
page.on("pageerror", (e) => violations.push("pageerror: " + e.message));
await page.goto("http://127.0.0.1:4180/", { waitUntil: "networkidle0" });
await new Promise((r) => setTimeout(r, 1200));
const title = await page.evaluate(() => document.body.innerText.slice(0, 80).replace(/\n/g, " | "));
await page.screenshot({ path: "/tmp/csp_ui.png" });
console.log("text:", JSON.stringify(title));
console.log("violations:", violations.length ? violations.join("\n") : "(none)");
await browser.close();
server.close();
