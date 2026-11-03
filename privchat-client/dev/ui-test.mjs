import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import puppeteer from "puppeteer-core";

const ROOT = "/root/.dsh-qqbot/workspace/privchat/privchat-client/dist-mock";
const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" };

const server = http.createServer((req, res) => {
  let p = decodeURIComponent(req.url.split("?")[0]);
  if (p === "/") p = "/index.html";
  const f = path.join(ROOT, p);
  fs.readFile(f, (e, data) => {
    if (e) { res.writeHead(404); res.end("nf"); return; }
    res.writeHead(200, { "Content-Type": MIME[path.extname(f)] || "application/octet-stream" });
    res.end(data);
  });
});
await new Promise((r) => server.listen(4173, "127.0.0.1", r));

const browser = await puppeteer.launch({
  executablePath: "/usr/bin/chromium",
  headless: "new",
  args: ["--no-sandbox", "--disable-gpu"],
});
const page = await browser.newPage();
await page.setViewport({ width: 430, height: 900, deviceScaleFactor: 1 });
const errors = [];
page.on("console", (m) => { if (m.type() === "error") errors.push("console: " + m.text()); });
page.on("pageerror", (e) => errors.push("pageerror: " + e.message));

await page.goto("http://127.0.0.1:4173/?page=chats", { waitUntil: "networkidle0" });
await new Promise((r) => setTimeout(r, 600));

const tabs = await page.$$(".tabbar .tab");
console.log("tabs:", tabs.length);

for (let i = 1; i < tabs.length; i++) {
  await tabs[i].click();
  await new Promise((r) => setTimeout(r, 700));
  const text = await page.evaluate(() => document.body.innerText.slice(0, 120).replace(/\n/g, " | "));
  await page.screenshot({ path: `/tmp/click_tab${i}.png` });
  console.log(`tab${i} text:`, JSON.stringify(text));
}

console.log("ERRORS:", errors.length ? errors.join("\n") : "(none)");
await browser.close();
server.close();
