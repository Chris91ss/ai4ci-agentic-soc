// Regenerates the README's images and the link preview from the static build, in headless Chrome:
//
//   docs/assets/overview.png    the overview of the recorded run
//   docs/assets/incident.png    an incident: its risk, techniques, entities and alert lanes
//   docs/assets/trace.png       the agent's investigation of that incident, tool call by tool call
//   docs/assets/evaluation.png  the agent against the two baselines, over ten seeds
//   docs/assets/drift.png       scenario S1: false alerts after the move to remote work, with and without retraining
//   docs/assets/queue.png       the incident queue                                         (gallery: the console
//   docs/assets/evidence.png    the evidence behind the agent's verdict, filterable        without the sidebar)
//   docs/assets/entity.png      a host: its baseline, incidents and timeline
//   docs/assets/actions.png     every containment action and what the policy gate decided
//   docs/assets/monitor.png     the drift monitor: PSI of M1's features, alarms and retrains
//   docs/assets/audit.png       the hash-chained audit log
//   docs/assets/palette.png     the command palette
//   docs/assets/detectors.png   M1-M3 on the held-out test weeks
//   docs/assets/load.png        scenario S2: a tenfold burst through Redpanda
//   docs/assets/llm.png         the agent on gpt-oss:20b, with and without the evidence verifier
//   docs/assets/demo.gif        a tour of the console (needs ffmpeg)
//   public/social.png           the link preview, from scripts/social-card.html
//
//   STATIC_EXPORT=1 NEXT_PUBLIC_DATA=static npm run build
//   node scripts/capture.mjs [shots] [gallery] [tour] [social]
//
// Name some of them to capture only those. Set NEXT_PUBLIC_BASE_PATH as for the build if the site was built
// with one, and CHROME_PATH if Chrome is not in its usual place. Rebuild afterwards, so the site serves the
// new social.png.
import { execFileSync } from "node:child_process";
import { createReadStream, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import puppeteer from "puppeteer-core";

const only = process.argv.slice(2);
const wanted = (name) => only.length === 0 || only.includes(name);
const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const siteDir = join(web, "out");
const assets = join(web, "..", "docs", "assets");
const base = (process.env.NEXT_PUBLIC_BASE_PATH ?? "").replace(/\/$/, "");
const incidentId = process.env.CAPTURE_INCIDENT ?? "INC-00055";
if (!existsSync(join(siteDir, "index.html"))) {
  console.error("build the static site first: STATIC_EXPORT=1 NEXT_PUBLIC_DATA=static npm run build");
  process.exit(2);
}
mkdirSync(assets, { recursive: true });

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".css": "text/css",
  ".json": "application/json",
  ".txt": "text/plain",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// The export as GitHub Pages serves it: under the base path, a/ as a/index.html.
const server = createServer((request, response) => {
  let path = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
  if (base && path.startsWith(base)) path = path.slice(base.length);
  let file = normalize(join(siteDir, path));
  if (!file.startsWith(siteDir)) {
    response.writeHead(403).end();
    return;
  }
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, "index.html");
  else if (!existsSync(file) && existsSync(`${file}.html`)) file = `${file}.html`;
  if (!existsSync(file)) {
    response.writeHead(404).end();
    return;
  }
  response.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(response);
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const site = `http://127.0.0.1:${server.address().port}${base}`;

const chrome = [
  process.env.CHROME_PATH,
  "/usr/bin/google-chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].find((path) => path && existsSync(path));
const browser = await puppeteer.launch({
  executablePath: chrome,
  headless: true,
  args: process.platform === "linux" ? ["--no-sandbox"] : [],
});
const page = await browser.newPage();
page.on("pageerror", (error) => console.error(`page error: ${error.message}`));
await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 1 });
const sleep = (milliseconds) => new Promise((done) => setTimeout(done, milliseconds));

async function open(path, text) {
  await page.goto(`${site}${path}`, { waitUntil: "networkidle0" });
  await page.waitForFunction((t) => document.querySelector("main")?.innerText.includes(t), { timeout: 60000 }, text);
  await sleep(1500); // the cards and counters animate in
}

async function waitFor(text) {
  await page.waitForFunction((t) => document.querySelector("main")?.innerText.includes(t), { timeout: 60000 }, text);
}

/** Clicks the visible element of `selector` whose text starts with `text`, with a real mouse click. */
async function clickText(selector, text) {
  const handle = await page.evaluateHandle(
    (s, t) =>
      [...document.querySelectorAll(s)].find((node) => node.getClientRects().length && node.textContent.trim().startsWith(t)),
    selector,
    text,
  );
  const element = handle.asElement();
  if (!element) throw new Error(`no visible ${selector} with text ${text}`);
  await element.click();
}

/** Clicks the visible link whose address contains `part`. */
async function clickLink(part) {
  const handle = await page.evaluateHandle(
    (p) => [...document.querySelectorAll("a[href]")].find((a) => a.getClientRects().length && a.getAttribute("href").includes(p)),
    part,
  );
  const element = handle.asElement();
  if (!element) throw new Error(`no visible link to ${part}`);
  await element.click();
}

async function rest() {
  await page.mouse.move(1430, 890);
  await sleep(500);
}

/** Saves a 1200 x 900 frame of what is in view, by default without the sidebar (clips are in page coordinates). */
async function shotMain(name, x = 240) {
  const y = await page.evaluate(() => window.scrollY);
  await page.screenshot({ path: join(assets, name), clip: { x, y, width: 1200, height: 900 } });
  console.log(`docs/assets/${name}`);
}

/** The card (a panel with a rounded border) that has a heading starting with `title`. */
async function card(title) {
  const handle = await page.evaluateHandle((t) => {
    let node = [...document.querySelectorAll("h3")].find((h) => h.textContent.trim().startsWith(t));
    while (node && !String(node.className).includes("radius-card")) node = node.parentElement;
    return node;
  }, title);
  const element = handle.asElement();
  if (!element) throw new Error(`no card titled ${title}`);
  return element;
}

async function pauseReplay() {
  const pause = await page.$("header button:has(svg.tabler-icon-player-pause)");
  if (pause) await pause.click();
}

if (wanted("shots")) {
  await open("/", "Security overview");
  await clickText("header button", "1 h/s"); // the activity feed fills faster
  await sleep(6000);
  await pauseReplay();
  await rest();
  await page.screenshot({ path: join(assets, "overview.png") });
  console.log("docs/assets/overview.png");

  await open(`/incident/?id=${incidentId}`, incidentId);
  await rest();
  await page.screenshot({ path: join(assets, "incident.png") });
  console.log("docs/assets/incident.png");

  await clickText('[role="tab"]', "Agent trace");
  await sleep(1200);
  await page.evaluate(() => {
    const tabs = document.querySelector('[role="tablist"]');
    window.scrollBy(0, tabs.getBoundingClientRect().top - 96);
  });
  await rest();
  await page.screenshot({ path: join(assets, "trace.png") });
  console.log("docs/assets/trace.png");

  await open("/evaluation/", "Agent (scripted analyst)");
  await rest();
  await page.screenshot({ path: join(assets, "evaluation.png") });
  console.log("docs/assets/evaluation.png");

  await clickText('[role="tab"]', "Drift (S1)");
  await waitFor("Seed 301");
  await sleep(1800);
  const panel = await page.evaluateHandle(() => {
    const title = [...document.querySelectorAll("h3")].find((h) => h.textContent.trim() === "Seed 301");
    let node = title;
    while (node && !node.className.includes("radius-card")) node = node.parentElement;
    return node;
  });
  await rest();
  await panel.asElement().screenshot({ path: join(assets, "drift.png") });
  console.log("docs/assets/drift.png");
}

// The rest of the console and of the evaluation, for the README's galleries.
if (wanted("gallery")) {
  await open("/incidents/", "Incident queue");
  await rest();
  await shotMain("queue.png");

  await open(`/incident/?id=${incidentId}`, incidentId);
  await clickText('[role="tab"]', "Evidence");
  await sleep(1200);
  await page.evaluate(() => {
    const tabs = document.querySelector('[role="tablist"]');
    window.scrollBy(0, tabs.getBoundingClientRect().top - 96);
  });
  await rest();
  await shotMain("evidence.png");

  await open("/entity/?e=host%3AWS-0156", "Timeline");
  await rest();
  await shotMain("entity.png");

  await open("/actions/", "WS-0156");
  await rest();
  await shotMain("actions.png");

  await open("/metrics/", "Drift monitor");
  await sleep(800);
  await rest();
  await (await card("Drift monitor")).screenshot({ path: join(assets, "monitor.png") });
  console.log("docs/assets/monitor.png");

  await open("/audit/", "Hash chain");
  await rest();
  await shotMain("audit.png");

  await open("/", "Security overview");
  await clickText("header button", "Search incidents");
  await page.waitForSelector("[cmdk-input]");
  await page.type("[cmdk-input]", "WS-0156", { delay: 40 });
  await sleep(900);
  await shotMain("palette.png", 120); // centred on the dialog
  await page.keyboard.press("Escape");

  await open("/evaluation/", "Agent (scripted analyst)");
  await clickText('[role="tab"]', "Detectors");
  await sleep(1800);
  await rest();
  await shotMain("detectors.png");

  await clickText('[role="tab"]', "Load (S2)");
  await sleep(1800);
  await rest();
  await (await card("LLM 4")).screenshot({ path: join(assets, "load.png") });
  console.log("docs/assets/load.png");

  await clickText('[role="tab"]', "Local LLM");
  await sleep(1800);
  await rest();
  await shotMain("llm.png");
}

// The tour, recorded as a screencast and turned into a GIF.
if (wanted("tour")) {
  await open("/", "Security overview");
  await clickText("header button", "1 h/s");
  await rest();
  const video = join(tmpdir(), "soc-tour.webm");
  rmSync(video, { force: true });
  const recorder = await page.screencast({ path: video });
  await sleep(2500);
  await clickLink("/incidents/");
  await waitFor(incidentId);
  await sleep(1600);
  await clickLink(`id=${incidentId}`);
  await waitFor("Agent trace");
  await sleep(2600);
  await clickText('[role="tab"]', "Agent trace");
  await sleep(2600);
  await clickText('[role="tab"]', "Evidence");
  await sleep(2200);
  await clickLink("/evaluation/");
  await waitFor("Agent (scripted analyst)");
  await sleep(3200);
  await recorder.stop();
  execFileSync("ffmpeg", [
    "-y", "-loglevel", "error", "-i", video,
    "-vf", "fps=10,scale=1000:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=160:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle",
    join(assets, "demo.gif"),
  ]); // prettier-ignore
  rmSync(video, { force: true });
  console.log("docs/assets/demo.gif");
}

// The link preview: the card, with an incident captured at twice the size.
if (wanted("social")) {
  await page.setViewport({ width: 1440, height: 900, deviceScaleFactor: 2 });
  await open(`/incident/?id=${incidentId}`, incidentId);
  await rest();
  const shot = await page.screenshot({ encoding: "base64", clip: { x: 248, y: 56, width: 1192, height: 744 } });
  await page.setViewport({ width: 1200, height: 630, deviceScaleFactor: 1 });
  await page.goto(pathToFileURL(join(web, "scripts", "social-card.html")).href, { waitUntil: "load" });
  await page.evaluate(
    (data) =>
      new Promise((done) => {
        const image = document.getElementById("shot");
        image.onload = done;
        image.src = `data:image/png;base64,${data}`;
      }),
    shot,
  );
  await sleep(300);
  await page.screenshot({ path: join(web, "public", "social.png") });
  console.log("web/public/social.png");
}

await browser.close();
server.close();
