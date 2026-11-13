// Captures the screenshots in docs/screenshots/ that the README shows.
//
// Like e2e/headless-ui.mjs, this drives the real production `dist/` bundle in headless Chrome
// against the real Rust engine (examples/ui_bridge.rs). The keystores and certificates it opens
// are made with keytool and openssl first, so every screen shows real parsed data.
//
//   pnpm screenshots            (pnpm build && node e2e/readme-screenshots.mjs)
//
// XKS_SCREENSHOTS=<dir> writes somewhere else; XKS_CHROME=system uses the installed Chrome.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const OUT = path.resolve(process.env.XKS_SCREENSHOTS || path.join(ROOT, "docs/screenshots"));
// Short, user-neutral paths show in the screenshots: a folder under /tmp (os.tmpdir() is a long
// per-user path on macOS), also used as the engine's HOME so the terminal prompt shows no user name.
const TMP = fs.mkdtempSync(path.join(process.platform === "win32" ? os.tmpdir() : "/tmp", "ks-"));
const WORK = path.join(TMP, "acme-pki");
fs.mkdirSync(WORK);
const [W, H] = [1320, 860]; // the app's default window size (tauri.conf.json)
let driver, bridge, server;

const log = (...a) => console.log("[shots]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, JAVA_TOOL_OPTIONS: "" } });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.stdout}${r.stderr}`);
  return r.stdout;
};
const w = (f) => path.join(WORK, f);

// ---- Fixtures --------------------------------------------------------------------------------

const PW = "studio-demo-1";
const PROD = w("acme-production.p12");
const TRUST = w("partner-truststore.jks");

function makeFixtures() {
  const kt = (store, type, ...args) => sh("keytool", [...args, "-keystore", store, "-storepass", PW, "-storetype", type]);
  const p12 = (...args) => kt(PROD, "PKCS12", ...args);
  const O = "O=Acme Corp, C=US";

  p12("-genkeypair", "-alias", "acme-root-ca", "-keyalg", "EC", "-groupname", "secp384r1", "-validity", "3650",
    "-dname", `CN=Acme Root CA, ${O}`, "-ext", "bc:c", "-ext", "ku:c=keyCertSign,cRLSign");
  const issue = (alias, keyArgs, days, sans, eku) => {
    p12("-genkeypair", "-alias", alias, ...keyArgs, "-dname", `CN=${alias}, OU=Platform, ${O}`);
    p12("-certreq", "-alias", alias, "-file", w(`${alias}.csr`));
    p12("-gencert", "-alias", "acme-root-ca", "-infile", w(`${alias}.csr`), "-outfile", w(`${alias}.crt`), "-rfc", "-validity", String(days),
      "-ext", `san=${sans}`, "-ext", `eku=${eku}`);
    p12("-importcert", "-alias", alias, "-file", w(`${alias}.crt`), "-noprompt");
  };
  issue("api.acme.dev", ["-keyalg", "RSA", "-keysize", "3072"], 397, "dns:api.acme.dev,dns:www.acme.dev", "serverAuth");
  issue("staging.acme.dev", ["-keyalg", "EC", "-groupname", "secp256r1"], 12, "dns:staging.acme.dev", "serverAuth");
  issue("mtls-client", ["-keyalg", "EC", "-groupname", "secp256r1"], 180, "email:ops@acme.dev", "clientAuth");
  p12("-genkeypair", "-alias", "release-signing", "-keyalg", "Ed25519", "-validity", "730", "-dname", `CN=Acme Release Signing, ${O}`);
  p12("-genkeypair", "-alias", "legacy-intranet", "-keyalg", "RSA", "-keysize", "1024", "-sigalg", "SHA1withRSA", "-validity", "3650",
    "-dname", "CN=intranet.acme.local, O=Acme Corp");
  p12("-genkeypair", "-alias", "vpn-gateway", "-keyalg", "RSA", "-keysize", "2048", "-startdate", "-400d", "-validity", "365",
    "-dname", `CN=vpn.acme.dev, ${O}`);
  p12("-genseckey", "-alias", "session-hmac", "-keyalg", "HmacSHA256", "-keysize", "256");

  // A partner's CA made with OpenSSL, trusted in both keystores.
  sh("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", w("partner.key"), "-out", w("partner-root.pem"), "-days", "1825",
    "-subj", "/CN=Globex Partner Root CA/O=Globex Corporation/C=DE", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  p12("-importcert", "-alias", "globex-partner-root", "-file", w("partner-root.pem"), "-noprompt");

  const jks = (...args) => kt(TRUST, "JKS", ...args);
  jks("-importcert", "-alias", "globex-partner-root", "-file", w("partner-root.pem"), "-noprompt");
  p12("-exportcert", "-alias", "acme-root-ca", "-rfc", "-file", w("acme-root.pem"));
  jks("-importcert", "-alias", "acme-root-ca", "-file", w("acme-root.pem"), "-noprompt");

  // A CSR from a partner team, signed on the CA & Signing page.
  sh("openssl", ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", w("payments.key"), "-out", w("payments.csr"),
    "-subj", "/CN=payments.acme.dev/OU=Payments/O=Acme Corp/C=US", "-addext", "subjectAltName=DNS:payments.acme.dev,DNS:pay.acme.dev"]);
  // A certificate chain file for the Certificates page.
  fs.writeFileSync(w("api-chain.pem"), fs.readFileSync(w("api.acme.dev.crt"), "utf8") + fs.readFileSync(w("acme-root.pem"), "utf8"));
}

// ---- Engine and page -------------------------------------------------------------------------

function startEngine() {
  return new Promise((resolve, reject) => {
    bridge = spawn("cargo", ["run", "--manifest-path", "src-tauri/Cargo.toml", "--example", "ui_bridge", "--no-default-features", "-q"], { cwd: ROOT, env: { ...process.env, HOME: WORK } });
    let out = "";
    bridge.stdout.on("data", (d) => {
      out += d.toString();
      const m = out.match(/(\d{3,5})/);
      if (m) resolve(Number(m[1]));
    });
    bridge.stderr.on("data", (d) => process.stderr.write(`[engine] ${d}`));
    bridge.once("exit", (c) => reject(new Error(`engine exited ${c}`)));
  });
}

/** Serves dist/ with the Tauri shim injected (see e2e/headless-ui.mjs, which this mirrors). */
function startServer(port) {
  const shim = `
    window.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      invoke: (cmd, args) =>
        cmd.startsWith("plugin:")
          ? Promise.resolve(null)
          : fetch("http://127.0.0.1:${port}/", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ cmd, args: args || {} }) })
              .then((r) => r.json())
              .then((r) => { if (r.error) throw new Error(r.error); return r.ok; }),
      transformCallback: (cb) => { const id = Math.random(); window[id] = cb; return id; },
      unregisterCallback: (id) => { delete window[id]; },
    };
    window.__xksStub = { open: [], save: [] };
  `;
  const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2" };
  server = http.createServer((req, res) => {
    let file = req.url.split("?")[0];
    if (file === "/") file = "/index.html";
    const full = path.join(DIST, file);
    if (!full.startsWith(DIST) || !fs.existsSync(full)) return res.writeHead(404).end();
    let body = fs.readFileSync(full);
    if (file === "/index.html") body = Buffer.from(body.toString().replace("<head>", `<head><script>${shim}</script>`));
    res.writeHead(200, { "Content-Type": MIME[path.extname(full)] ?? "application/octet-stream" }).end(body);
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
}

const byTest = (id) => By.css(`[data-testid="${id}"]`);
const find = (id, timeout = 15000) => driver.wait(until.elementLocated(byTest(id)), timeout, `no [data-testid="${id}"]`);
const click = async (id) => driver.executeScript("arguments[0].click()", await find(id));
const setField = async (id, value) =>
  driver.executeScript(
    `const el = arguments[0], v = arguments[1];
     const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
     Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
     el.dispatchEvent(new Event("input", { bubbles: true }));`,
    await find(id), value);
const clickButton = (text) =>
  driver.executeScript(
    `const el = [...document.querySelectorAll("button, [role=tab]")].find((b) => !b.disabled && b.innerText.replace(/\\s+/g, " ").trim() === ${JSON.stringify(text)});
     if (!el) throw new Error("no button: " + ${JSON.stringify(text)}); el.click();`);
const waitText = (text, timeout = 15000) =>
  driver.wait(async () => (await driver.findElement(By.tagName("body")).getText()).includes(text), timeout, `never saw "${text}"`);
const gone = (id, timeout = 15000) => driver.wait(async () => (await driver.findElements(byTest(id))).length === 0, timeout, `${id} never closed`);
const escape = () => driver.actions().sendKeys("").perform();
const nav = async (id) => {
  await click(`nav-${id}`);
  await sleep(400);
};
const openFile = async (file) => {
  await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(file)});`);
  await click("header-open");
};
const dismissToasts = () => driver.executeScript(`document.querySelectorAll('[data-testid^="toast-"] button[aria-label="Dismiss"]').forEach((b) => b.click())`);

/** Sizes the window so the page itself is W×H (a headless window frame still takes some height). */
async function setViewport() {
  await driver.manage().window().setRect({ width: W, height: H });
  const [iw, ih] = await driver.executeScript("return [window.innerWidth, window.innerHeight]");
  await driver.manage().window().setRect({ width: W + (W - iw), height: H + (H - ih) });
}

/** The theme setting defaults to System, so this switches the app the way the OS would. */
async function colorScheme(value) {
  await driver.sendDevToolsCommand("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value }] });
  await sleep(300);
}

const shots = [];
async function shot(name) {
  await dismissToasts();
  await sleep(500);
  const file = path.join(OUT, `${name}.png`);
  fs.writeFileSync(file, await driver.takeScreenshot(), "base64");
  shots.push(file);
  log(`saved ${path.relative(ROOT, file)}`);
}

async function scene(name, fn) {
  try {
    await fn();
  } catch (err) {
    log(`FAILED ${name}: ${err?.message ?? err}`);
    process.exitCode = 1;
    try { await escape(); } catch { /* page gone */ }
  }
}

// ---- Scenes ----------------------------------------------------------------------------------

async function run() {
  makeFixtures();
  fs.mkdirSync(OUT, { recursive: true });
  const port = await startEngine();
  const web = await startServer(port);

  const opts = new chrome.Options().addArguments("--headless=new", "--disable-gpu", "--no-sandbox", "--force-device-scale-factor=1.5", "--hide-scrollbars");
  if (process.env.XKS_CHROME !== "system") opts.setBrowserVersion(process.env.XKS_CHROME || "stable");
  driver = await new Builder().forBrowser("chrome").setChromeOptions(opts).build();
  await setViewport();
  await colorScheme("light");
  await driver.get(`http://127.0.0.1:${web}/`);
  await waitText("Welcome to Keystore Studio", 30000);

  await scene("vault setup", async () => {
    await nav("vault");
    await setField("vault-key", "correct horse battery");
    await setField("vault-key-confirm", "correct horse battery");
    await click("vault-submit");
    await find("vault-lock");
  });

  const openKeystore = async (file) => {
    await openFile(file);
    await setField("open-password", PW);
    const remember = await driver.findElements(By.css('[data-testid="remember-password"]'));
    if (remember.length) await driver.executeScript("arguments[0].click()", remember[0]);
    await click("open-submit");
    await gone("open-submit");
  };

  await scene("keystores", async () => {
    await nav("keystores");
    await openKeystore(TRUST);
    await openKeystore(PROD);
    await find("tree-entry-api.acme.dev");
    await click("unlock-all");
    await setField("unlock-key-password", PW);
    await click("unlock-key-submit");
    await gone("unlock-key-submit", 30000);
    await shot("keystores");
    await click("tree-entry-api.acme.dev");
    await find("entry-inspector");
    await shot("entry-inspector");
    await escape();
    await gone("entry-inspector");
  });

  await scene("certificates", async () => {
    await openFile(w("api-chain.pem"));
    await find("certificates-page");
    await openFile(w("partner-root.pem"));
    await sleep(800);
    await shot("certificates");
  });

  await scene("examine", async () => {
    await nav("examine");
    await setField("tls-host", "github.com");
    await setField("tls-port", "443");
    await click("tls-run");
    await find("tls-result", 30000);
    await shot("examine-tls");
  });

  await scene("ca & signing", async () => {
    await nav("ca_signing");
    await setField("sign-csr-input", fs.readFileSync(w("payments.csr"), "utf8"));
    await sleep(800);
    await click("sign-csr-submit");
    await find("issued-chain", 20000);
    await shot("ca-signing");
  });

  await scene("convert", async () => {
    await nav("convert");
    await shot("convert");
  });

  await scene("security audit", async () => {
    await nav("scanner");
    await sleep(1000);
    await shot("security-audit");
  });

  await scene("vault", async () => {
    await nav("vault");
    await shot("vault");
  });

  await scene("dashboard", async () => {
    await nav("home");
    await shot("dashboard");
  });

  await scene("terminal", async () => {
    await nav("keystores");
    await click("header-terminal");
    const input = await driver.wait(until.elementLocated(By.css('[data-testid="terminal"] input')), 10000);
    await input.sendKeys("openssl x509 -in api.acme.dev.crt -noout -subject -issuer -enddate -ext subjectAltName,extendedKeyUsage", "");
    await waitText("notAfter=", 30000);
    await shot("terminal");
    await click("header-terminal");
  });

  await scene("command palette", async () => {
    await click("open-palette");
    await find("palette-input");
    await shot("command-palette");
    await escape();
  });

  await scene("dark theme", async () => {
    await colorScheme("dark");
    await nav("keystores");
    await shot("keystores-dark");
    await nav("home");
    await shot("dashboard-dark");
    await colorScheme("light");
  });
}

try {
  await run();
} finally {
  await driver?.quit().catch(() => {});
  server?.close();
  bridge?.kill();
  fs.rmSync(TMP, { recursive: true, force: true });
  log(`${shots.length} screenshots in ${path.relative(ROOT, OUT) || OUT}`);
}
