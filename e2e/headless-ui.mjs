// Drives the real built frontend in headless Chrome against the real Rust engine.
//
// This exists for machines where the Tauri webview cannot run at all: macOS does not execute
// JavaScript in a WKWebView that has no display surface (a locked screen, or a session without
// Screen Recording / Accessibility permission), so e2e/eval-drive.mjs cannot start there.
// Headless Chrome needs no display surface, so the UI itself can still be exercised.
//
// What is real here: the production `dist/` bundle (the same React code the app ships), and the
// engine behind every command (examples/ui_bridge.rs calls the same xkeystore_lib functions the
// Tauri commands call). What is replaced: the webview and the Tauri IPC transport.
//
//   pnpm build && node e2e/headless-ui.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DIST = path.join(ROOT, "dist");
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "xks-headless-"));
const results = [];
let driver, bridge, server, bridgePort;

const log = (...a) => console.log("[headless]", ...a);
const sh = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, JAVA_TOOL_OPTIONS: "" } });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.stdout}${r.stderr}`);
  return `${r.stdout}${r.stderr}`;
};

const MIME = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png" };

function startEngine() {
  return new Promise((resolve, reject) => {
    bridge = spawn("cargo", ["run", "--manifest-path", "src-tauri/Cargo.toml", "--example", "ui_bridge", "--no-default-features", "-q"], { cwd: ROOT });
    let out = "";
    const onData = (d) => {
      out += d.toString();
      const m = out.match(/(\d{3,5})/);
      if (m) {
        bridge.stdout.off("data", onData);
        resolve(Number(m[1]));
      }
    };
    bridge.stdout.on("data", onData);
    bridge.stderr.on("data", (d) => process.stderr.write(`[engine] ${d}`));
    bridge.once("exit", (c) => reject(new Error(`engine exited ${c}`)));
    setTimeout(() => reject(new Error("engine did not report a port")), 90000);
  });
}

/** Serves dist/, and injects the Tauri shim so the UI's commands reach the real engine. */
function startServer(port) {
  const shim = `
    window.__TAURI_INTERNALS__ = {
      invoke: (cmd, args) =>
        fetch("http://127.0.0.1:${port}/", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ cmd, args: args || {} }),
        })
          .then((r) => r.json())
          .then((r) => { if (r.error) throw new Error(r.error); return r.ok; }),
      transformCallback: (cb) => { const id = Math.random(); window[id] = cb; return id; },
    };
    window.__xksStub = { open: [], save: [] };
  `;
  server = http.createServer((req, res) => {
    let file = req.url.split("?")[0];
    if (file === "/") file = "/index.html";
    const full = path.join(DIST, file);
    if (!full.startsWith(DIST) || !fs.existsSync(full)) {
      res.writeHead(404).end("not found");
      return;
    }
    let body = fs.readFileSync(full);
    if (file === "/index.html") {
      body = Buffer.from(body.toString().replace("<head>", `<head><script>${shim}</script>`));
    }
    res.writeHead(200, { "Content-Type": MIME[path.extname(full)] ?? "application/octet-stream" });
    res.end(body);
  });
  return new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
}

async function step(name, fn) {
  const t = Date.now();
  try {
    await fn();
    results.push({ name, ok: true });
    log(`PASS ${name} (${Date.now() - t} ms)`);
  } catch (err) {
    results.push({ name, ok: false, err: String(err?.message ?? err) });
    log(`FAIL ${name}: ${err?.message ?? err}`);
    throw err;
  }
}

const byTest = (id) => By.css(`[data-testid="${id}"]`);
const click = async (id) => {
  const el = await driver.wait(until.elementLocated(byTest(id)), 10000);
  await driver.wait(until.elementIsEnabled(el), 10000);
  await driver.executeScript("arguments[0].click()", el);
};
const setField = async (id, value) => {
  const el = await driver.wait(until.elementLocated(byTest(id)), 10000);
  await driver.executeScript(
    `const el = arguments[0], v = arguments[1];
     const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
     Object.getOwnPropertyDescriptor(proto, "value").set.call(el, v);
     el.dispatchEvent(new Event("input", { bubbles: true }));
     el.dispatchEvent(new Event("change", { bubbles: true }));`,
    el, value);
};
const waitText = (text, timeout = 15000) =>
  driver.wait(async () => (await driver.findElement(By.tagName("body")).getText()).includes(text), timeout, `never saw "${text}"`);

async function run() {
  bridgePort = await startEngine();
  log(`engine on ${bridgePort}`);
  const webPort = await startServer(bridgePort);
  log(`frontend on ${webPort}`);

  const opts = new chrome.Options().addArguments("--headless=new", "--disable-gpu", "--no-sandbox", "--window-size=1400,900");
  driver = await new Builder().forBrowser("chrome").setChromeOptions(opts).build();
  await driver.get(`http://127.0.0.1:${webPort}/`);

  await step("the real UI boots and renders the dashboard", async () => {
    await waitText("xkeystore", 20000);
    const ran = await driver.executeScript("return typeof window.__TAURI_INTERNALS__ === 'object'");
    if (!ran) throw new Error("the Tauri shim is not present; the page did not run its scripts");
  });

  await step("the engine is reachable from the page", async () => {
    const info = await driver.executeScript(
      "return window.__TAURI_INTERNALS__.invoke('app_info').then(v => JSON.stringify(v), e => 'ERR ' + e.message)"
    );
    if (!info.includes("1.0.0")) throw new Error(`app_info did not answer: ${info}`);
  });

  await step("the dashboard action opens the PKCS#12 dialog", async () => {
    await driver.executeScript("window.__xksErrors = []; window.addEventListener('error', e => window.__xksErrors.push(String(e.message)));");
    await click("welcome-build-p12");
    await waitText("Create PKCS#12");
  });

  await step("create a PKCS#12 from a certificate and key through the UI", async () => {
    const cert = path.join(WORK, "ui-cert.pem");
    const key = path.join(WORK, "ui-key.pem");
    const out = path.join(WORK, "ui-out.pfx");
    const PW = "ui-pass-9";
    sh("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "30", "-nodes", "-subj", "/CN=headless.e2e.test/O=xkeystore UI"]);

    // Paste the certificate and key, set the passphrase, name the alias.
    await setField("build-p12-cert", fs.readFileSync(cert, "utf8"));
    await setField("build-p12-key", fs.readFileSync(key, "utf8"));
    await setField("build-p12-pass", PW);
    await setField("build-p12-pass-confirm", PW);
    await setField("build-p12-alias", "ui-built");

    // The save dialog is native, so the destination is injected the way the app's stub does it.
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("build-p12-submit");

    // The UI must report success, and the file must exist.
    await waitText("PKCS#12 created", 30000);
    if (!fs.existsSync(out)) throw new Error("the UI reported success but no file was written");

    // And it must be a real PKCS#12 that OpenSSL and keytool accept.
    const dump = sh("openssl", ["pkcs12", "-in", out, "-passin", `pass:${PW}`, "-nodes"]);
    if (!dump.includes("BEGIN PRIVATE KEY")) throw new Error(`no private key:\n${dump}`);
    if (!dump.includes("friendlyName: ui-built")) throw new Error(`alias missing:\n${dump}`);
    const list = sh("keytool", ["-list", "-v", "-keystore", out, "-storetype", "PKCS12", "-storepass", PW]);
    if (!list.includes("PrivateKeyEntry")) throw new Error(`keytool sees no key:\n${list}`);
    if (!list.includes("headless.e2e.test")) throw new Error(`unexpected subject:\n${list}`);
    log("   openssl and keytool both accept the file the UI produced");
  });

  await step("the UI refuses a key that does not match the certificate", async () => {
    const otherKey = path.join(WORK, "other.pem");
    sh("openssl", ["genrsa", "-out", otherKey, "2048"]);
    const cert = fs.readFileSync(path.join(WORK, "ui-cert.pem"), "utf8");
    await setField("build-p12-cert", cert);
    await setField("build-p12-key", fs.readFileSync(otherKey, "utf8"));
    await setField("build-p12-pass", "x-pass-1");
    await setField("build-p12-pass-confirm", "x-pass-1");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(path.join(WORK, "never.pfx"))});`);
    await click("build-p12-submit");
    await waitText("matches the private key", 20000);
    if (fs.existsSync(path.join(WORK, "never.pfx"))) throw new Error("a file was written for a mismatched pair");
  });
}

let failed = false;
try {
  await run();
} catch {
  failed = true;
} finally {
  try { await driver?.quit(); } catch { /* already gone */ }
  server?.close();
  bridge?.kill();
  const passed = results.filter((r) => r.ok).length;
  log(`${passed}/${results.length} steps passed. Work dir: ${WORK}`);
  process.exit(failed ? 1 : 0);
}
