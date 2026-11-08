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
  // stdin closed: OpenSSL 3.4+ tries to prompt on a piped stdin even when -passin is given.
  const r = spawnSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, JAVA_TOOL_OPTIONS: "" } });
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
    try { log("page text at failure:\n" + (await driver.findElement(By.tagName("body")).getText()).slice(0, 1500)); } catch { /* page gone */ }
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
/** Set XKS_SCREENSHOTS=<dir> to save a PNG of the window at the main screens, for review. */
const shot = async (name) => {
  const dir = process.env.XKS_SCREENSHOTS;
  if (!dir) return;
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${name}.png`), await driver.takeScreenshot(), "base64");
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

  // ---- Keystore dialogs added with the PKCS#12 builder: key password and compare ----
  const JKS = path.join(WORK, "kp.jks");
  const JKS_OUT = path.join(WORK, "kp-out.jks");
  const STORE_PW = "storepw1";
  const rowMenu = async (alias, item) => {
    await click(`row-menu-${alias}`);
    await click(item);
  };

  await step("a key with its own password opens locked and unlocks through the UI", async () => {
    sh("keytool", ["-genkeypair", "-alias", "sep", "-keyalg", "EC", "-dname", "CN=sep", "-storetype", "JKS", "-keystore", JKS, "-storepass", STORE_PW, "-keypass", "keypass1"]);
    await driver.actions().sendKeys("\uE00C").perform(); // Escape closes the PKCS#12 dialog
    await click("nav-keystores");
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(JKS)});`);
    await click("empty-open");
    await setField("open-password", STORE_PW);
    await click("open-submit");
    await waitText("sep");
    await rowMenu("sep", "menu-unlock");
    await setField("unlock-key-password", "wrong-key-pw");
    await click("unlock-key-submit");
    await waitText("password", 10000);
    await setField("unlock-key-password", "keypass1");
    await click("unlock-key-submit");
    await driver.wait(async () => (await driver.findElements(byTest("unlock-key-submit"))).length === 0, 10000, "unlock dialog never closed");
  });

  await step("change key password in the UI, save, and keytool accepts only the new one", async () => {
    await rowMenu("sep", "menu-keypw");
    await setField("keypw-new", "newkey99");
    await setField("keypw-confirm", "newkey99");
    await click("keypw-submit");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(JKS_OUT)});`);
    await click("ks-more");
    await click("ks-save-as");
    // Distinct key passwords are a JKS/JCEKS feature (keytool -keypasswd); Java's PKCS12 ignores them.
    const fmt = await driver.wait(until.elementLocated(byTest("save-format")), 10000);
    await driver.executeScript(
      `Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(arguments[0], "JKS");
       arguments[0].dispatchEvent(new Event("change", { bubbles: true }));`, fmt);
    await click("save-choose-location");
    await driver.wait(async () => fs.existsSync(JKS_OUT), 20000, "saved keystore never appeared");
    sh("keytool", ["-certreq", "-alias", "sep", "-keystore", JKS_OUT, "-storepass", STORE_PW, "-keypass", "newkey99", "-file", path.join(WORK, "kp.csr")]);
    const old = spawnSync("keytool", ["-certreq", "-alias", "sep", "-keystore", JKS_OUT, "-storepass", STORE_PW, "-keypass", "keypass1", "-file", path.join(WORK, "kp2.csr")], { encoding: "utf8", env: { ...process.env, JAVA_TOOL_OPTIONS: "" } });
    if (old.status === 0) throw new Error("the old key password still works after the change");
  });

  await step("compare against the file on disk reports an entry added on disk", async () => {
    sh("keytool", ["-genkeypair", "-alias", "extra", "-keyalg", "EC", "-dname", "CN=extra", "-storetype", "JKS", "-keystore", JKS_OUT, "-storepass", STORE_PW, "-keypass", STORE_PW]);
    await click("ks-more");
    await click("ks-compare");
    await click("diff-disk");
    await waitText("Added: extra", 15000);
  });

  // ---- Keystore navigator, locked key pairs and the Convert page ----
  const P12 = path.join(WORK, "nav.p12");
  const P12_PW = "navpass1";
  const clickTab = async (label) => {
    const el = await driver.wait(until.elementLocated(By.xpath(`//button[@role="tab"][contains(normalize-space(.), ${JSON.stringify(label)})]`)), 10000);
    await driver.executeScript("arguments[0].click()", el);
  };
  const exists = async (css) => (await driver.findElements(By.css(css))).length > 0;
  const certPem = () => fs.readFileSync(path.join(WORK, "ui-cert.pem"), "utf8");

  await step("a key pair read from a file opens locked and needs its key password", async () => {
    await driver.actions().sendKeys("\uE00C").perform(); // close the compare dialog
    sh("keytool", ["-genkeypair", "-alias", "web", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=web.nav.test", "-storetype", "PKCS12", "-keystore", P12, "-storepass", P12_PW]);
    sh("keytool", ["-importcert", "-noprompt", "-alias", "anchor", "-file", path.join(WORK, "ui-cert.pem"), "-storetype", "PKCS12", "-keystore", P12, "-storepass", P12_PW]);
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(P12)});`);
    await click("ks-open");
    await setField("open-password", P12_PW);
    await click("open-submit");
    // Both keystores are listed in the navigator, with this one's entries under it.
    await driver.wait(until.elementLocated(byTest("tree-entry-web")), 10000);
    if (!(await exists('[data-testid="ks-tab-kp-out.jks"]'))) throw new Error("the earlier keystore is missing from the navigator");
    if (!(await exists('[data-testid="tree-entry-anchor"]'))) throw new Error("the certificate is missing from the navigator");
    // Each type has its own icon, and the key pair wears a lock.
    if (!(await exists('[data-entry-type="KeyPair"][data-locked="true"]'))) throw new Error("the key pair is not shown locked");
    if (!(await exists('[data-entry-type="TrustedCertificate"]'))) throw new Error("no certificate icon");
    await shot("keystores-locked");
    await click("tree-entry-web");
    await driver.wait(until.elementLocated(byTest("unlock-key-dialog")), 10000);
    await shot("unlock-dialog");
    if (await exists('[data-testid="entry-inspector"]')) throw new Error("the inspector opened before the key was unlocked");
    await setField("unlock-key-password", "not-the-password");
    await click("unlock-key-submit");
    await waitText("Incorrect key password", 10000);
    await setField("unlock-key-password", P12_PW);
    await click("unlock-key-submit");
    await driver.wait(until.elementLocated(byTest("entry-inspector")), 10000);
    if (await exists('[data-entry-type="KeyPair"][data-locked="true"]')) throw new Error("the key pair still shows locked");
    await driver.actions().sendKeys("\uE00C").perform();
  });

  await step("the Convert row toggles its submenu and Open is icon-only", async () => {
    const expanded = async () => (await driver.findElement(byTest("nav-convert"))).getAttribute("aria-expanded");
    if (await expanded() !== "true") throw new Error("conversions should start expanded");
    await click("nav-convert");
    if (await expanded() !== "false" || await exists('[data-testid="nav-convert-certificate"]')) {
      throw new Error("clicking Convert did not collapse its submenu");
    }
    await click("nav-convert");
    if (await expanded() !== "true" || !(await exists('[data-testid="nav-convert-certificate"]'))) {
      throw new Error("clicking Convert did not expand its submenu");
    }
    const open = await driver.findElement(byTest("header-open"));
    if (await open.getText() || await open.getAttribute("aria-label") !== "Open (Ctrl+O)") throw new Error("Open should be an accessible icon-only button");
    if ((await driver.findElement(By.tagName("body")).getText()).includes("Local Rust engine · offline")) throw new Error("offline status is still shown");
  });

  await step("convert a certificate to a PKCS#7 bundle that OpenSSL reads", async () => {
    const out = path.join(WORK, "conv.p7b");
    await click("nav-convert-certificate");
    await setField("convert-input", certPem());
    await waitText("X.509 certificate", 10000);
    await click("convert-target-pkcs7_pem");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("convert-save");
    await driver.wait(async () => fs.existsSync(out), 20000, "the PKCS#7 file was never written");
    await shot("convert-certificate");
    const dump = sh("openssl", ["pkcs7", "-in", out, "-print_certs", "-noout"]);
    if (!dump.includes("headless.e2e.test")) throw new Error(`unexpected bundle:\n${dump}`);
  });

  await step("preview a certificate's public key as an OpenSSH line", async () => {
    await click("nav-convert-public_key");
    await setField("convert-input", certPem());
    await click("convert-target-openssh");
    await click("convert-preview");
    const el = await driver.wait(until.elementLocated(byTest("convert-output")), 15000);
    const line = (await el.getText()).trim();
    await shot("convert-public-key");
    if (!line.startsWith("ssh-rsa ")) throw new Error(`not an OpenSSH line: ${line}`);
    const pub = path.join(WORK, "conv.pub");
    fs.writeFileSync(pub, `${line}\n`);
    sh("ssh-keygen", ["-l", "-f", pub]);
  });

  await step("convert a private key to encrypted PKCS#8", async () => {
    const out = path.join(WORK, "conv-enc.key");
    await click("nav-convert-private_key");
    await setField("convert-input", fs.readFileSync(path.join(WORK, "ui-key.pem"), "utf8"));
    await click("convert-target-pkcs8_encrypted_pem");
    await setField("convert-out-password", "enc-pass-1");
    await setField("convert-out-password-confirm", "enc-pass-1");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("convert-save");
    await driver.wait(async () => fs.existsSync(out), 20000, "the key was never written");
    if (!fs.readFileSync(out, "utf8").includes("BEGIN ENCRYPTED PRIVATE KEY")) throw new Error("the key is not encrypted PKCS#8");
    sh("openssl", ["pkey", "-in", out, "-passin", "pass:enc-pass-1", "-noout"]);
    if (spawnSync("openssl", ["pkey", "-in", out, "-passin", "pass:wrong", "-noout"], { stdio: "ignore" }).status === 0) throw new Error("the wrong password decrypted the key");
  });

  await step("convert a JKS file to PKCS#12 that keytool accepts", async () => {
    const out = path.join(WORK, "from-jks.p12");
    await click("nav-convert-keystore");
    await clickTab("File on disk");
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(JKS_OUT)});`);
    await click("convert-ks-pick");
    await setField("convert-ks-password", STORE_PW);
    await click("convert-ks-load");
    await driver.wait(until.elementLocated(byTest("convert-ks-summary")), 15000);
    // 'sep' has its own key password, so PKCS#12 is refused until it is given.
    await click("convert-format-PKCS12");
    await waitText("can only be saved back to JKS", 10000);
    await setField("convert-ks-keypw", "newkey99");
    await click("convert-ks-unlock");
    await driver.wait(async () => !(await driver.findElement(By.tagName("body")).getText()).includes("locked by their own key password"), 15000, "the locked key never unlocked");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("convert-save");
    await driver.wait(async () => fs.existsSync(out), 20000, "the PKCS#12 was never written");
    const list = sh("keytool", ["-list", "-keystore", out, "-storetype", "PKCS12", "-storepass", STORE_PW]);
    if (!list.includes("extra") || !list.includes("sep")) throw new Error(`entries missing:\n${list}`);
    // Every key, including the one that had its own password, opens with the one PKCS#12 password.
    const dump = sh("openssl", ["pkcs12", "-in", out, "-passin", `pass:${STORE_PW}`, "-nodes"]);
    if ((dump.match(/BEGIN PRIVATE KEY/g) ?? []).length !== 2) throw new Error(`expected two keys under the store password:\n${dump}`);
  });

  await step("export an open keystore to PEM after unlocking its key pair", async () => {
    const out = path.join(WORK, "nav.pem");
    await click("nav-keystores");
    await click("ks-tab-nav.p12");
    await click("ks-more");
    await click("ks-lock-all");
    await click("ks-more");
    await click("ks-extract");
    await driver.wait(until.elementLocated(byTest("convert-entries")), 10000);
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("convert-save");
    // The key pair was locked again, so its key password is asked for first.
    await driver.wait(until.elementLocated(byTest("unlock-key-dialog")), 10000);
    if (fs.existsSync(out)) throw new Error("the PEM was written before the key was unlocked");
    await setField("unlock-key-password", P12_PW);
    await click("unlock-key-submit");
    await driver.wait(async () => fs.existsSync(out), 20000, "the PEM was never written");
    await shot("convert-extract");
    await click("nav-keystores");
    await waitText("Median key age");
    await shot("keystores-unlocked");
    await click("nav-convert");
    await shot("convert-overview");
    const pem = fs.readFileSync(out, "utf8");
    if ((pem.match(/BEGIN CERTIFICATE/g) ?? []).length !== 2) throw new Error(`expected 2 certificates:\n${pem}`);
    sh("openssl", ["pkey", "-in", out, "-noout"]);
    sh("openssl", ["x509", "-in", out, "-noout"]);
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
