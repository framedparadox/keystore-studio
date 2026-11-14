// Drives the real built frontend in headless Chrome against the real Rust engine.
//
// This exists for machines where the Tauri webview cannot run at all: macOS does not execute
// JavaScript in a WKWebView that has no display surface (a locked screen, or a session without
// Screen Recording / Accessibility permission), so e2e/eval-drive.mjs cannot start there.
// Headless Chrome needs no display surface, so the UI itself can still be exercised.
//
// What is real here: the production `dist/` bundle (the same React code the app ships), and the
// engine behind every command (examples/ui_bridge.rs calls the same keystore_studio_lib functions the
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
import { Builder, By, Key, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
// XKS_DIST=<dir> drives another build of the frontend, e.g. the previous one, to show a new test fails there.
const DIST = path.resolve(process.env.XKS_DIST || path.join(ROOT, "dist"));
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
  // Window metadata and the plugin channel (events, opener) belong to the Tauri runtime, not the
  // engine: they are answered here, so the app's window hooks (the unsaved-changes guard, drag and
  // drop) start without errors. Engine commands go to the bridge.
  const shim = `
    window.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
      invoke: (cmd, args) =>
        cmd.startsWith("plugin:")
          ? Promise.resolve(null)
          : fetch("http://127.0.0.1:${port}/", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ cmd, args: args || {} }),
            })
              .then((r) => r.json())
              .then((r) => { if (r.error) throw new Error(r.error); return r.ok; }),
      transformCallback: (cb) => { const id = Math.random(); window[id] = cb; return id; },
      unregisterCallback: (id) => { delete window[id]; },
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
    // XKS_KEEP_GOING=1 runs every step, to see all that fail (e.g. new steps against an old build).
    if (process.env.XKS_KEEP_GOING) {
      try { await driver.actions().sendKeys("\uE00C").perform(); } catch { /* no page */ }
      return;
    }
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
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const exists = async (css) => (await driver.findElements(By.css(css))).length > 0;
  bridgePort = await startEngine();
  log(`engine on ${bridgePort}`);
  const webPort = await startServer(bridgePort);
  log(`frontend on ${webPort}`);

  const opts = new chrome.Options().addArguments("--headless=new", "--disable-gpu", "--no-sandbox", "--window-size=1400,900");
  // A pinned Chrome for Testing build (Selenium Manager downloads and caches it), not the desktop
  // Chrome: an everyday Chrome that has an update waiting quits a headless session after ~35 s,
  // which ends the run halfway. XKS_CHROME=system uses the installed Chrome; any other value is a
  // Chrome for Testing version or channel.
  if (process.env.XKS_CHROME !== "system") opts.setBrowserVersion(process.env.XKS_CHROME || "stable");
  driver = await new Builder().forBrowser("chrome").setChromeOptions(opts).build();
  await driver.get(`http://127.0.0.1:${webPort}/`);

  await step("the real UI boots and renders the dashboard", async () => {
    await waitText("Keystore Studio", 20000);
    const ran = await driver.executeScript("return typeof window.__TAURI_INTERNALS__ === 'object'");
    if (!ran) throw new Error("the Tauri shim is not present; the page did not run its scripts");
    if ((await driver.findElements(byTest("undo"))).length || (await driver.findElements(byTest("redo"))).length) {
      throw new Error("undo or redo is visible with no history");
    }
  });

  await step("the header and sidebar use theme-aware monochrome accents", async () => {
    const previous = await driver.executeScript("return document.documentElement.dataset.theme");
    try {
      for (const [theme, accent, foreground] of [
        ["light", "rgb(0, 0, 0)", "rgb(255, 255, 255)"],
        ["dark", "rgb(255, 255, 255)", "rgb(0, 0, 0)"],
      ]) {
        await driver.executeScript("document.documentElement.dataset.theme = arguments[0]", theme);
        await sleep(500);
        const colors = await driver.executeScript(`const button = document.querySelector('[data-testid="header-new"]');
          const icon = document.querySelector('[data-testid="nav-home"] svg');
          return { background: getComputedStyle(button).backgroundColor, foreground: getComputedStyle(button).color,
            icon: getComputedStyle(icon).color, terminal: getComputedStyle(document.querySelector('[data-testid="header-terminal"] svg')).color,
            pageAccent: getComputedStyle(document.documentElement).getPropertyValue("--color-brand").trim() };`);
        if (colors.background !== accent || colors.foreground !== foreground || colors.icon !== accent || colors.terminal !== accent || colors.pageAccent === (theme === "light" ? "#000000" : "#ffffff")) {
          throw new Error(`unexpected ${theme} shell colors: ${JSON.stringify(colors)}`);
        }
      }
    } finally {
      await driver.executeScript("document.documentElement.dataset.theme = arguments[0]", previous);
    }
  });

  await step("sidebar: Workspaces follows Dashboard and footer controls toggle the theme", async () => {
    const layout = await driver.executeScript(`const home = document.querySelector('[data-testid="nav-home"]');
      const workspace = document.querySelector('[data-testid="nav-workspaces"]');
      const controls = ["sidebar-collapse", "sidebar-theme", "sidebar-terminal"].map(id => document.querySelector('[data-testid="' + id + '"]'));
      return { next: home.nextElementSibling === workspace,
        sameRow: controls.every(el => Math.abs(el.getBoundingClientRect().top - controls[0].getBoundingClientRect().top) < 1),
        divider: controls[0].parentElement.previousElementSibling.getBoundingClientRect().width / controls[0].parentElement.getBoundingClientRect().width };`);
    if (!layout.next || !layout.sameRow || Math.abs(layout.divider - 0.5) > 0.01) throw new Error(`unexpected sidebar layout: ${JSON.stringify(layout)}`);
    const previous = await driver.executeScript("return document.documentElement.dataset.theme");
    await click("sidebar-theme");
    await driver.wait(async () => (await driver.executeScript("return document.documentElement.dataset.theme")) !== previous, 5000, "theme did not change");
    await click("sidebar-theme");
    await driver.wait(async () => (await driver.executeScript("return document.documentElement.dataset.theme")) === previous, 5000, "theme did not change back");
    await click("sidebar-terminal");
    if (!(await exists('[data-testid="terminal"]'))) throw new Error("sidebar terminal button did not open the terminal");
    await click("sidebar-terminal");
    if (await exists('[data-testid="terminal"]')) throw new Error("sidebar terminal button did not close the terminal");
  });

  await step("settings: section defaults are restored from the page header", async () => {
    await click("nav-settings");
    const position = await driver.executeScript(`const button = document.querySelector('[data-testid="settings-restore"]');
      const header = [...document.querySelectorAll("h1")].find(el => el.textContent === "Settings")?.parentElement.parentElement.parentElement;
      if (!button || !header) return null;
      return { inside: header.contains(button), rightGap: header.getBoundingClientRect().right - button.getBoundingClientRect().right };`);
    if (!position?.inside || Math.abs(position.rightGap) > 1) throw new Error(`restore action is not at the right of the page header: ${JSON.stringify(position)}`);
    await click("settings-tab-security");
    if (await exists('[data-testid="settings-restore"]')) throw new Error("restore action is visible for an unchanged section");
    await click("settings-tab-general");
    await click("settings-restore");
    if (await exists('[data-testid="settings-restore"]')) throw new Error("restoring the section did not clear its changes");
    await click("nav-home");
  });

  await step("settings: Help search shares the heading row and About centers the app identity", async () => {
    await click("nav-settings");
    await click("settings-tab-help");
    const help = await driver.executeScript(`const input = document.querySelector('[data-testid="help-search"]');
      const heading = document.querySelector('#settings-panel-help h3');
      const a = heading.getBoundingClientRect(), b = input.getBoundingClientRect();
      return { sameRow: Math.abs(a.top - b.top) < 10, toRight: b.left > a.right };`);
    if (!help.sameRow || !help.toRight) throw new Error(`Help search is not beside its heading: ${JSON.stringify(help)}`);
    await setField("help-search", "master key");
    if (!(await exists('[data-testid="help-topic-vault"]'))) throw new Error("Help search did not return the vault topic");
    await setField("help-search", "zzzz-no-help-match");
    await waitText("No matching topics");
    await click("settings-tab-about");
    const about = await driver.executeScript(`const panel = document.querySelector('#settings-panel-about');
      const heading = [...panel.querySelectorAll('h3')].find(el => el.textContent === 'About Keystore Studio');
      const identity = heading.parentElement.parentElement;
      const image = [...identity.querySelectorAll('img')].find(el => getComputedStyle(el).display !== 'none');
      const row = heading.parentElement.getBoundingClientRect(), box = identity.getBoundingClientRect();
      return { logo: !!image, centered: Math.abs((row.left + row.right - box.left - box.right) / 2) < 1,
        version: identity.lastElementChild.textContent.trim() };`);
    if (!about.logo || !about.centered || !about.version.startsWith("Version ")) throw new Error(`unexpected About identity: ${JSON.stringify(about)}`);
    await click("nav-home");
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
    sh("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "30", "-nodes", "-subj", "/CN=headless.e2e.test/O=Keystore Studio UI"]);

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
    // The direction must be stated: 'extra' exists only on disk, not in the keystore open here.
    const rowText = async (id) => {
      const els = await driver.findElements(byTest(id));
      return els.length ? els[0].getText() : "";
    };
    await driver.wait(async () => (await rowText("diff-only-there")).includes("extra"), 15000, "'extra' was not reported as only in the file on disk");
    if ((await rowText("diff-only-here")).includes("extra")) throw new Error("'extra' was reported as only in the open keystore");
    if (!(await rowText("diff-only-there")).includes("the file on disk")) throw new Error("the comparison does not name what it compared against");
  });

  // ---- Keystore navigator, locked key pairs and the Convert page ----
  const P12 = path.join(WORK, "nav.p12");
  const P12_PW = "navpass1";
  const clickTab = async (label) => {
    const el = await driver.wait(until.elementLocated(By.xpath(`//button[@role="tab"][contains(normalize-space(.), ${JSON.stringify(label)})]`)), 10000);
    await driver.executeScript("arguments[0].click()", el);
  };
  const clickButton = (text) => driver.executeScript(
    `const el = [...document.querySelectorAll("button")].find((b) => !b.disabled && b.innerText.replace(/\\s+/g, " ").trim().includes(${JSON.stringify(text)}));
     if (!el) throw new Error("no button: " + ${JSON.stringify(text)});
     el.click(); return true;`);
  const certPem = () => fs.readFileSync(path.join(WORK, "ui-cert.pem"), "utf8");

  await step("a key pair read from a file opens locked and needs its key password", async () => {
    await driver.actions().sendKeys("\uE00C").perform(); // close the compare dialog
    sh("keytool", ["-genkeypair", "-alias", "web", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=web.nav.test", "-storetype", "PKCS12", "-keystore", P12, "-storepass", P12_PW]);
    sh("keytool", ["-importcert", "-noprompt", "-alias", "anchor", "-file", path.join(WORK, "ui-cert.pem"), "-storetype", "PKCS12", "-keystore", P12, "-storepass", P12_PW]);
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(P12)});`);
    // Only one keystore is open here, so the navigator (and its own Open button) is not rendered yet.
    await click("header-open");
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
    // The inspector must show the key as usable: a stale, pre-unlock snapshot would still say "Private key locked".
    await driver.wait(async () => !(await driver.findElement(By.tagName("body")).getText()).includes("Private key locked"), 3000, "the inspector still says the private key is locked after unlocking").catch(async (err) => {
      throw new Error(`${err.message}: the inspector was opened from a snapshot taken before the key was unlocked`);
    });
    await driver.actions().sendKeys("\uE00C").perform();
  });

  await step("the Convert row toggles its submenu and Open is icon-only", async () => {
    const expanded = async () => (await driver.findElement(byTest("nav-convert"))).getAttribute("aria-expanded");
    if (await expanded() !== "false" || await exists('[data-testid="nav-convert-certificate"]')) throw new Error("conversions should start collapsed");
    await click("nav-convert");
    if (await expanded() !== "true" || !(await exists('[data-testid="nav-convert-certificate"]'))) {
      throw new Error("clicking Convert did not expand its submenu");
    }
    await click("nav-convert");
    if (await expanded() !== "false" || await exists('[data-testid="nav-convert-certificate"]')) throw new Error("clicking Convert did not collapse its submenu");
    await click("nav-convert");
    const open = await driver.findElement(byTest("header-open"));
    if (await open.getText() || !/^Open \((Ctrl\+|⌘)O\)$/.test(await open.getAttribute("aria-label"))) throw new Error("Open should be an accessible icon-only button");
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

  await step("the inspector opened from a workspace shows a key as unlocked once its own password is entered", async () => {
    // A JCEKS key with its own password, opened fresh so it is locked by the engine, not just by the session.
    const WS = path.join(WORK, "ws.jks");
    sh("keytool", ["-genkeypair", "-alias", "ws-key", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=ws.test", "-storetype", "JCEKS", "-keystore", WS, "-storepass", "wsstore1", "-keypass", "wskey-pw1"]);
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(WS)});`);
    await click("header-open");
    await driver.wait(until.elementLocated(byTest("open-password")), 15000);
    await setField("open-password", "wsstore1");
    await click("open-submit");
    await waitText("ws-key", 15000);

    await click("nav-workspaces");
    await click("workspace-new");
    await setField("workspace-name", "Locked review");
    await click("workspace-save");
    await click("workspace-assign");
    await driver.executeScript(`const el = [...document.querySelectorAll("button[aria-pressed]")].find((b) => [...b.querySelectorAll("span")].some((s) => s.textContent.trim() === "ws-key"));
       if (!el) throw new Error("no picker row for ws-key"); el.click(); return true;`);
    await clickButton("Done");

    const inspect = await driver.wait(until.elementLocated(By.css('[aria-label="Inspect"]')), 10000);
    await driver.executeScript("arguments[0].click()", inspect);
    await driver.wait(until.elementLocated(byTest("unlock-key-dialog")), 10000);
    await setField("unlock-key-password", "wskey-pw1");
    await click("unlock-key-submit");
    await driver.wait(until.elementLocated(byTest("entry-inspector")), 10000);
    // The inspector must reflect the unlock: a copy taken before it would still carry the locked alert.
    const text = await driver.findElement(By.tagName("body")).getText();
    if (text.includes("Private key locked")) throw new Error("the inspector still says the key is locked after the unlock");
    await driver.actions().sendKeys("\uE00C").perform();
  });

  // ---- Regressions from the code review: each of these failed before its fix ----
  const R = path.join(WORK, "review");
  fs.mkdirSync(R, { recursive: true });
  const REV_PW = "reviewpw1";
  const ESC = "\uE00C";
  const keys = (...k) => driver.actions().sendKeys(...k).perform();
  const present = async (id) => (await driver.findElements(byTest(id))).length > 0;
  const gone = (id, what) => driver.wait(async () => !(await present(id)), 10000, what ?? `${id} is still open`);
  const activeTestId = () => driver.executeScript("return document.activeElement?.getAttribute('data-testid') ?? document.activeElement?.getAttribute('role') ?? document.activeElement?.tagName");
  const aliases = () => driver.executeScript(`return [...document.querySelectorAll('[data-testid="entry-alias"]')].map((e) => e.textContent.trim())`);
  const keytoolPair = (file, alias, type = "PKCS12", extra = []) =>
    sh("keytool", ["-genkeypair", "-alias", alias, "-keyalg", "EC", "-groupname", "secp256r1", "-dname", `CN=${alias}.review.test`, "-storetype", type, "-keystore", file, "-storepass", REV_PW, ...extra]);
  const openKeystore = async (file, pw = REV_PW) => {
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(file)});`);
    await click("header-open");
    await driver.wait(until.elementLocated(byTest("open-password")), 15000);
    await setField("open-password", pw);
    await click("open-submit");
    await gone("open-password-dialog", `${path.basename(file)} did not open`);
  };
  const clickAlias = (alias) =>
    driver.executeScript(`const el = [...document.querySelectorAll('[data-testid="entry-alias"]')].find((e) => e.textContent.trim() === ${JSON.stringify(alias)});
       if (!el) throw new Error("no alias " + ${JSON.stringify(alias)}); el.click();`);

  await step("review: a workspace row asks for the key password before showing the key", async () => {
    const file = path.join(R, "ws-row.p12");
    keytoolPair(file, "row-key");
    await openKeystore(file);
    await click("nav-workspaces");
    await click("workspace-new");
    await setField("workspace-name", "Row review");
    await click("workspace-save");
    await click("workspace-assign");
    await driver.executeScript(`const el = [...document.querySelectorAll("button[aria-pressed]")].find((b) => [...b.querySelectorAll("span")].some((s) => s.textContent.trim() === "row-key"));
       if (!el) throw new Error("no picker row for row-key"); el.click();`);
    await clickButton("Done");
    // The row itself, not the eye icon: the row opened the inspector, and its private key, without the password.
    await driver.executeScript(`const row = [...document.querySelectorAll("tbody tr")].find((r) => r.innerText.includes("row-key")); row.click();`);
    await driver.wait(until.elementLocated(byTest("unlock-key-dialog")), 10000);
    if (await present("entry-inspector")) throw new Error("the inspector opened before the key password was entered");
    await keys(ESC);
    await gone("unlock-key-dialog");
    await sleep(200);
    if (await present("entry-inspector")) throw new Error("cancelling the key password still opened the inspector");
  });

  await step("review: Escape closes only the dialog on top", async () => {
    await click("nav-keystores");
    await click("ks-tab-ws-row.p12");
    await clickAlias("row-key");
    await driver.wait(until.elementLocated(byTest("unlock-key-password")), 10000);
    await setField("unlock-key-password", REV_PW);
    await click("unlock-key-submit");
    await driver.wait(until.elementLocated(byTest("entry-inspector")), 10000);
    await clickTab("Private key");
    await click("reveal-key");
    await driver.wait(until.elementLocated(byTest("confirm-ok")), 10000);
    await keys(ESC);
    await gone("confirm-ok", "the confirmation did not close on Escape");
    if (!(await present("entry-inspector"))) throw new Error("Escape on the confirmation also closed the inspector underneath");
    await keys(ESC);
    await gone("entry-inspector", "the inspector did not close on the next Escape");
  });

  await step("review: unlocking a key with its own password is not an unsaved change", async () => {
    const file = path.join(R, "own-pw.jks");
    keytoolPair(file, "own", "JKS", ["-keypass", "ownkeypw1"]);
    await openKeystore(file);
    await driver.wait(until.elementLocated(byTest("row-unlock-own")), 10000);
    await click("row-unlock-own");
    await setField("unlock-key-password", "ownkeypw1");
    await click("unlock-key-submit");
    await gone("unlock-key-dialog");
    await sleep(200);
    const state = await driver.executeScript(`return { title: document.title, badge: document.querySelector('[data-testid="keystore-detail"]').innerText.includes("Unsaved changes") }`);
    if (state.title.startsWith("\u2022") || state.badge) throw new Error(`unlocking marked own-pw.jks as changed: ${JSON.stringify(state)}`);
  });

  await step("review: undo does not close a keystore opened after the edit", async () => {
    await rowMenu("own", "menu-rename");
    await setField("rename-input", "own-renamed");
    await click("rename-submit");
    await driver.wait(async () => (await aliases()).includes("own-renamed"), 5000, "the rename did not apply");
    const undoIsLeftOfSearch = await driver.executeScript(`const undo = document.querySelector('[data-testid="undo"]');
      const search = document.querySelector('[data-testid="open-palette"]');
      return !!undo && undo.getBoundingClientRect().right <= search.getBoundingClientRect().left;`);
    if (!undoIsLeftOfSearch || await present("redo")) throw new Error("undo/redo visibility or position after rename is incorrect");
    const later = path.join(R, "opened-later.p12");
    keytoolPair(later, "later");
    await openKeystore(later);
    await click("undo");
    await sleep(300);
    if (!(await present("ks-tab-opened-later.p12"))) throw new Error("undo closed the keystore that was opened after the edit");
    await click("ks-tab-own-pw.jks");
    await driver.wait(async () => (await aliases()).includes("own"), 5000, "undo did not revert the rename");
    if (!(await present("redo"))) throw new Error("redo is not visible after undo");
    await click("redo");
    await driver.wait(async () => (await aliases()).includes("own-renamed"), 5000, "redo did not restore the rename");
    if (await present("redo")) throw new Error("redo remains visible when there is nothing to redo");
    await click("undo");
    await driver.wait(async () => (await aliases()).includes("own"), 5000, "undo did not revert the rename again");
  });

  await step("review: Save As can replace another existing keystore file", async () => {
    const target = path.join(R, "existing-target.p12");
    keytoolPair(target, "stale");
    fs.utimesSync(target, new Date(2001, 1, 1), new Date(2001, 1, 1));
    await click("ks-tab-opened-later.p12");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(target)});`);
    await click("ks-more");
    await click("ks-save-as");
    await setField("save-password", REV_PW);
    await setField("save-password-confirm", REV_PW);
    await click("save-choose-location");
    await gone("save-dialog", "Save As did not finish");
    if ((await driver.findElement(By.tagName("body")).getText()).includes("modified after it was opened")) throw new Error("Save As onto an existing file was refused as 'changed on disk'");
    const list = sh("keytool", ["-list", "-keystore", target, "-storetype", "PKCS12", "-storepass", REV_PW]);
    if (!list.includes("later") || list.includes("stale")) throw new Error(`the file was not replaced:\n${list}`);
  });

  await step("review: a keystore created as JKS is first saved as JKS", async () => {
    await click("header-new");
    await click("format-JKS");
    await setField("new-keystore-password", REV_PW);
    await setField("new-keystore-password-confirm", REV_PW);
    await click("new-keystore-create");
    await gone("new-keystore-dialog", "the new keystore was not created");
    await click("ks-save");
    const format = await (await driver.wait(until.elementLocated(byTest("save-format")), 10000)).getAttribute("value");
    if (format !== "JKS") throw new Error(`the first save of a new JKS keystore offered ${format}`);
    const out = path.join(R, "created.jks");
    await driver.executeScript(`window.__xksStub.save.push(${JSON.stringify(out)});`);
    await click("save-choose-location");
    await driver.wait(async () => fs.existsSync(out), 15000, "the JKS file was not written");
    const list = sh("keytool", ["-list", "-keystore", out, "-storetype", "JKS", "-storepass", REV_PW]);
    if (!/Keystore type: JKS/i.test(list)) throw new Error(`not a JKS file:\n${list}`);
  });

  await step("review: bulk Label labels every selected entry, and the selection follows the filter", async () => {
    await click("ks-tab-nav.p12");
    await click("select-all");
    await waitText("2 selected");
    await click("bulk-label");
    await setField("bulk-label-input", "audit-2026");
    await click("bulk-label-submit");
    await gone("bulk-label-dialog");
    const labelled = await driver.executeScript(`return [...document.querySelectorAll('select[aria-label="Filter by label"] option')].map((o) => o.value)`);
    if (!labelled.includes("audit-2026")) throw new Error(`the label was not applied (window.prompt does nothing in the webview): ${labelled}`);
    // Narrowing the list drops hidden entries from the selection, so a bulk Delete only hits what is shown.
    const search = await driver.findElement(By.css('input[type="search"][aria-label^="Search by alias"]'));
    await driver.executeScript(`const el = arguments[0]; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, "anchor"); el.dispatchEvent(new Event("input", { bubbles: true }));`, search);
    await waitText("1 selected");
    await driver.executeScript(`const el = arguments[0]; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, ""); el.dispatchEvent(new Event("input", { bubbles: true }));`, search);
    await click("select-all");
    await click("select-all");
    if ((await driver.findElement(By.tagName("body")).getText()).match(/\d selected/)) throw new Error("select-all did not toggle the selection off");
  });

  await step("review: a destructive confirmation defaults to Cancel, and Enter keeps the entry", async () => {
    await driver.executeScript(`document.querySelector('button[aria-label="Delete anchor"]').click()`);
    await driver.wait(until.elementLocated(byTest("confirm-cancel")), 10000);
    await sleep(100);
    if ((await activeTestId()) !== "confirm-cancel") throw new Error(`focus is on ${await activeTestId()}, not Cancel`);
    await keys("\uE007");
    await gone("confirm-cancel");
    if (!(await aliases()).includes("anchor")) throw new Error("Enter on the confirmation deleted the entry");
  });

  await step("review: row menus work from the keyboard and give focus back", async () => {
    await click("row-menu-anchor");
    await driver.wait(async () => (await activeTestId()) === "menuitem" || (await driver.executeScript("return document.activeElement?.getAttribute('role')")) === "menuitem", 5000, "focus did not move into the menu");
    const first = await driver.executeScript("return document.activeElement.innerText");
    await keys("\uE015");
    const second = await driver.executeScript("return document.activeElement.innerText");
    if (first === second) throw new Error("ArrowDown did not move through the menu");
    await keys(ESC);
    await driver.wait(async () => (await activeTestId()) === "row-menu-anchor", 5000, "Escape did not return focus to the menu button");
  });

  await step("review: a dialog returns focus to what opened it, and toasts never cover it", async () => {
    await click("ks-more");
    await click("ks-compare");
    await driver.wait(until.elementLocated(byTest("diff-dialog")), 10000);
    // Toasts sit bottom-right, where a dialog footer puts its buttons: they must stay below dialogs.
    const covered = await driver.executeScript(`
      const btn = [...document.querySelectorAll('[data-testid="diff-dialog"] button')].pop();
      const r = btn.getBoundingClientRect();
      const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
      const toasts = document.querySelector('[aria-live="polite"]');
      return { onTop: btn.contains(hit), toastZ: getComputedStyle(toasts).zIndex };`);
    if (!covered.onTop) throw new Error("something covers the dialog's footer button");
    if (Number(covered.toastZ) >= 50) throw new Error(`toasts (z-index ${covered.toastZ}) are above dialogs`);
    await keys(ESC);
    await gone("diff-dialog");
    await driver.wait(async () => (await activeTestId()) === "ks-more", 5000, `focus went to ${await activeTestId()}, not back to the menu button`);
  });

  await step("review: a cut secret key that cannot be pasted stays on the clipboard", async () => {
    const file = path.join(R, "secrets.p12");
    keytoolPair(file, "holder");
    await openKeystore(file);
    await click("ks-add-entry");
    await click("add-secret");
    await setField("sk-alias", "move-me");
    await click("secret-key-submit");
    await gone("secret-key-dialog");
    await rowMenu("move-me", "menu-cut");
    await click("ks-tab-own-pw.jks");
    await click("footer-paste");
    await waitText("stays on the clipboard");
    // It was already removed from secrets.p12, so emptying the clipboard here would lose it.
    if (!(await present("footer-paste"))) throw new Error("the clipboard was emptied although JKS could not take the key");
    await click("ks-tab-secrets.p12");
    await click("footer-paste");
    await driver.wait(async () => (await aliases()).includes("move-me"), 5000, "the secret key could not be pasted back");
  });

  await step("review: a dropped CSR opens in Examine once, not on every visit", async () => {
    // A CSR, not a certificate: certificates are listed on the Certificates page instead (below).
    const cert = path.join(R, "examine-once.csr");
    sh("openssl", ["req", "-new", "-key", path.join(WORK, "ui-key.pem"), "-subj", "/CN=examine-once.e2e.test", "-out", cert]);
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(cert)});`);
    await click("header-open");
    await driver.wait(until.elementLocated(byTest("decode-title")), 15000);
    await clickTab("TLS server");
    await click("nav-home");
    await click("nav-examine");
    await sleep(300);
    const selected = await driver.executeScript(`return [...document.querySelectorAll('[role="tab"][aria-selected="true"]')].map((t) => t.innerText.trim()).join("|")`);
    if (selected.includes("Decode")) throw new Error("returning to Examine replayed the old file in Decode");
  });

  await step("review: the audit raises a JKS keystore once, with a way to open it", async () => {
    await click("nav-scanner");
    await driver.wait(until.elementLocated(byTest("audit-open-jks")), 15000);
  });

  await step("review: a keystore path stays on one line, with a copy button", async () => {
    await click("nav-keystores");
    await click("ks-tab-nav.p12");
    const box = await driver.executeScript(`const el = document.querySelector('[data-testid="keystore-detail"] [data-testid="path-text"]'); return el && { h: el.getBoundingClientRect().height, copy: !!el.querySelector('button[aria-label="Copy path"]'), title: el.getAttribute("title") }`);
    if (!box) throw new Error("no path shown");
    if (box.h > 32) throw new Error(`the path wraps (${box.h}px tall)`);
    if (!box.copy || !box.title?.endsWith("nav.p12")) throw new Error(`path tooltip or copy missing: ${JSON.stringify(box)}`);
  });

  // ---- Certificates: opened certificate files are listed under Keystores, not decoded in Examine ----
  const C = path.join(WORK, "certs");
  fs.mkdirSync(C, { recursive: true });
  const ROOT_CN = "E2E Cert Root";
  const LEAF_CN = "leaf.certs.e2e.test";
  const c = (f) => path.join(C, f);
  sh("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", c("root.key"), "-out", c("root.pem"), "-days", "365", "-subj", `/CN=${ROOT_CN}`,
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  sh("openssl", ["req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", c("leaf.key"), "-out", c("leaf.csr"), "-subj", `/CN=${LEAF_CN}`]);
  fs.writeFileSync(c("leaf.ext"), `basicConstraints=CA:FALSE\nsubjectAltName=DNS:${LEAF_CN}\nextendedKeyUsage=serverAuth\n`);
  sh("openssl", ["x509", "-req", "-in", c("leaf.csr"), "-CA", c("root.pem"), "-CAkey", c("root.key"), "-CAcreateserial", "-out", c("leaf.pem"), "-days", "30", "-extfile", c("leaf.ext")]);
  fs.writeFileSync(c("chain.pem"), fs.readFileSync(c("leaf.pem"), "utf8") + fs.readFileSync(c("root.pem"), "utf8"));
  // A certificates-only PKCS#7 bundle holding a certificate not opened any other way, and a CMS signature.
  sh("openssl", ["crl2pkcs7", "-nocrl", "-certfile", path.join(WORK, "ui-cert.pem"), "-outform", "DER", "-out", c("bundle.p7b")]);
  fs.writeFileSync(c("msg.txt"), "signed by the e2e leaf\n");
  sh("openssl", ["cms", "-sign", "-in", c("msg.txt"), "-signer", c("leaf.pem"), "-inkey", c("leaf.key"), "-outform", "DER", "-out", c("msg.p7s"), "-nodetach", "-binary"]);

  const certAliases = () => driver.executeScript(`return [...document.querySelectorAll('[data-testid="certificates-page"] tbody [data-testid="entry-alias"]')].map((e) => e.textContent.trim())`);
  const countOf = async (alias) => (await certAliases()).filter((a) => a === alias).length;
  const lastToast = () => driver.executeScript(`const t = [...document.querySelectorAll('[data-testid^="toast-"]')].pop(); return t ? t.innerText : ""`);
  const openFile = async (file) => {
    await driver.executeScript(`window.__xksStub.open.push(${JSON.stringify(file)});`);
    await click("header-open");
  };
  const tableText = () => driver.executeScript(`const t = document.querySelector("tbody"); return t ? t.innerText : ""`);
  /** Sizes the window so the page itself is w×h: the frame of a headless window still takes some height. */
  const setViewport = async (w, h) => {
    await driver.manage().window().setRect({ width: w, height: h });
    const [iw, ih] = await driver.executeScript("return [window.innerWidth, window.innerHeight]");
    await driver.manage().window().setRect({ width: w + (w - iw), height: h + (h - ih) });
    await sleep(250);
  };
  const restoreWindow = async () => {
    await driver.manage().window().setRect({ width: 1400, height: 900 });
    await sleep(150);
  };
  /** With XKS_SCREENSHOTS set: the default window (1320×860) and the smallest one (1024×680). */
  const shotSizes = async (name) => {
    if (!process.env.XKS_SCREENSHOTS) return;
    // Toasts left by earlier steps would cover the page.
    await driver.executeScript(`document.querySelectorAll('[data-testid^="toast-"] button[aria-label="Dismiss"]').forEach((b) => b.click())`);
    for (const [w, h] of [[1320, 860], [1024, 680]]) {
      await setViewport(w, h);
      await shot(`${name}-${w}x${h}`);
    }
    await restoreWindow();
  };

  await step("certificates: Certificates sits right under Keystores in the sidebar", async () => {
    const order = await driver.executeScript(`return [...document.querySelectorAll('nav[aria-label="Primary"] [data-testid^="nav-"]')].map((b) => b.dataset.testid)`);
    const i = order.indexOf("nav-keystores");
    if (i < 0 || order[i + 1] !== "nav-certificates") throw new Error(`sidebar order: ${order.join(", ")}`);
    await click("nav-certificates");
    await driver.wait(until.elementLocated(byTest("cert-empty-open")), 10000);
    await shotSizes("20-certificates-empty");
  });

  await step("certificates: an opened certificate file is listed on Certificates, not decoded in Examine", async () => {
    await click("nav-home");
    await openFile(c("leaf.pem"));
    await driver.wait(until.elementLocated(byTest("certificates-page")), 15000);
    await driver.wait(async () => (await countOf(LEAF_CN)) === 1, 10000, "the certificate is not listed");
    const t = await lastToast();
    if (!t.includes("Opened leaf.pem: 1 certificate")) throw new Error(`toast: ${t}`);
    // Examine must not have picked the file up.
    await click("nav-examine");
    await sleep(300);
    if (await present("decode-title")) throw new Error("the certificate was also decoded in Examine");
    const selected = await driver.executeScript(`return [...document.querySelectorAll('[role="tab"][aria-selected="true"]')].map((t) => t.innerText.trim()).join("|")`);
    if (selected.includes("Decode")) throw new Error("Examine switched to Decode for an opened certificate");
  });

  await step("certificates: a chain file lists every certificate once, and opening it again adds nothing", async () => {
    await openFile(c("chain.pem"));
    await driver.wait(async () => (await countOf(ROOT_CN)) === 1, 10000, "the root of the chain is not listed");
    if ((await countOf(LEAF_CN)) !== 1) throw new Error("the leaf is listed twice");
    const t = await lastToast();
    if (!t.includes("1 already listed")) throw new Error(`toast: ${t}`);
    await openFile(c("chain.pem"));
    await driver.wait(async () => (await lastToast()).includes("already listed"), 10000, "no 'already listed' note");
    if ((await certAliases()).length !== 2) throw new Error(`listed: ${(await certAliases()).join(", ")}`);
  });

  await step("certificates: a PKCS#7 bundle is listed on Certificates, a CMS signature opens in Examine", async () => {
    await openFile(c("bundle.p7b"));
    await driver.wait(async () => (await countOf("headless.e2e.test")) === 1, 10000, "the bundle's certificate is not listed");
    await openFile(c("msg.p7s"));
    await driver.wait(until.elementLocated(byTest("decode-title")), 15000);
    const title = await (await driver.findElement(byTest("decode-title"))).getText();
    if (!title.includes("signed data")) throw new Error(`Examine shows: ${title}`);
    await click("nav-certificates");
    if ((await certAliases()).length !== 3) throw new Error(`a signature was listed as a certificate: ${(await certAliases()).join(", ")}`);
  });

  await step("certificates: the inspector shows details, the source file and no false 'anchor not open'", async () => {
    await click(`cert-inspect-${LEAF_CN}`);
    const dlg = await driver.wait(until.elementLocated(byTest("certificate-inspector")), 10000);
    const text = await dlg.getText();
    for (const want of [LEAF_CN, "leaf.pem", "SHA-256", `DNS:${LEAF_CN}`]) if (!text.includes(want)) throw new Error(`inspector lacks "${want}":\n${text}`);
    if (!text.includes(`issued by ${ROOT_CN}`)) throw new Error(`inspector does not name the issuer:\n${text}`);
    // The root is open on the same page, so the issuer is known.
    if (text.includes("Trust anchor not open")) throw new Error("the inspector says the trust anchor is not open while it is listed");
    await shotSizes("21-certificate-inspector");
    await keys(ESC);
    await gone("certificate-inspector");
    await shotSizes("22-certificates-list");
  });

  await step("certificates: at the smallest window (1024×680) the row actions are not cut off", async () => {
    await setViewport(1024, 680);
    try {
      const r = await driver.executeScript(`const t = document.querySelector('[data-testid="certificates-page"] table');
         const box = t.parentElement.getBoundingClientRect();
         const more = [...t.querySelectorAll('tbody [aria-label^="More actions"]')].map((b) => b.getBoundingClientRect().right);
         return { overflow: t.parentElement.scrollWidth - t.parentElement.clientWidth, right: Math.max(...more), edge: box.right }`);
      if (r.overflow > 0 || r.right > r.edge) throw new Error(`the table scrolls sideways by ${r.overflow}px; the row menu ends at ${r.right}, the table at ${r.edge}`);
      // About 720px: room for the type, lock and status icons.
      const names = await driver.executeScript(`return [...document.querySelectorAll('[data-testid="certificates-page"] thead th')].filter((th) => getComputedStyle(th).display !== "none").map((th) => th.textContent.trim())`);
      for (const want of ["Type", "Lock status", "Expires", "Status"]) if (!names.includes(want)) throw new Error(`the ${want} column is hidden at the smallest window: ${names.join(", ")}`);
    } finally {
      await restoreWindow();
    }
  });

  await step("certificates: a certificate is added to a new workspace and shows there", async () => {
    await click(`cert-workspaces-${LEAF_CN}`);
    const input = await driver.wait(until.elementLocated(By.css('input[placeholder="New workspace name"]')), 10000);
    await driver.executeScript(
      `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(arguments[0], "Cert review");
       arguments[0].dispatchEvent(new Event("input", { bubbles: true }));`, input);
    await clickButton("Create & add");
    await waitText("Included");
    await clickButton("Done");
    await click("nav-workspaces");
    await driver.wait(async () => (await tableText()).includes(LEAF_CN), 10000, "the certificate is not in the workspace");
    if (!(await tableText()).includes("Certificate · leaf.pem")) throw new Error(`row: ${await tableText()}`);
    // A certificate has no key: Inspect opens the certificate inspector, never the key password prompt.
    await driver.executeScript(`const row = [...document.querySelectorAll("tbody tr")].find((r) => r.innerText.includes(${JSON.stringify(LEAF_CN)})); row.click();`);
    await driver.wait(until.elementLocated(byTest("certificate-inspector")), 10000);
    if (await present("unlock-key-dialog")) throw new Error("a certificate asked for a key password");
    await keys(ESC);
    await gone("certificate-inspector");
  });

  await step("certificates: the workspace picker offers certificates next to keystore entries", async () => {
    await click("workspace-assign");
    await click(`picker-cert-${ROOT_CN}`);
    const pressed = await (await driver.findElement(byTest(`picker-cert-${ROOT_CN}`))).getAttribute("aria-pressed");
    if (pressed !== "true") throw new Error("the picker did not mark the certificate as included");
    await shotSizes("23-workspace-picker");
    await clickButton("Done");
    await driver.wait(async () => (await tableText()).includes(ROOT_CN), 10000, "the root is not in the workspace");
    await waitText("2 certificates");
    await shotSizes("24-workspace-with-certificates");
  });

  await step("certificates: add a listed certificate to an open keystore", async () => {
    await click("nav-certificates");
    await click(`cert-menu-${ROOT_CN}`);
    await click("cert-menu-add-nav.p12");
    await driver.wait(async () => (await lastToast()).includes("to nav.p12"), 10000, "no confirmation of the add");
    await click("nav-keystores");
    await click("ks-tab-nav.p12");
    await driver.wait(async () => (await aliases()).includes("e2e-cert-root"), 10000, "the certificate is not in nav.p12");
  });

  await step("certificates: removing one that is in a workspace asks first, and opening the file brings it back", async () => {
    await click("nav-certificates");
    await click(`cert-menu-${LEAF_CN}`);
    await click("cert-menu-remove");
    await driver.wait(until.elementLocated(byTest("confirm-ok")), 10000);
    const ask = await driver.executeScript(`return document.querySelector('[data-testid="confirm-ok"]').closest('[role="dialog"]').innerText`);
    if (!ask.includes("Cert review")) throw new Error(`the confirmation does not name the workspace:\n${ask}`);
    await click("confirm-ok");
    await driver.wait(async () => (await countOf(LEAF_CN)) === 0, 10000, "the certificate was not removed");
    if (!fs.existsSync(c("leaf.pem"))) throw new Error("removing from the list deleted the file");
    await click("nav-workspaces");
    await waitText("Certificate not open");
    await openFile(c("leaf.pem"));
    await driver.wait(async () => (await countOf(LEAF_CN)) === 1, 10000, "reopening did not list it again");
    await click("nav-workspaces");
    await driver.wait(async () => (await tableText()).includes(LEAF_CN), 10000, "the workspace did not find the reopened certificate");
  });

  await step("certificates: removing one that is in no workspace needs no confirmation, and Undo restores it", async () => {
    await click("nav-certificates");
    await click("cert-menu-headless.e2e.test");
    await click("cert-menu-remove");
    await driver.wait(async () => (await countOf("headless.e2e.test")) === 0, 10000, "not removed");
    if (await present("confirm-ok")) throw new Error("asked to confirm a removal that loses nothing");
    // The newest toast's Undo: the previous step's "Removed…" toast can still be on screen, and its
    // Undo correctly does nothing (that certificate was opened again since).
    await driver.executeScript(`const t = [...document.querySelectorAll('[data-testid^="toast-"]')].pop();
       if (!t || !t.innerText.includes("headless.e2e.test")) throw new Error("no toast for the removal: " + (t ? t.innerText : "none"));
       [...t.querySelectorAll("button")].find((b) => b.innerText.trim() === "Undo").click();`);
    await driver.wait(async () => (await countOf("headless.e2e.test")) === 1, 10000, "Undo did not bring it back");
  });

  await step("certificates: Examine can add a decoded certificate to Certificates", async () => {
    sh("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", c("dec.key"), "-out", c("dec.pem"), "-days", "10", "-subj", "/CN=decoded.e2e.test"]);
    await click("nav-examine");
    await clickTab("Decode");
    await setField("decode-input", fs.readFileSync(c("dec.pem"), "utf8"));
    await click("decode-run");
    await click("decode-keep-0");
    await driver.wait(async () => (await lastToast()).includes("Added 'decoded.e2e.test' to Certificates"), 10000, "no confirmation");
    await click("nav-certificates");
    await driver.wait(async () => (await countOf("decoded.e2e.test")) === 1, 10000, "not listed");
  });

  await step("certificates: Paste reports bad input inline and adds valid PEM", async () => {
    sh("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", c("paste.key"), "-out", c("paste.pem"), "-days", "10", "-subj", "/CN=pasted.e2e.test"]);
    await click("cert-paste");
    await setField("cert-paste-input", "not a certificate");
    await click("cert-paste-submit");
    const dlg = await driver.findElement(byTest("cert-paste-dialog"));
    await driver.wait(async () => (await dlg.getText()).toLowerCase().includes("no certificate"), 10000, "no inline error");
    await setField("cert-paste-input", fs.readFileSync(c("paste.pem"), "utf8"));
    await click("cert-paste-submit");
    await gone("cert-paste-dialog");
    await driver.wait(async () => (await countOf("pasted.e2e.test")) === 1, 10000, "not listed");
    // The list has no Source column; the inspector names where a certificate came from.
    await click("cert-inspect-pasted.e2e.test");
    const insp = await driver.wait(until.elementLocated(byTest("certificate-inspector")), 10000);
    if (!(await insp.getText()).includes("Pasted")) throw new Error("the source of a pasted certificate is not shown");
    await keys(ESC);
    await gone("certificate-inspector");
  });

  await step("certificates: a row opens from the keyboard, and focus returns to it", async () => {
    await click("nav-certificates");
    await driver.executeScript(`document.querySelector('[data-testid="certificates-page"] tbody tr').focus()`);
    await keys(Key.ENTER);
    await driver.wait(until.elementLocated(byTest("certificate-inspector")), 5000);
    await keys(ESC);
    await gone("certificate-inspector");
    const back = await driver.executeScript(`const a = document.activeElement; return a?.tagName === "TR" && !!a.closest('[data-testid="certificates-page"]')`);
    if (!back) throw new Error(`focus went to ${await activeTestId()} instead of the row`);
  });

  await step("certificates: Ctrl+0 opens Certificates", async () => {
    await click("nav-home");
    await driver.actions().keyDown(Key.CONTROL).sendKeys("0").keyUp(Key.CONTROL).perform();
    await driver.wait(until.elementLocated(byTest("certificates-page")), 5000);
  });

  // Both tables: type and lock as icons alone, then name, algorithm, expiry, status as an icon, actions.
  // Each header's name (what a screen reader says) and visible text, and each cell, per visible column.
  const TABLE_JS = `
    const t = document.querySelector(arguments[0] + " table");
    if (!t) return null;
    const visible = (el) => getComputedStyle(el).display !== "none";
    const shown = (el) => { const c = el.cloneNode(true); c.querySelectorAll(".sr-only").forEach((s) => s.remove()); return c.textContent.trim(); };
    const heads = [...t.querySelectorAll("thead th")].filter(visible);
    const names = heads.map((th) => th.textContent.trim());`;
  const headersOf = (scope) =>
    driver.executeScript(`${TABLE_JS}
      return heads.map((th) => ({ name: th.textContent.trim(), text: shown(th), icon: !!th.querySelector("[data-header] svg") }));`, scope);
  const cellsOf = (scope, alias) =>
    driver.executeScript(`${TABLE_JS}
      const tr = [...t.querySelectorAll("tbody tr")].find((r) => [...r.querySelectorAll('[data-testid="entry-alias"]')].some((a) => a.textContent.trim() === arguments[1]));
      if (!tr) return null;
      const out = {};
      [...tr.children].filter(visible).forEach((td, i) => {
        // Only what is drawn: the name cell keeps a hidden type tile for narrow tables.
        const seen = (css) => [...td.querySelectorAll(css)].find((el) => el.getClientRects().length > 0) ?? null;
        const img = seen('[role="img"]');
        const tile = seen("[data-entry-type]");
        out[names[i] || "pick"] = { text: shown(td), lock: seen("[data-lock]")?.dataset.lock ?? null, health: seen("[data-health]")?.dataset.health ?? null,
          type: tile?.dataset.entryType ?? null, kind: seen("[data-cert-kind]")?.dataset.certKind ?? null, tip: img?.getAttribute("aria-label") ?? tile?.getAttribute("title") ?? null };
      });
      return out;`, scope, alias);
  /** Gap between the bottom of the table's card and the top of the summary: negative when the summary is above. */
  const summaryGap = (scope, figure) =>
    driver.executeScript(`const t = document.querySelector(arguments[0] + " table");
       const label = [...document.querySelectorAll(arguments[0] + " div")].find((d) => d.children.length === 0 && d.textContent.trim() === arguments[1]);
       if (!t || !label) return null;
       const card = t.closest(".rounded-card") ?? t;
       return label.parentElement.parentElement.getBoundingClientRect().top - card.getBoundingClientRect().bottom;`, scope, figure);
  const expectHeaders = async (scope, want) => {
    const heads = await headersOf(scope);
    if (!heads) throw new Error("no table");
    const names = heads.map((h) => h.name);
    if (JSON.stringify(names) !== JSON.stringify(want)) throw new Error(`columns: ${JSON.stringify(names)}, want ${JSON.stringify(want)}`);
    for (const h of heads.filter((h) => h.name === "Type" || h.name === "Lock status"))
      if (h.text || !h.icon) throw new Error(`the ${h.name} header should be an icon alone, it shows "${h.text}"`);
  };
  const expectIconOnly = (cells, col, what) => {
    const c = cells[col];
    if (!c) throw new Error(`no ${col} cell for ${what}`);
    if (c.text) throw new Error(`the ${col} cell of ${what} shows text "${c.text}"; it should be an icon alone`);
    if (!c.tip) throw new Error(`the ${col} icon of ${what} has no name for screen readers`);
  };
  const COLS = path.join(WORK, "cols.p12");

  await step("tables: the keystore table is type and lock icons, alias, algorithm, expiry, status icon and actions", async () => {
    keytoolPair(COLS, "cols-key", "PKCS12", ["-validity", "365"]);
    sh("keytool", ["-importcert", "-noprompt", "-alias", "cols-anchor", "-file", path.join(WORK, "ui-cert.pem"), "-storetype", "PKCS12", "-keystore", COLS, "-storepass", REV_PW]);
    await openKeystore(COLS);
    await driver.wait(until.elementLocated(byTest("row-unlock-cols-key")), 10000);
    const ks = '[data-testid="keystore-detail"]';
    await expectHeaders(ks, ["", "Type", "Lock status", "Alias", "Algorithm", "Expires", "Status", "Actions"]);
    const key = await cellsOf(ks, "cols-key");
    const anchor = await cellsOf(ks, "cols-anchor");
    for (const col of ["Type", "Lock status", "Status"]) {
      expectIconOnly(key, col, "the key pair");
      expectIconOnly(anchor, col, "the certificate");
    }
    if (key.Type.type !== "KeyPair" || anchor.Type.type !== "TrustedCertificate") throw new Error(`type icons: ${key.Type.type}, ${anchor.Type.type}`);
    if (key["Lock status"].lock !== "locked") throw new Error(`the locked key pair shows lock "${key["Lock status"].lock}"`);
    if (anchor["Lock status"].lock !== "no-key") throw new Error(`the certificate shows lock "${anchor["Lock status"].lock}"`);
    if (key.Status.health !== "healthy" || key.Status.tip !== "Healthy") throw new Error(`status: ${JSON.stringify(key.Status)}`);
    if (key.Alias.type) throw new Error("the alias cell still draws the type icon next to the new Type column");
    if (!key.Alias.text.includes("cols-key")) throw new Error(`alias cell: ${key.Alias.text}`);
    await click("row-unlock-cols-key");
    await setField("unlock-key-password", REV_PW);
    await click("unlock-key-submit");
    await gone("unlock-key-dialog");
    await driver.wait(async () => (await cellsOf(ks, "cols-key"))["Lock status"].lock === "unlocked", 5000, "the lock icon did not change after unlocking");
  });

  await step("tables: the keystore summary sits below the entry table", async () => {
    const gap = await summaryGap('[data-testid="keystore-detail"]', "Median key age");
    if (gap === null) throw new Error("no keystore summary");
    if (gap < 0) throw new Error(`the summary is above the table (${Math.round(gap)}px)`);
    if (!(await exists('[role="group"][aria-label="Keystore summary"]'))) throw new Error("the summary is not named for screen readers");
    await shotSizes("23-keystore-table");
  });

  /** How far a table scrolls sideways, and whether the last row menu ends inside it. */
  const fitOf = (scope) =>
    driver.executeScript(`const t = document.querySelector(arguments[0] + " table");
       const box = t.parentElement.getBoundingClientRect();
       const more = [...t.querySelectorAll('tbody [aria-label^="More actions"]')].map((b) => b.getBoundingClientRect().right);
       return { overflow: t.parentElement.scrollWidth - t.parentElement.clientWidth, right: Math.max(...more), edge: box.right, width: Math.round(box.width) }`, scope);
  const expectFits = async (scope, required) => {
    const r = await fitOf(scope);
    if (r.overflow > 0 || r.right > r.edge) throw new Error(`the table (${r.width}px) scrolls sideways by ${r.overflow}px; the row menu ends at ${r.right}, the table at ${r.edge}`);
    const names = (await headersOf(scope)).map((h) => h.name);
    for (const want of required) if (!names.includes(want)) throw new Error(`the ${want} column is hidden in a ${r.width}px table: ${names.join(", ")}`);
    return r;
  };

  await step("tables: with the navigator open the keystore table fits, and a narrow one keeps type, lock and status", async () => {
    const ks = '[data-testid="keystore-detail"]';
    try {
      // The default window: every column the user asked for but Algorithm, which needs more room.
      await setViewport(1320, 860);
      await expectFits(ks, ["Type", "Lock status", "Alias", "Expires", "Status", "Actions"]);
      // The smallest window leaves the table about 430px: Type and Lock move into the alias cell.
      await setViewport(1024, 680);
      await expectFits(ks, ["Alias", "Status", "Actions"]);
      const key = await cellsOf(ks, "cols-key");
      if (key.Alias.type !== "KeyPair" || !/ — (un)?locked$/.test(key.Alias.tip ?? "")) throw new Error(`a narrow alias cell should show the type and lock: ${JSON.stringify(key.Alias)}`);
      expectIconOnly(key, "Status", "the key pair");
    } finally {
      await restoreWindow();
    }
  });

  await step("tables: the certificates table is type and lock icons, certificate, algorithm, expiry, status icon and actions", async () => {
    await click("nav-certificates");
    const page = '[data-testid="certificates-page"]';
    await driver.wait(async () => (await countOf(LEAF_CN)) === 1 && (await countOf(ROOT_CN)) === 1, 10000, "the e2e certificates are not listed");
    await expectHeaders(page, ["Type", "Lock status", "Certificate", "Algorithm", "Expires", "Status", "Actions"]);
    const leaf = await cellsOf(page, LEAF_CN);
    const root = await cellsOf(page, ROOT_CN);
    for (const col of ["Type", "Lock status", "Status"]) {
      expectIconOnly(leaf, col, "the leaf");
      expectIconOnly(root, col, "the root");
    }
    if (root.Type.kind !== "ca" || leaf.Type.kind !== "end-entity") throw new Error(`kind icons: root ${root.Type.kind}, leaf ${leaf.Type.kind}`);
    if (!root.Type.tip.startsWith("CA certificate")) throw new Error(`root type tooltip: ${root.Type.tip}`);
    if (leaf["Lock status"].lock !== "no-key" || root["Lock status"].lock !== "no-key") throw new Error("a certificate shows a key lock");
    // The leaf is valid for 30 days: inside the critical window.
    if (leaf.Status.health !== "critical" || leaf.Status.tip !== "Expires soon") throw new Error(`leaf status: ${JSON.stringify(leaf.Status)}`);
    if (root.Status.health !== "healthy") throw new Error(`root status: ${JSON.stringify(root.Status)}`);
    if (leaf.Certificate.type) throw new Error("the certificate cell still draws the type icon next to the new Type column");
  });

  await step("tables: the certificates summary sits below the table", async () => {
    const gap = await summaryGap('[data-testid="certificates-page"]', "Expiring soon");
    if (gap === null) throw new Error("no certificates summary");
    if (gap < 0) throw new Error(`the summary is above the table (${Math.round(gap)}px)`);
    if (!(await exists('[role="group"][aria-label="Certificates summary"]'))) throw new Error("the summary is not named for screen readers");
    await shotSizes("24-certificates-table");
  });

  await step("sidebar: the logo follows the applied theme", async () => {
    const logos = await driver.executeScript(`const root = document.documentElement;
      const previous = root.dataset.theme;
      const visibleLogo = (theme) => {
        root.dataset.theme = theme;
        return [...document.querySelectorAll('aside button[aria-label="Keystore Studio dashboard"] img')]
          .filter((img) => getComputedStyle(img).display !== "none")
          .map((img) => img.getAttribute("src"));
      };
      const light = visibleLogo("light"), dark = visibleLogo("dark");
      if (previous === undefined) delete root.dataset.theme;
      else root.dataset.theme = previous;
      return { light, dark };`);
    if (JSON.stringify(logos.light) !== JSON.stringify(["/icon.png"]) || JSON.stringify(logos.dark) !== JSON.stringify(["/icon-l.png"])) {
      throw new Error(`incorrect sidebar logos: ${JSON.stringify(logos)}`);
    }
  });

  await step("sidebar: collapsed, it expands from the bottom of the navigation", async () => {
    const asideWidth = () => driver.executeScript(`return Math.round(document.querySelector("aside").getBoundingClientRect().width)`);
    await driver.findElement(By.css('aside button[aria-label="Collapse sidebar"]')).click();
    await driver.wait(async () => (await asideWidth()) === 64, 5000, "the sidebar did not collapse");
    const r = await driver.executeScript(`const aside = document.querySelector("aside");
       const b = aside.querySelector('[aria-label="Expand sidebar"]');
       const search = document.querySelector('[data-testid="open-palette"]').getBoundingClientRect();
       const terminal = document.querySelector('[data-testid="header-terminal"]').getBoundingClientRect();
       return { chevron: !!b?.querySelector('svg path[d="m9 18 6-6-6-6"]'),
         bottom: b ? aside.getBoundingClientRect().bottom - b.getBoundingClientRect().bottom : null,
         gap: terminal.left - search.right };`);
    if (!r.chevron) throw new Error("the collapsed navigation has no expand chevron");
    if (r.bottom < 0 || r.bottom > 24) throw new Error(`the chevron is not at the bottom of the navigation (${r.bottom}px)`);
    if (r.gap < 0 || r.gap > 12) throw new Error(`the terminal is not beside search (${r.gap}px gap)`);
    await shotSizes("25-sidebar-collapsed");
    await click("sidebar-expand");
    await driver.wait(async () => (await asideWidth()) === 240, 5000, "the sidebar did not expand");
    if (await present("sidebar-expand")) throw new Error("the expand chevron stays visible while the sidebar is expanded");
  });

  await step("settings: the panel fills the available content width", async () => {
    try {
      await click("nav-settings");
      for (const width of [1024, 1600]) {
        await setViewport(width, 900);
        const gap = await driver.executeScript(`const panel = document.querySelector('[role="tabpanel"]');
          return panel.parentElement.getBoundingClientRect().right - panel.getBoundingClientRect().right;`);
        if (Math.abs(gap) > 1) throw new Error(`settings panel has a ${gap}px right gap at ${width}px`);
      }
    } finally {
      await restoreWindow();
    }
  });

  await step("details: the certificate table has a Subject CN row under Subject and an Issuer CN row under Issuer", async () => {
    // The Overview table's rows, label and value, in order.
    const rows = (id) =>
      driver.executeScript(`return [...document.querySelectorAll('[data-testid="${id}"] table tr')].map((tr) => ({
         label: tr.querySelector("th")?.innerText.trim(), value: tr.querySelector("td")?.innerText.trim(),
         copy: tr.querySelector("td button")?.getAttribute("aria-label") ?? null }))`);
    const expect = async (id, subjectCn, issuerCn) => {
      await driver.wait(until.elementLocated(byTest(id)), 10000);
      const r = await rows(id);
      const labels = r.map((x) => x.label);
      const at = labels.indexOf("Subject");
      if (JSON.stringify(labels.slice(at, at + 4)) !== JSON.stringify(["Subject", "Subject CN", "Issuer", "Issuer CN"])) throw new Error(`rows in ${id}: ${labels.join(", ")}`);
      const row = (l) => r.find((x) => x.label === l);
      if (row("Subject CN").value !== subjectCn) throw new Error(`Subject CN in ${id}: ${row("Subject CN").value}, want ${subjectCn}`);
      if (row("Issuer CN").value !== issuerCn) throw new Error(`Issuer CN in ${id}: ${row("Issuer CN").value}, want ${issuerCn}`);
      if (row("Subject CN").copy !== "Copy Subject CN" || row("Issuer CN").copy !== "Copy Issuer CN") throw new Error(`the CN rows have no copy buttons in ${id}`);
    };
    // A leaf issued by a CA: two different CNs.
    await click("nav-certificates");
    await click(`cert-inspect-${LEAF_CN}`);
    await expect("certificate-inspector", LEAF_CN, ROOT_CN);
    await shotSizes("33-certificate-cn-rows");
    await keys(ESC);
    await gone("certificate-inspector");
    // A keystore entry whose subject has other parts before the CN (O=Keystore Studio UI, CN=headless.e2e.test).
    await click("nav-keystores");
    await click("ks-tab-cols.p12");
    await driver.wait(async () => (await aliases()).includes("cols-anchor"), 10000, "cols.p12 is not shown");
    await clickAlias("cols-anchor");
    await expect("entry-inspector", "headless.e2e.test", "headless.e2e.test");
    await shotSizes("34-entry-cn-rows");
    await keys(ESC);
    await gone("entry-inspector");
  });

  // A listening port and a closed one on this machine: the connection test needs no internet.
  const listening = net.createServer((sock) => sock.end());
  await new Promise((r) => listening.listen(0, "127.0.0.1", r));
  const OPEN_PORT = listening.address().port;
  const CLOSED_PORT = await new Promise((r) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => r(p));
    });
  });

  await step("connection: Examine tells an open port, a closed port and an unknown host apart", async () => {
    await click("nav-examine");
    const tab = await driver.executeScript(`const t = [...document.querySelectorAll('[role="tab"]')].find((t) => t.innerText.trim() === "Connection"); t?.click(); return !!t;`);
    if (!tab) throw new Error("Examine has no Connection mode");
    const result = async (want) => {
      await driver.wait(async () => {
        const els = await driver.findElements(byTest("conn-result"));
        return els.length > 0 && (await els[0].getAttribute(want.attr)) === want.value;
      }, 15000, `no ${want.attr}=${want.value} result`);
      return (await driver.findElement(byTest("conn-result"))).getText();
    };
    await setField("conn-host", "127.0.0.1");
    await setField("conn-port", String(OPEN_PORT));
    await click("conn-run");
    let text = await result({ attr: "data-succeeded", value: "true" });
    for (const want of [`127.0.0.1:${OPEN_PORT} is reachable`, "Source address", "Interface", "Name resolution"]) if (!text.includes(want)) throw new Error(`the result lacks "${want}":\n${text}`);
    if (!/\blo\d*\b/.test(text)) throw new Error(`the loopback interface is not named:\n${text}`);
    await shotSizes("30-connection-reachable");
    // Refused: the host answered, nothing listens.
    await setField("conn-port", String(CLOSED_PORT));
    await click("conn-run");
    text = await result({ attr: "data-failure", value: "refused" });
    if (!text.includes(`Cannot reach 127.0.0.1:${CLOSED_PORT}`) || !text.includes("nothing accepts connections")) throw new Error(`refused result:\n${text}`);
    await shotSizes("31-connection-refused");
    // A name that never resolves.
    await setField("conn-host", "no-such-host.invalid");
    await setField("conn-port", "443");
    await click("conn-run");
    text = await result({ attr: "data-failure", value: "name-resolution" });
    if (!text.includes("Cannot resolve no-such-host.invalid")) throw new Error(`unresolved result:\n${text}`);
    // From a reachable port, Inspect TLS opens the TLS tool on the same host and port.
    await setField("conn-host", "127.0.0.1");
    await setField("conn-port", String(OPEN_PORT));
    await click("conn-run");
    await result({ attr: "data-succeeded", value: "true" });
    await click("conn-inspect-tls");
    await driver.wait(until.elementLocated(byTest("tls-host")), 5000);
    const [h, p] = await driver.executeScript(`return [document.querySelector('[data-testid="tls-host"]').value, document.querySelector('[data-testid="tls-port"]').value]`);
    if (h !== "127.0.0.1" || p !== String(OPEN_PORT)) throw new Error(`the TLS tool got ${h}:${p}`);
  });

  await step("connection: Test-NetConnection runs in the built-in terminal, in PowerShell's format", async () => {
    const termText = () => driver.executeScript(`return document.querySelector('[data-testid="terminal"]')?.innerText ?? ""`);
    const type = async (command, until_) => {
      const input = await driver.findElement(By.css('[aria-label="Terminal input"]'));
      await driver.wait(async () => await input.isEnabled(), 15000, "the terminal is still busy");
      await input.sendKeys(command, Key.ENTER);
      await driver.wait(async () => until_(await termText()), 15000, `no output for: ${command}`).catch(async (err) => {
        throw new Error(`${err.message}\n${await termText()}`);
      });
    };
    if (!(await present("terminal"))) await driver.findElement(By.css('header [aria-label^="Terminal"]')).click();
    await driver.wait(until.elementLocated(byTest("terminal")), 5000);
    await type(`Test-NetConnection -ComputerName 127.0.0.1 -Port ${OPEN_PORT} -DetailedInformation`, (t) => t.includes("TcpTestSucceeded"));
    let t = await termText();
    for (const want of ["ComputerName          : 127.0.0.1", `RemotePort            : ${OPEN_PORT}`, "NameResolutionResults : 127.0.0.1", "SourceAddress         : 127.0.0.1", "TcpTestSucceeded      : True", "Built into Keystore Studio"])
      if (!t.includes(want)) throw new Error(`the output lacks "${want}":\n${t}`);
    if (t.includes("command not found")) throw new Error(`the shell ran it:\n${t}`);
    await type(`tnc 127.0.0.1 -Port ${CLOSED_PORT}`, (t) => t.includes(`(127.0.0.1 : ${CLOSED_PORT}) failed`));
    t = await termText();
    if (!t.includes("TcpTestSucceeded : False")) throw new Error(`a closed port is not reported as failed:\n${t}`);
    await type(`tnc 127.0.0.1 -Port ${OPEN_PORT} -InformationLevel Quiet`, (t) => /\nTrue\n/.test(`${t}\n`));
    await type("tnc example.com", (t) => t.includes("Add -Port"));
    await shotSizes("32-terminal-test-netconnection");
    await driver.findElement(By.css('[aria-label="Close terminal"]')).click();
    listening.close();
  });

  await step("certificates: the list and workspace membership survive a restart", async () => {
    await click("nav-certificates");
    await driver.wait(async () => (await certAliases()).length > 0, 10000, "no certificates listed before the restart");
    const before = (await certAliases()).sort();
    await sleep(900); // the state is saved 400 ms after the last change
    await driver.navigate().refresh();
    await waitText("Keystore Studio", 20000);
    await click("nav-certificates");
    await driver.wait(async () => JSON.stringify((await certAliases()).sort()) === JSON.stringify(before), 15000, "the certificates did not come back");
    await click("nav-workspaces");
    await driver.executeScript(`const el = [...document.querySelectorAll('[role="tab"]')].find((t) => t.innerText.includes("Cert review")); if (!el) throw new Error("no Cert review workspace"); el.click();`);
    await driver.wait(async () => (await tableText()).includes(LEAF_CN) && (await tableText()).includes(ROOT_CN), 10000, "the workspace lost its certificates");
    if ((await tableText()).includes("Certificate not open")) throw new Error("a restored certificate shows as not open");
  });

  // After the restart the keystores come back locked, so Home is the welcome page, with recent files.
  await step("dashboard: Get started titles sit beside their icons; Click to open is on the right above a half-height Recent files", async () => {
    await click("nav-home");
    await driver.wait(until.elementLocated(byTest("welcome-open")), 10000);
    await shotSizes("26-dashboard-welcome");
    try {
      for (const [w, h] of [[1320, 860], [1024, 680]]) {
        await setViewport(w, h);
        const r = await driver.executeScript(`
          const box = (el) => el.getBoundingClientRect();
          const gs = document.querySelector('[data-testid="get-started"]') ?? [...document.querySelectorAll("h3")].find((x) => x.textContent.trim() === "Get started")?.closest(".rounded-card");
          const recent = document.querySelector('[data-testid="recent-files"]') ?? [...document.querySelectorAll("h3")].find((x) => x.textContent.trim() === "Recent files")?.closest(".rounded-card");
          const drop = document.querySelector('[data-testid="dropzone"]');
          const tiles = [...document.querySelectorAll('button[data-testid^="welcome-"]')].map((b) => {
            const icon = box(b.querySelector("svg"));
            const title = [...b.querySelectorAll("*")].find((el) => el.children.length === 0 && el.textContent.trim() && !el.closest("svg"));
            const t = box(title);
            return { name: title.textContent.trim(), beside: t.left > icon.right && Math.abs((t.top + t.bottom) / 2 - (icon.top + icon.bottom) / 2) < 4 };
          });
          const g = box(gs), d = box(drop), rc = box(recent);
          const list = recent.querySelector("ul")?.parentElement;
          return { tiles, dropH: Math.round(d.height), dropInGetStarted: gs.contains(drop), dropRight: d.left >= g.right, dropAbove: d.bottom <= rc.top, recentH: Math.round(rc.height), gsH: Math.round(g.height),
                   bottomGap: Math.round(rc.bottom - g.bottom), scrolls: list ? getComputedStyle(list).overflowY : null, files: recent.querySelectorAll("li").length }`);
        const at = `${w}×${h}`;
        const stacked = r.tiles.filter((t) => !t.beside).map((t) => t.name);
        if (stacked.length) throw new Error(`at ${at} these titles are not beside their icon: ${stacked.join(", ")}`);
        if (r.dropInGetStarted || !r.dropRight) throw new Error(`at ${at} Click to open is not in the right column`);
        if (!r.dropAbove) throw new Error(`at ${at} Click to open is not above Recent files`);
        // Recent files used to be as tall as Get started with the drop zone inside it (16px apart); now about half of that.
        const before = r.dropInGetStarted ? r.gsH : r.gsH + r.dropH + 16;
        if (r.recentH > before * 0.55) throw new Error(`at ${at} Recent files is ${r.recentH}px, about ${before}px before: not about half`);
        if (Math.abs(r.bottomGap) > 1) throw new Error(`at ${at} the right column does not end with Get started (${r.bottomGap}px)`);
        if (r.files < 2) throw new Error(`at ${at} expected recent files after this run, saw ${r.files}`);
        if (r.scrolls !== "auto") throw new Error(`at ${at} the recent files list cannot scroll (${r.scrolls})`);
      }
    } finally {
      await restoreWindow();
    }
  });

  await step("dashboard: a terminal section with two commands side by side spans the page under Get started and Recent files; no locked-keystores notice", async () => {
    await click("nav-home");
    await driver.wait(until.elementLocated(byTest("welcome-open")), 10000);
    await shotSizes("27-dashboard-terminal");
    const r = await driver.executeScript(`
      const box = (el) => el.getBoundingClientRect();
      const card = (title) => [...document.querySelectorAll("h3")].find((h) => h.textContent.trim() === title)?.closest(".rounded-card");
      const term = card("Terminal"), gs = card("Get started"), rc = card("Recent files");
      if (!term) return null;
      const t = box(term), g = box(gs), c = box(rc);
      const runs = [...term.querySelectorAll("button")].filter((b) => b.textContent.trim() === "Run").map((b) => box(b.closest("li")));
      return { below: t.top >= Math.max(g.bottom, c.bottom), left: Math.round(t.left - g.left), right: Math.round(t.right - c.right), run: runs.length,
               sideBySide: runs.length === 2 && Math.abs(runs[0].top - runs[1].top) < 1 && runs[1].left >= runs[0].right - 1 };`);
    if (!r) throw new Error("the welcome page has no Terminal section");
    if (!r.below) throw new Error("the Terminal section is not below Get started and Recent files");
    if (Math.abs(r.left) > 1 || Math.abs(r.right) > 1) throw new Error(`the Terminal section does not span the page (${r.left}px, ${r.right}px from the edges)`);
    if (r.run !== 2) throw new Error(`the Terminal section lists ${r.run} commands; it should list two`);
    if (!r.sideBySide) throw new Error("the two Terminal commands are not side by side, one per column");
    // The locked-keystores notice was removed from the dashboard.
    if (await present("sealed-banner")) throw new Error("the locked-keystores notice is back on the dashboard");
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
  if (results.some((r) => !r.ok)) failed = true;
  log(`${passed}/${results.length} steps passed. Work dir: ${WORK}`);
  process.exit(failed ? 1 : 0);
}
