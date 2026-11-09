// End-to-end test of the real xkeystore desktop app (Rust engine + UI) via tauri-driver.
//
//   pnpm tauri build --debug --no-bundle
//   xvfb-run -a node e2e/app.e2e.mjs        (Linux; needs tauri-driver and WebKitWebDriver)
//
// Native file dialogs are the only thing scripted: with XKEYSTORE_E2E=1 the app takes dialog
// answers from window.__xksStub (paths in a temporary directory). Everything else is the real
// application, and the files it writes are verified with keytool and openssl.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Builder, By, Capabilities, Key, until } from "selenium-webdriver";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APP = process.env.XKS_APP ?? path.join(ROOT, "src-tauri/target/debug/xkeystore");
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "xks-e2e-"));
const DATA = path.join(WORK, "data");
const SHOTS = process.env.XKS_SHOTS ?? path.join(WORK, "shots");
fs.mkdirSync(DATA, { recursive: true });
fs.mkdirSync(SHOTS, { recursive: true });

const STORE_PW = "storepass1";
const MASTER = "e2e-master-key";
const P12 = path.join(WORK, "e2e.p12");
const results = [];
let driver;
let tauriDriver;

const log = (...a) => console.log("[e2e]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const env = { ...process.env, JAVA_TOOL_OPTIONS: "" };
/** Runs a tool and returns stdout + stderr (OpenSSL reports verification results on stderr). */
const sh = (cmd, args) => {
  const r = spawnSync(cmd, args, { env, encoding: "utf8" });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.stdout}${r.stderr}`);
  return `${r.stdout}${r.stderr}`;
};

const portOpen = (port) =>
  new Promise((res) => {
    const s = net.connect(port, "127.0.0.1", () => (s.end(), res(true)));
    s.on("error", () => res(false));
  });

async function startDriver() {
  if (await portOpen(4444)) throw new Error("port 4444 is already in use (a stale tauri-driver?); stop it and retry");
  tauriDriver = spawn(process.env.TAURI_DRIVER ?? path.join(os.homedir(), ".cargo/bin/tauri-driver"), ["--port", "4444", "--native-port", "4445"], {
    env: { ...process.env, XKEYSTORE_DATA_DIR: DATA, XKEYSTORE_E2E: "1" },
    stdio: ["ignore", "inherit", "inherit"],
  });
  for (let i = 0; i < 50; i++) {
    if (await portOpen(4444)) return;
    await sleep(200);
  }
  throw new Error("tauri-driver did not start");
}

async function launch() {
  const caps = new Capabilities();
  caps.set("tauri:options", { application: APP });
  caps.setBrowserName("wry");
  driver = await new Builder().withCapabilities(caps).usingServer("http://127.0.0.1:4444/").build();
  await driver.manage().setTimeouts({ implicit: 0 });
  await waitText("xkeystore", 30000);
  await installDialogStub();
}

async function quit() {
  if (driver) await driver.quit().catch(() => {});
  driver = undefined;
}

async function installDialogStub() {
  // Answers for native file dialogs (honoured only because the app runs with XKEYSTORE_E2E=1).
  await driver.executeScript("window.__xksStub = window.__xksStub || { open: [], save: [] }");
}
const queueOpen = (p) => driver.executeScript("window.__xksStub.open.push(arguments[0])", p);
const queueSave = (p) => driver.executeScript("window.__xksStub.save.push(arguments[0])", p);

const tid = (id) => By.css(`[data-testid="${id}"]`);
const xpText = (text, tag = "*") => By.xpath(`//${tag}[contains(normalize-space(.), ${JSON.stringify(text)})]`);
async function find(locator, timeout = 15000) {
  const el = await driver.wait(until.elementLocated(locator), timeout, `not found: ${locator}`);
  await driver.wait(until.elementIsVisible(el), timeout, `not visible: ${locator}`);
  return el;
}
async function click(locator, timeout) {
  const el = await find(locator, timeout);
  await driver.executeScript("arguments[0].scrollIntoView({block:'center'})", el);
  await el.click();
  return el;
}
async function clickButton(text, timeout) {
  return click(By.xpath(`//button[not(@disabled)][contains(normalize-space(.), ${JSON.stringify(text)})]`), timeout);
}
async function type(locator, text) {
  const el = await find(locator);
  await el.clear();
  await el.sendKeys(Key.chord(Key.CONTROL, "a"), Key.BACK_SPACE);
  await el.sendKeys(text);
  return el;
}
async function waitText(text, timeout = 20000) {
  await driver.wait(async () => String(await driver.executeScript("return document.body.innerText")).includes(text), timeout, `text not shown: ${text}`);
}
async function waitGone(locator, timeout = 20000) {
  await driver.wait(async () => (await driver.findElements(locator)).length === 0, timeout, `still present: ${locator}`);
}
async function toast(timeout = 30000) {
  const el = await find(By.css('[data-testid^="toast-"]'), timeout);
  const text = await el.getText();
  const kind = await el.getAttribute("data-testid");
  // dismiss all toasts so the next assertion sees fresh ones
  await driver.executeScript(`document.querySelectorAll('[aria-label="Dismiss"]').forEach(b => b.click())`);
  if (kind === "toast-danger") throw new Error(`error toast: ${text}`);
  return text;
}
async function shot(name) {
  const png = await driver.takeScreenshot();
  fs.writeFileSync(path.join(SHOTS, `${name}.png`), png, "base64");
}
async function nav(id) {
  await click(tid(`nav-${id}`));
  await sleep(150);
}
async function step(name, fn) {
  const t = Date.now();
  try {
    await fn();
    results.push({ name, ok: true, ms: Date.now() - t });
    log(`PASS ${name} (${Date.now() - t} ms)`);
  } catch (err) {
    results.push({ name, ok: false, err: String(err?.message ?? err) });
    log(`FAIL ${name}: ${err?.name ?? ""} ${err?.message ?? err}`);
    if (process.env.XKS_DEBUG) console.error(err?.stack);
    if (driver) await shot(`FAIL-${name.replace(/\W+/g, "_")}`).catch(() => {});
    throw err;
  }
}
async function openRowMenu(alias) {
  await click(tid(`row-menu-${alias}`));
}

async function run() {
  await startDriver();
  await launch();

  await step("first launch shows the welcome screen", async () => {
    await waitText("Welcome to xkeystore");
    await waitText("Recent files");
    await shot("01-welcome");
  });

  await step("vault setup", async () => {
    await nav("vault");
    await type(tid("vault-key"), MASTER);
    await type(tid("vault-key-confirm"), MASTER);
    await click(tid("vault-submit"));
    await waitText("Remembered passwords");
    await shot("02-vault");
  });

  await step("create a PKCS#12 keystore with an initial key pair", async () => {
    await click(tid("header-new"));
    await find(tid("new-keystore-dialog"));
    await type(tid("new-keystore-name"), "e2e.p12");
    await type(tid("new-keystore-password"), STORE_PW);
    await type(tid("new-keystore-password-confirm"), STORE_PW);
    await type(tid("new-keystore-alias"), "web");
    await click(tid("new-keystore-create"));
    const t = await toast();
    if (!t.includes("Created e2e.p12")) throw new Error(t);
    await waitText("Not saved yet");
    await find(xpText("web", "span"));
    await shot("03-new-keystore");
  });

  await step("save keystore to disk (first save asks for a location)", async () => {
    await queueSave(P12);
    await click(tid("ks-save"));
    await find(tid("save-dialog"));
    await click(tid("save-choose-location"));
    const t = await toast();
    if (!t.includes("Saved e2e.p12")) throw new Error(t);
    if (!fs.existsSync(P12)) throw new Error("file not written");
    const listing = sh("keytool", ["-list", "-keystore", P12, "-storepass", STORE_PW]);
    if (!listing.includes("web, ") || !listing.includes("PrivateKeyEntry")) throw new Error(listing);
  });

  await step("generate a CA and a CA-signed key pair", async () => {
    await click(tid("ks-add-entry"));
    await click(tid("add-ca"));
    await find(tid("generate-keypair-dialog"));
    await type(tid("kp-alias"), "e2e-ca");
    await type(tid("kp-cn"), "E2E Root CA");
    await click(tid("generate-keypair-submit"));
    await toast();
    await click(tid("ks-add-entry"));
    await click(tid("add-keypair"));
    await type(tid("kp-alias"), "api");
    await type(tid("kp-cn"), "api.e2e.test");
    await type(tid("kp-sans"), "api.e2e.test, 127.0.0.1");
    const signer = await find(tid("kp-signer"));
    const options = await signer.findElements(By.css("option"));
    for (const o of options) if ((await o.getText()).startsWith("e2e-ca")) await o.click();
    await click(tid("generate-keypair-submit"));
    const t = await toast();
    if (!t.includes("signed by e2e-ca")) throw new Error(t);
    await shot("04-entries");
  });

  await step("generate an AES secret key", async () => {
    await click(tid("ks-add-entry"));
    await click(tid("add-secret"));
    await type(tid("sk-alias"), "aes-key");
    await click(tid("secret-key-submit"));
    await toast();
  });

  await step("inspect the CA-signed entry", async () => {
    await click(xpText("api", "span"));
    await find(tid("entry-inspector"));
    await waitText("Chain (2)");
    await waitText("DNS:api.e2e.test, IP:127.0.0.1");
    await shot("05-inspector");
    await driver.actions().sendKeys(Key.ESCAPE).perform();
    await waitGone(tid("entry-inspector"));
  });

  await step("export certificate and chain, verified by openssl", async () => {
    const ca = path.join(WORK, "ca.pem");
    const chain = path.join(WORK, "api-chain.pem");
    await openRowMenu("e2e-ca");
    await click(tid("menu-export"));
    await queueSave(ca);
    await click(tid("export-run"));
    await toast();
    await clickButton("Close");
    await openRowMenu("api");
    await click(tid("menu-export"));
    const select = await find(tid("export-format"));
    for (const o of await select.findElements(By.css("option"))) if ((await o.getAttribute("value")) === "chain_pem") await o.click();
    await queueSave(chain);
    await click(tid("export-run"));
    await toast();
    await clickButton("Close");
    const out = sh("openssl", ["verify", "-CAfile", ca, "-verify_hostname", "api.e2e.test", chain]);
    if (!out.includes("OK")) throw new Error(out);
  });

  await step("CSR → CA signs it → installed as CA reply", async () => {
    const csr = path.join(WORK, "web.csr");
    await openRowMenu("web");
    await click(tid("menu-csr"));
    await click(tid("csr-generate"));
    await find(tid("csr-output"));
    await queueSave(csr);
    await click(tid("csr-save"));
    await toast();
    await clickButton("Close");
    const v = sh("openssl", ["req", "-in", csr, "-noout", "-verify"]) ;
    if (!/verify ok/i.test(v)) throw new Error(v);

    await nav("ca_signing");
    await queueOpen(csr);
    await clickButton("Choose file…");
    await click(tid("sign-csr-submit"));
    await toast();
    await click(tid("install-issued"));
    const t = await toast();
    if (!t.includes("Installed the certificate into 'web'")) throw new Error(t);
    await shot("06-ca-signing");
  });

  await step("save in place and verify with keytool", async () => {
    await nav("keystores");
    await driver.actions().keyDown(Key.CONTROL).sendKeys("s").keyUp(Key.CONTROL).perform();
    const t = await toast();
    if (!t.includes("Saved e2e.p12")) throw new Error(t);
    const listing = sh("keytool", ["-list", "-v", "-keystore", P12, "-storepass", STORE_PW]);
    for (const alias of ["web", "api", "e2e-ca", "aes-key"]) if (!listing.includes(`Alias name: ${alias}`)) throw new Error(`missing ${alias}`);
    if ((listing.match(/Certificate chain length: 2/g) ?? []).length < 2) throw new Error("expected web and api to have 2-cert chains");
    if (!listing.includes("SecretKeyEntry")) throw new Error("secret key missing");
  });

  await step("delete, undo and redo", async () => {
    await openRowMenu("aes-key");
    await click(tid("menu-delete"));
    await click(tid("confirm-ok"));
    await toast();
    await waitGone(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="aes-key"]`));
    await click(tid("undo"));
    await find(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="aes-key"]`));
    await click(tid("redo"));
    await waitGone(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="aes-key"]`));
    await click(tid("undo"));
    await find(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="aes-key"]`));
  });

  await step("rename an entry", async () => {
    await openRowMenu("api");
    await click(tid("menu-rename"));
    await type(tid("rename-input"), "api-server");
    await click(tid("rename-submit"));
    await toast();
    await find(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="api-server"]`));
  });

  await step("workspace with an entry", async () => {
    await nav("workspaces");
    await click(tid("workspace-new"));
    await type(tid("workspace-name"), "Payments");
    await click(tid("workspace-save"));
    await toast();
    await click(tid("workspace-assign"));
    await click(By.xpath(`//button[@aria-pressed][.//span[normalize-space(.)="api-server"]]`));
    await clickButton("Done");
    await find(xpText("api-server", "div"));
    await shot("07-workspace");
  });

  await step("security audit lists findings", async () => {
    await nav("scanner");
    await waitText("Health score");
    await waitText("Findings");
    await shot("08-security");
  });

  await step("examine: decode a certificate", async () => {
    await nav("examine");
    await clickButton("Decode");
    await type(tid("decode-input"), fs.readFileSync(path.join(WORK, "ca.pem"), "utf8"));
    await click(tid("decode-run"));
    const title = await find(tid("decode-title"));
    if ((await title.getText()) !== "X.509 certificate") throw new Error(await title.getText());
    await waitText("E2E Root CA");
  });

  await step("examine: live TLS handshake with an untrusted server", async () => {
    const key = path.join(WORK, "tls.key");
    const cert = path.join(WORK, "tls.crt");
    sh("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "2"]);
    const port = 20000 + Math.floor(Math.random() * 20000);
    const server = spawn("openssl", ["s_server", "-accept", String(port), "-cert", cert, "-key", key, "-www", "-quiet"], { stdio: "ignore" });
    try {
      await sleep(600);
      await clickButton("TLS server");
      await type(tid("tls-host"), "127.0.0.1");
      await type(tid("tls-port"), String(port));
      await click(tid("tls-run"));
      await find(tid("tls-result"), 20000);
      await waitText("Not trusted");
      await waitText("TLS 1.3");
      await shot("09-tls");
    } finally {
      server.kill();
    }
  });

  await step("JWT sign and verify", async () => {
    await nav("ca_signing");
    await clickButton("JWT");
    const signer = await find(tid("jwt-signer"));
    for (const o of await signer.findElements(By.css("option"))) if ((await o.getText()).startsWith("api-server")) await o.click();
    await click(tid("jwt-sign"));
    await waitText("Valid ES256 signature");
  });

  await step("terminal runs a command", async () => {
    await driver.actions().keyDown(Key.CONTROL).sendKeys("`").keyUp(Key.CONTROL).perform();
    const input = await find(By.css('[aria-label="Terminal input"]'));
    await input.sendKeys("echo xks-terminal-ok", Key.ENTER);
    await waitText("xks-terminal-ok\n");
    await driver.actions().keyDown(Key.CONTROL).sendKeys("`").keyUp(Key.CONTROL).perform();
  });

  await step("save, then close with the unsaved-changes prompt", async () => {
    await nav("keystores");
    await click(tid("ks-save"));
    await toast();
    // make a change, then close and discard it
    await openRowMenu("aes-key");
    await click(tid("menu-delete"));
    await click(tid("confirm-ok"));
    await toast();
    await click(tid("ks-more"));
    await click(tid("ks-close"));
    await waitText("Save changes to e2e.p12?");
    await clickButton("Don't save");
    await waitText("No keystores open");
  });

  await step("reopen asks for the password and remembers it", async () => {
    await queueOpen(P12);
    await click(tid("empty-open"));
    await find(tid("open-password-dialog"));
    await type(tid("open-password"), "wrong-password");
    await click(tid("open-submit"));
    await waitText("That password does not open this keystore.");
    await type(tid("open-password"), STORE_PW);
    await click(By.xpath(`//label[contains(., "Remember the password in the vault")]`));
    await click(tid("open-submit"));
    const t = await toast();
    if (!t.includes("Opened e2e.p12: 4 entries")) throw new Error(t);
  });

  await step("restart restores the session; vault unlock reopens the keystore", async () => {
    await sleep(800); // let the debounced session save land
    await quit();
    await launch();
    await waitText("Welcome to xkeystore");
    await shot("10-restored");
    await nav("vault");
    await type(tid("vault-key"), MASTER);
    await click(tid("vault-submit"));
    const t = await toast();
    if (!t.includes("Unlocked 1 keystore")) throw new Error(t);
    await waitText("Dashboard");
    await nav("workspaces");
    await find(xpText("api-server", "div"));
    await nav("keystores");
    await find(By.xpath(`//span[@data-testid="entry-alias"][normalize-space(.)="aes-key"]`));
    await shot("11-dashboard-after-restart");
  });

  await step("command palette navigates", async () => {
    await driver.actions().keyDown(Key.CONTROL).sendKeys("k").keyUp(Key.CONTROL).perform();
    await type(tid("palette-input"), "Go to Settings");
    await driver.actions().sendKeys(Key.ENTER).perform();
    await waitText("Keyboard shortcuts");
  });
}

let failed = false;
try {
  await run();
} catch (err) {
  failed = true;
  if (!results.some((r) => !r.ok)) console.error("[e2e] setup failed:", err);
} finally {
  await quit();
  tauriDriver?.kill();
  const passed = results.filter((r) => r.ok).length;
  log(`${passed}/${results.length} steps passed. Screenshots: ${SHOTS}`);
  if (!failed && !process.env.XKS_KEEP) fs.rmSync(DATA, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
}
