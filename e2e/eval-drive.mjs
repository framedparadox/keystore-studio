// Drives the real xkeystore window on macOS, where tauri-driver has no WKWebView backend.
//
// The app must be started with XKEYSTORE_E2E=1. It then listens on 127.0.0.1 and writes the
// port to $XKEYSTORE_DATA_DIR/e2e.port. This script sends the same user journey as
// app.e2e.mjs and checks the files with keytool and openssl.
//
//   node e2e/eval-drive.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const APP = process.env.XKS_APP ?? path.join(ROOT, "src-tauri/target/debug/xkeystore");
const WORK = fs.mkdtempSync(path.join(os.tmpdir(), "xks-e2e-"));
const DATA = path.join(WORK, "data");
fs.mkdirSync(DATA, { recursive: true });
const PORT_FILE = path.join(DATA, "e2e.port");

const STORE_PW = "storepass1";
const MASTER = "e2e-master-key";
const P12 = path.join(WORK, "e2e.p12");
const results = [];
let child;
let sock;
let buf = Buffer.alloc(0);
let chain = Promise.resolve();

const log = (...a) => console.log("[e2e]", ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sh = (cmd, args) => {
  const r = spawnSync(cmd, args, { encoding: "utf8", env: { ...process.env, JAVA_TOOL_OPTIONS: "" } });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(" ")} failed:\n${r.stdout}${r.stderr}`);
  return `${r.stdout}${r.stderr}`;
};

function startApp() {
  if (fs.existsSync(PORT_FILE)) fs.rmSync(PORT_FILE);
  buf = Buffer.alloc(0);
  child = spawn(APP, [], {
    env: { ...process.env, XKEYSTORE_DATA_DIR: DATA, XKEYSTORE_E2E: "1", JAVA_TOOL_OPTIONS: "" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.on("data", (d) => process.stdout.write(d));
  child.stderr.on("data", (d) => process.stderr.write(d));
}

function connectOnce(port) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1");
    const timer = setTimeout(() => {
      s.destroy();
      reject(new Error("connect timeout"));
    }, 2000);
    s.once("connect", () => {
      clearTimeout(timer);
      resolve(s);
    });
    s.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function connect() {
  const start = Date.now();
  while (Date.now() - start < 30000) {
    if (child.exitCode != null) throw new Error(`app exited ${child.exitCode} before the bridge opened`);
    if (fs.existsSync(PORT_FILE)) {
      const port = Number(fs.readFileSync(PORT_FILE, "utf8").trim());
      if (port > 0) {
        try {
          sock = await connectOnce(port);
          sock.on("error", () => {});
          return;
        } catch {
          /* bridge not accepting yet */
        }
      }
    }
    await sleep(200);
  }
  throw new Error("e2e bridge did not open");
}

function evalOnce(script) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(script, "utf8");
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length);
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.off("data", onData);
      fn(value);
    };
    const timer = setTimeout(() => finish(reject, new Error("eval timed out")), 100000);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 4) return;
      const len = buf.readUInt32BE(0);
      if (len > 5_000_000) return finish(reject, new Error("response too large"));
      if (buf.length < 4 + len) return;
      const raw = buf.subarray(4, 4 + len).toString("utf8");
      buf = buf.subarray(4 + len);
      let value;
      try {
        value = raw.length ? JSON.parse(raw) : null;
      } catch {
        return finish(reject, new Error(`bad json: ${raw.slice(0, 300)}`));
      }
      if (value && typeof value === "object" && value.__e2eError) return finish(reject, new Error(value.__e2eError));
      finish(resolve, value);
    };
    sock.on("data", onData);
    sock.write(Buffer.concat([header, body]));
  });
}

function js(script) {
  const run = chain.then(() => evalOnce(script));
  chain = run.then(
    () => {},
    () => {}
  );
  return run;
}

const q = (v) => JSON.stringify(v);
async function click(id, timeout = 4000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const ok = await js(`const el = document.querySelector(${q(`[data-testid="${id}"]`)}); if (!el) return false; el.click(); return true;`);
    if (ok) return;
    await sleep(40);
  }
  const menus = await js(`return [...document.querySelectorAll('[role="menuitem"]')].map((el) => el.innerText).join(" | ")`);
  throw new Error(`missing ${id}. open menu: ${menus || "(none)"}`);
}
async function clickButton(text) {
  await js(`
    const want = ${q(text)};
    const el = [...document.querySelectorAll("button")].find((b) => !b.disabled && b.innerText.replace(/\\s+/g, " ").trim().includes(want));
    if (!el) throw new Error("no button: " + want);
    el.click();
    return true;
  `);
}
async function setField(id, value) {
  await js(`
    const el = document.querySelector(${q(`[data-testid="${id}"]`)});
    if (!el) throw new Error(${q(`missing ${id}`)});
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, ${q(value)});
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  `);
}
async function selectValue(id, value) {
  await js(`
    const sel = document.querySelector(${q(`[data-testid="${id}"]`)});
    if (!sel) throw new Error(${q(`missing ${id}`)});
    const opt = [...sel.options].find((o) => o.value === ${q(value)} || o.text.startsWith(${q(value)}));
    if (!opt) throw new Error("no option " + ${q(value)} + " in " + [...sel.options].map((o) => o.value + ":" + o.text).join(" | "));
    Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value").set.call(sel, opt.value);
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    return opt.text;
  `);
}
async function queue(kind, file) {
  await js(`window.__xksStub = window.__xksStub || { open: [], save: [] }; window.__xksStub[${q(kind)}].push(${q(file)}); return true;`);
}
async function bodyText() {
  return String((await js(`return document.body ? document.body.innerText : ""`)) ?? "");
}
async function waitText(text, timeout = 20000) {
  const start = Date.now();
  let last = "";
  while (Date.now() - start < timeout) {
    last = await bodyText();
    if (last.includes(text)) return last;
    await sleep(200);
  }
  throw new Error(`text not shown: ${text}\n---\n${last.slice(0, 1200)}`);
}
async function waitAlias(alias, present = true, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const found = await js(`return [...document.querySelectorAll('[data-testid="entry-alias"]')].some((el) => el.textContent.trim() === ${q(alias)});`);
    if (found === present) return;
    await sleep(150);
  }
  throw new Error(present ? `missing alias ${alias}` : `alias still present ${alias}`);
}
async function clickAlias(alias) {
  await js(`
    const el = [...document.querySelectorAll('[data-testid="entry-alias"]')].find((el) => el.textContent.trim() === ${q(alias)});
    if (!el) throw new Error("no alias " + ${q(alias)});
    el.click();
    return true;
  `);
}
async function waitGone(id, timeout = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const n = await js(`return document.querySelectorAll(${q(`[data-testid="${id}"]`)}).length`);
    if (n === 0) return;
    await sleep(150);
  }
  throw new Error(`still present: ${id}`);
}
async function toast(timeout = 45000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    const t = await js(`
      const el = document.querySelector('[data-testid^="toast-"]');
      if (!el) return null;
      const text = el.innerText;
      const kind = el.getAttribute("data-testid");
      document.querySelectorAll('[aria-label="Dismiss"]').forEach((b) => b.click());
      return { text, kind };
    `);
    if (t) {
      if (t.kind === "toast-danger") throw new Error(`error toast: ${t.text}`);
      return t.text;
    }
    await sleep(200);
  }
  throw new Error(`no toast\n---\n${(await bodyText()).slice(0, 1200)}`);
}
async function nav(id) {
  await click(`nav-${id}`);
  await sleep(200);
}
async function openRowMenu(alias) {
  await click(`row-menu-${alias}`);
  const start = Date.now();
  while (Date.now() - start < 3000) {
    const n = await js(`return document.querySelectorAll('[role="menu"]').length`);
    if (n > 0) return;
    await sleep(40);
  }
  throw new Error(`row menu for ${alias} did not open`);
}
async function press(key, extra = {}) {
  await js(`window.dispatchEvent(new KeyboardEvent("keydown", ${q({ key, bubbles: true, ...extra })})); return true;`);
}
async function step(name, fn) {
  const t = Date.now();
  try {
    await fn();
    results.push({ name, ok: true, ms: Date.now() - t });
    log(`PASS ${name} (${Date.now() - t} ms)`);
  } catch (err) {
    results.push({ name, ok: false, err: String(err?.message ?? err) });
    log(`FAIL ${name}: ${err?.message ?? err}`);
    throw err;
  }
}

async function restart() {
  sock.destroy();
  sock = undefined;
  chain = Promise.resolve();
  buf = Buffer.alloc(0);
  child.kill();
  const exited = await Promise.race([
    new Promise((r) => child.once("exit", () => r(true))),
    sleep(4000).then(() => false),
  ]);
  if (!exited) {
    child.kill("SIGKILL");
    await sleep(300);
  }
  startApp();
  await connect();
}

async function run() {
  startApp();
  await connect();

  await step("first launch shows the welcome screen", async () => {
    await waitText("Welcome to xkeystore");
    await waitText("Recent files");
  });

  await step("vault setup", async () => {
    await nav("vault");
    await setField("vault-key", MASTER);
    await setField("vault-key-confirm", MASTER);
    await click("vault-submit");
    await waitText("Remembered passwords");
  });

  await step("create a PKCS#12 keystore with an initial key pair", async () => {
    await click("header-new");
    await js(`if (!document.querySelector('[data-testid="new-keystore-dialog"]')) throw new Error("new keystore dialog missing"); return true;`);
    await setField("new-keystore-name", "e2e.p12");
    await setField("new-keystore-password", STORE_PW);
    await setField("new-keystore-password-confirm", STORE_PW);
    await setField("new-keystore-alias", "web");
    await click("new-keystore-create");
    const t = await toast(60000);
    if (!t.includes("Created e2e.p12")) throw new Error(t);
    await waitText("Not saved yet");
    await waitAlias("web");
  });

  await step("save keystore to disk (first save asks for a location)", async () => {
    await queue("save", P12);
    await click("ks-save");
    await js(`if (!document.querySelector('[data-testid="save-dialog"]')) throw new Error("save dialog missing"); return true;`);
    await click("save-choose-location");
    const t = await toast();
    if (!t.includes("Saved e2e.p12")) throw new Error(t);
    if (!fs.existsSync(P12)) throw new Error("file not written");
    const listing = sh("keytool", ["-list", "-keystore", P12, "-storepass", STORE_PW]);
    if (!listing.includes("web, ") || !listing.includes("PrivateKeyEntry")) throw new Error(listing);
  });

  await step("generate a CA and a CA-signed key pair", async () => {
    await click("ks-add-entry");
    await click("add-ca");
    await js(`if (!document.querySelector('[data-testid="generate-keypair-dialog"]')) throw new Error("generate dialog missing"); return true;`);
    await setField("kp-alias", "e2e-ca");
    await setField("kp-cn", "E2E Root CA");
    await click("generate-keypair-submit");
    await toast(60000);
    await click("ks-add-entry");
    await click("add-keypair");
    await setField("kp-alias", "api");
    await setField("kp-cn", "api.e2e.test");
    await setField("kp-sans", "api.e2e.test, 127.0.0.1");
    await selectValue("kp-signer", "e2e-ca");
    await click("generate-keypair-submit");
    const t = await toast(60000);
    if (!t.includes("signed by e2e-ca")) throw new Error(t);
  });

  await step("generate an AES secret key", async () => {
    await click("ks-add-entry");
    await click("add-secret");
    await setField("sk-alias", "aes-key");
    await click("secret-key-submit");
    await toast();
  });

  await step("inspect the CA-signed entry", async () => {
    await clickAlias("api");
    await js(`if (!document.querySelector('[data-testid="entry-inspector"]')) throw new Error("inspector missing"); return true;`);
    await waitText("Chain (2)");
    await waitText("DNS:api.e2e.test, IP:127.0.0.1");
    await press("Escape");
    await waitGone("entry-inspector");
  });

  await step("export certificate and chain, verified by openssl", async () => {
    const ca = path.join(WORK, "ca.pem");
    const chain = path.join(WORK, "api-chain.pem");
    await openRowMenu("e2e-ca");
    await click("menu-export");
    await queue("save", ca);
    await click("export-run");
    await toast();
    await clickButton("Close");
    await openRowMenu("api");
    await click("menu-export");
    await selectValue("export-format", "chain_pem");
    await queue("save", chain);
    await click("export-run");
    await toast();
    await clickButton("Close");
    const out = sh("openssl", ["verify", "-CAfile", ca, "-verify_hostname", "api.e2e.test", chain]);
    if (!out.includes("OK")) throw new Error(out);
  });

  await step("CSR → CA signs it → installed as CA reply", async () => {
    const csr = path.join(WORK, "web.csr");
    await openRowMenu("web");
    await click("menu-csr");
    await click("csr-generate");
    const csrStart = Date.now();
    let csrReady = false;
    let csrErr = "";
    while (Date.now() - csrStart < 20000) {
      csrReady = (await js(`return document.querySelectorAll('[data-testid="csr-output"]').length`)) > 0;
      if (csrReady) break;
      csrErr = String((await js(`const el = document.querySelector('[data-testid="toast-error"]'); return el ? el.innerText : ""`)) ?? "");
      if (csrErr) break;
      await sleep(150);
    }
    if (!csrReady) throw new Error(csrErr || "csr output missing");
    await queue("save", csr);
    await click("csr-save");
    await toast();
    await clickButton("Close");
    const v = sh("openssl", ["req", "-in", csr, "-noout", "-verify"]);
    if (!/verify ok/i.test(v)) throw new Error(v);

    await nav("ca_signing");
    await queue("open", csr);
    await clickButton("Choose file…");
    await click("sign-csr-submit");
    await toast(60000);
    await click("install-issued");
    const t = await toast();
    if (!t.includes("Installed the certificate into 'web'")) throw new Error(t);
  });

  await step("save in place and verify with keytool", async () => {
    await nav("keystores");
    await press("s", { ctrlKey: true });
    const t = await toast();
    if (!t.includes("Saved e2e.p12")) throw new Error(t);
    const listing = sh("keytool", ["-list", "-v", "-keystore", P12, "-storepass", STORE_PW]);
    for (const alias of ["web", "api", "e2e-ca", "aes-key"]) if (!listing.includes(`Alias name: ${alias}`)) throw new Error(`missing ${alias}\n${listing}`);
    if ((listing.match(/Certificate chain length: 2/g) ?? []).length < 2) throw new Error("expected web and api to have 2-cert chains");
    if (!listing.includes("SecretKeyEntry")) throw new Error("secret key missing");
  });

  await step("delete, undo and redo", async () => {
    await openRowMenu("aes-key");
    await click("menu-delete");
    await click("confirm-ok");
    await toast();
    await waitAlias("aes-key", false);
    await click("undo");
    await waitAlias("aes-key", true);
    await click("redo");
    await waitAlias("aes-key", false);
    await click("undo");
    await waitAlias("aes-key", true);
  });

  await step("rename an entry", async () => {
    await openRowMenu("api");
    await click("menu-rename");
    await setField("rename-input", "api-server");
    await click("rename-submit");
    await toast();
    await waitAlias("api-server");
  });

  await step("workspace with an entry", async () => {
    await nav("workspaces");
    await click("workspace-new");
    await setField("workspace-name", "Payments");
    await click("workspace-save");
    await toast();
    await click("workspace-assign");
    await js(`
      const el = [...document.querySelectorAll("button[aria-pressed]")].find((b) => [...b.querySelectorAll("span")].some((s) => s.textContent.trim() === "api-server"));
      if (!el) throw new Error("no workspace row for api-server");
      el.click();
      return true;
    `);
    await clickButton("Done");
    await waitText("api-server");
  });

  await step("security audit lists findings", async () => {
    await nav("scanner");
    await waitText("Health score");
    await waitText("Findings");
  });

  await step("examine: decode a certificate", async () => {
    await nav("examine");
    await clickButton("Decode");
    await setField("decode-input", fs.readFileSync(path.join(WORK, "ca.pem"), "utf8"));
    await click("decode-run");
    const decodeStart = Date.now();
    let title = "";
    let decodeErr = "";
    while (Date.now() - decodeStart < 20000) {
      title = String((await js(`const el = document.querySelector('[data-testid="decode-title"]'); return el ? el.textContent.trim() : ""`)) ?? "");
      if (title) break;
      decodeErr = String((await js(`const el = document.querySelector('[data-testid="toast-error"]'); return el ? el.innerText : ""`)) ?? "");
      if (decodeErr) break;
      await sleep(150);
    }
    if (title !== "X.509 certificate") throw new Error(decodeErr || title || "no decode title");
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
      await setField("tls-host", "127.0.0.1");
      await setField("tls-port", String(port));
      await click("tls-run");
      const tlsStart = Date.now();
      let tlsReady = false;
      while (Date.now() - tlsStart < 20000) {
        tlsReady = (await js(`return document.querySelectorAll('[data-testid="tls-result"]').length`)) > 0;
        if (tlsReady) break;
        await sleep(200);
      }
      if (!tlsReady) throw new Error("tls result missing");
      await waitText("Not trusted");
      await waitText("TLS 1.3");
    } finally {
      server.kill();
    }
  });

  await step("JWT sign and verify", async () => {
    await nav("ca_signing");
    await clickButton("JWT");
    await selectValue("jwt-signer", "api-server");
    const ready = Date.now();
    let enabled = false;
    while (Date.now() - ready < 10000) {
      enabled = Boolean(await js(`const el = document.querySelector('[data-testid="jwt-sign"]'); return !!(el && !el.disabled);`));
      if (enabled) break;
      await sleep(50);
    }
    if (!enabled) throw new Error("Sign token stayed disabled");
    await click("jwt-sign");
    await waitText("Valid ES256 signature", 20000);
  });

  await step("terminal runs a command", async () => {
    await js(`
      const btn = document.querySelector(${q('[aria-label="Terminal (Ctrl+`)"]')});
      if (!btn) throw new Error("no terminal button");
      btn.click();
      return true;
    `);
    await setFieldBySelector('[aria-label="Terminal input"]', "echo xks-terminal-ok");
    await js(`
      const input = document.querySelector('[aria-label="Terminal input"]');
      if (!input) throw new Error("no terminal input");
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      return true;
    `);
    await waitText("xks-terminal-ok");
    await js(`
      const btn = document.querySelector(${q('[aria-label="Terminal (Ctrl+`)"]')});
      btn.click();
      return true;
    `);
  });

  await step("save, then close with the unsaved-changes prompt", async () => {
    await nav("keystores");
    await click("ks-save");
    await toast();
    await openRowMenu("aes-key");
    await click("menu-delete");
    await click("confirm-ok");
    await toast();
    await click("ks-more");
    await click("ks-close");
    await waitText("Save changes to e2e.p12?");
    await clickButton("Don't save");
    await waitText("No keystores open");
  });

  await step("reopen asks for the password and remembers it", async () => {
    await queue("open", P12);
    await click("empty-open");
    const openStart = Date.now();
    let openDialog = false;
    while (Date.now() - openStart < 15000) {
      openDialog = (await js(`return document.querySelectorAll('[data-testid="open-password-dialog"]').length`)) > 0;
      if (openDialog) break;
      await sleep(100);
    }
    if (!openDialog) throw new Error(`password dialog missing\n---\n${(await bodyText()).slice(0, 800)}`);
    await setField("open-password", "wrong-password");
    await click("open-submit");
    await waitText("That password does not open this keystore.");
    await setField("open-password", STORE_PW);
    await js(`
      const label = [...document.querySelectorAll("label")].find((l) => l.textContent.includes("Remember the password in the vault"));
      if (!label) throw new Error("no remember checkbox");
      label.click();
      return true;
    `);
    await click("open-submit");
    const t = await toast();
    if (!t.includes("Opened e2e.p12: 4 entries")) throw new Error(t);
  });

  await step("restart restores the session; vault unlock reopens the keystore", async () => {
    await sleep(800);
    await restart();
    await waitText("locked");
    await click("unlock-with-vault");
    await setField("vault-prompt-key", MASTER);
    await click("vault-prompt-submit");
    const t = await toast();
    if (!t.includes("Unlocked 1 keystore")) throw new Error(t);
    await waitText("Dashboard");
    await nav("workspaces");
    await waitText("api-server");
    await nav("keystores");
    await waitAlias("aes-key");
  });

  await step("create a PKCS#12 from a certificate and private key on disk", async () => {
    // Inputs a user would actually have: a cert and key produced by OpenSSL, not by this app.
    const certPem = path.join(WORK, "standalone-cert.pem");
    const keyPem = path.join(WORK, "standalone-key.pem");
    const outPfx = path.join(WORK, "standalone.pfx");
    const PFX_PW = "pfx-pass-1";
    sh("openssl", [
      "req", "-x509", "-newkey", "rsa:2048",
      "-keyout", keyPem, "-out", certPem,
      "-days", "30", "-nodes",
      "-subj", "/CN=standalone.e2e.test/O=xkeystore e2e",
    ]);

    await nav("home");
    await click("home-build-p12");
    await waitText("Create PKCS#12");
    await setFieldBySelector('[data-testid="build-p12-cert"]', fs.readFileSync(certPem, "utf8"));
    await setFieldBySelector('[data-testid="build-p12-key"]', fs.readFileSync(keyPem, "utf8"));
    await setField("build-p12-pass", PFX_PW);
    await setField("build-p12-pass-confirm", PFX_PW);
    await setField("build-p12-alias", "standalone");
    await queue("save", outPfx);
    await click("build-p12-submit");
    await toast();
    await clickButton("Close");

    if (!fs.existsSync(outPfx)) throw new Error("no PKCS#12 was written");

    // OpenSSL must find both the key and the certificate under the passphrase we set.
    const dump = sh("openssl", ["pkcs12", "-in", outPfx, "-passin", `pass:${PFX_PW}`, "-nodes"]);
    if (!dump.includes("BEGIN PRIVATE KEY")) throw new Error(`no private key in the .pfx:\n${dump}`);
    if (!dump.includes("BEGIN CERTIFICATE")) throw new Error(`no certificate in the .pfx:\n${dump}`);
    if (!dump.includes("friendlyName: standalone")) throw new Error(`alias missing:\n${dump}`);

    // The wrong passphrase must be refused.
    const bad = spawnSync("openssl", ["pkcs12", "-in", outPfx, "-passin", "pass:wrong", "-nodes", "-noout"], { encoding: "utf8" });
    if (bad.status === 0) throw new Error("the .pfx opened with the wrong passphrase");

    // Java agrees it is a usable PrivateKeyEntry.
    const list = sh("keytool", ["-list", "-v", "-keystore", outPfx, "-storetype", "PKCS12", "-storepass", PFX_PW]);
    if (!list.includes("PrivateKeyEntry")) throw new Error(`keytool sees no private key:\n${list}`);
    if (!list.includes("standalone.e2e.test")) throw new Error(`unexpected subject:\n${list}`);
  });

  await step("command palette navigates", async () => {
    await press("k", { ctrlKey: true });
    await setField("palette-input", "Go to Settings");
    await js(`
      const input = document.querySelector('[data-testid="palette-input"]');
      if (!input) throw new Error("palette missing");
      input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      return true;
    `);
    await waitText("Keyboard shortcuts");
  });
}

async function setFieldBySelector(selector, value) {
  await js(`
    const el = document.querySelector(${q(selector)});
    if (!el) throw new Error("missing " + ${q(selector)});
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, ${q(value)});
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  `);
}

let failed = false;
try {
  await run();
} catch (err) {
  failed = true;
  if (!results.some((r) => !r.ok)) console.error("[e2e] setup failed:", err);
} finally {
  try {
    sock?.destroy();
  } catch {
    /* already closed */
  }
  if (child && child.exitCode == null) {
    child.kill();
    await Promise.race([new Promise((r) => child.once("exit", r)), sleep(2000)]);
    if (child.exitCode == null) child.kill("SIGKILL");
  }
  const passed = results.filter((r) => r.ok).length;
  log(`${passed}/${results.length} steps passed. Work dir: ${WORK}`);
  process.exit(failed ? 1 : 0);
}
