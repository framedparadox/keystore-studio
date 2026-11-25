/* Keystore Studio website — behaviour for the More apps, Changelog and Feedback pages.
   Loaded after site.js (theme, nav, reveal, copy buttons), iso.js (scenes) and pages.js (tabs,
   table-of-contents scroll-spy). Every part checks for its own markup, so one file serves all three. */
(() => {
  "use strict";

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const smooth = () => (reduceMotion.matches ? "auto" : "smooth");
  const flash = (el) => {
    el.classList.remove("is-flash");
    void el.offsetWidth; // restart the highlight animation
    el.classList.add("is-flash");
  };

  /* =====================================================================
     More apps: cards and jump links light up their block (or shelf) in the scene;
     clicking a block in the scene scrolls to its card.
     ===================================================================== */
  const shelf = document.querySelector('.iso-scene[data-scene="apps"]');
  if (shelf) {
    let timer = 0;
    const setActive = (id) => {
      window.clearTimeout(timer);
      if (id) shelf.dataset.active = id;
      else timer = window.setTimeout(() => delete shelf.dataset.active, 140);
    };
    document.querySelectorAll("[data-app], .x-jump a[href^='#']").forEach((el) => {
      const id = el.dataset.app || el.getAttribute("href").slice(1);
      el.addEventListener("pointerenter", (e) => e.pointerType !== "touch" && setActive(id));
      el.addEventListener("pointerleave", () => setActive(null));
      el.addEventListener("focusin", () => setActive(id));
      el.addEventListener("focusout", () => setActive(null));
    });
    shelf.addEventListener("iso:pick", (e) => {
      const card = document.getElementById(`app-${e.detail.id}`);
      if (!card) return;
      card.scrollIntoView({ behavior: smooth(), block: "center" });
      flash(card);
    });
  }

  /* =====================================================================
     Changelog: the milestone under the reading line (or under the pointer) is the
     active slab in the stack scene, and hovering a slab marks its milestone.
     ===================================================================== */
  const stack = document.querySelector('.iso-scene[data-scene="changelog"]');
  const steps = [...document.querySelectorAll("[data-road]")];
  const road = document.getElementById("road");
  if (stack && steps.length && road) {
    let hover = null;
    let spied = null;
    const sync = () => {
      const cur = hover ?? spied;
      if (cur == null) delete stack.dataset.active;
      else stack.dataset.active = cur;
      steps.forEach((li) => li.classList.toggle("is-current", li.dataset.road === String(cur)));
    };
    steps.forEach((li) => {
      li.addEventListener("pointerenter", (e) => {
        if (e.pointerType === "touch") return;
        hover = li.dataset.road;
        sync();
      });
      li.addEventListener("pointerleave", () => {
        hover = null;
        sync();
      });
    });
    stack.addEventListener("iso:hot", (e) => {
      hover = e.detail.index == null ? null : String(e.detail.index);
      sync();
    });
    let ticking = false;
    const update = () => {
      ticking = false;
      const r = road.getBoundingClientRect();
      const line = window.innerHeight * 0.55;
      let cur = null;
      if (r.top < window.innerHeight * 0.85 && r.bottom > window.innerHeight * 0.2) {
        cur = steps[0].dataset.road;
        steps.forEach((li) => {
          if (li.getBoundingClientRect().top <= line) cur = li.dataset.road;
        });
      }
      if (cur !== spied) {
        spied = cur;
        sync();
      }
    };
    const onScroll = () => {
      if (!ticking) {
        ticking = true;
        window.requestAnimationFrame(update);
      }
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    update();
  }

  /* Changelog: a version anchor in the address bar briefly highlights its release. */
  if (document.body.classList.contains("page-changelog")) {
    const mark = () => {
      const el = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)));
      if (el && el.classList.contains("x-release")) flash(el);
    };
    window.addEventListener("hashchange", mark);
    mark();
  }

  /* =====================================================================
     Feedback: builds a mailto: link and hands it to the visitor's mail app.
     No backend and no form service: the CSP's form-action 'self' would block a
     mailto: form action anyway, so the form is submitted here, in script.
     ===================================================================== */
  const form = document.querySelector("form[data-feedback]");
  if (!form) return;

  const TO = "hello@keystore-studio.app";
  const MAX = 2000;
  const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const HINTS = {
    "Bug report": "What you did, what you expected, and what happened instead. Paste the output of Copy diagnostics too.",
    Suggestion: "What you'd like Keystore Studio to do, and the problem it would solve for you.",
    Feedback: "Friction, rough edges, wording, anything that could feel smoother.",
    Praise: "What works well for you. It helps decide what not to change.",
  };

  const $ = (sel) => form.querySelector(sel);
  const name = $("#fb-name");
  const email = $("#fb-email");
  const emailErr = $("#fb-email-err");
  const msg = $("#fb-msg");
  const msgErr = $("#fb-msg-err");
  const version = $("#fb-version");
  const os = $("#fb-os");
  const bugFields = $("[data-bug-fields]");
  const hint = $("[data-hint]");
  const counter = $("#fb-count");
  const counterLive = $("#fb-count-live");
  const seg = $("[data-seg]");
  const done = $("#fb-done");
  const preview = $("#fb-preview");
  const radios = [...form.querySelectorAll('input[name="type"]')];
  const scene = document.querySelector('.iso-scene[data-scene="feedback"]');

  /* ---------- Operating system, prefilled and still editable ---------- */
  const handheld = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || (navigator.maxTouchPoints > 1 && /Macintosh/.test(navigator.userAgent));
  const detectOS = () => {
    if (handheld) return ""; // the app is desktop-only; let the visitor say which computer
    const ua = navigator.userAgent;
    const p = (navigator.userAgentData && navigator.userAgentData.platform) || "";
    if (/Windows/i.test(p) || /Windows NT/i.test(ua)) return "Windows";
    if (/mac/i.test(p) || /Mac OS X|Macintosh/i.test(ua)) return "macOS";
    if (/CrOS/.test(ua)) return "ChromeOS";
    if (/Linux/i.test(p) || /Linux|X11/i.test(ua)) return "Linux";
    return "";
  };
  const fillOS = () => {
    os.value = detectOS();
    os.dataset.auto = "1";
    // Chromium browsers can tell Windows 10 from 11 and the CPU architecture.
    const uad = navigator.userAgentData;
    if (!os.value || !uad || typeof uad.getHighEntropyValues !== "function") return;
    uad
      .getHighEntropyValues(["platformVersion", "architecture", "bitness"])
      .then((v) => {
        if (os.dataset.auto !== "1") return;
        let label = os.value;
        const major = parseInt(v.platformVersion, 10);
        if (label === "Windows" && major > 0) label = major >= 13 ? "Windows 11" : "Windows 10";
        const arch = v.architecture === "arm" ? "arm64" : v.architecture === "x86" && v.bitness === "64" ? "x64" : "";
        if (arch) label += ` (${arch})`;
        os.value = label;
      })
      .catch(() => {});
  };
  os.addEventListener("input", () => delete os.dataset.auto);
  fillOS();

  /* ---------- Type: segmented control built from native radios ---------- */
  const currentType = () => (radios.find((r) => r.checked) || radios[0]).value;
  const onType = () => {
    const t = currentType();
    seg.style.setProperty("--idx", String(Math.max(0, radios.findIndex((r) => r.checked))));
    bugFields.hidden = t !== "Bug report";
    hint.textContent = HINTS[t] || "";
    if (scene) scene.dataset.type = t;
  };
  radios.forEach((r) => r.addEventListener("change", onType));
  onType();

  document.querySelectorAll("[data-pick-type]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const r = radios.find((x) => x.value === btn.dataset.pickType);
      if (!r) return;
      r.checked = true;
      onType();
      document.getElementById("write")?.scrollIntoView({ behavior: smooth(), block: "start" });
      msg.focus({ preventScroll: true });
    });
  });

  /* ---------- Character count ---------- */
  let lastBand = 0;
  const onCount = () => {
    const n = msg.value.length;
    counter.textContent = `${n.toLocaleString("en-US")} / ${MAX.toLocaleString("en-US")}`;
    const band = n >= MAX ? 2 : n >= MAX - 200 ? 1 : 0;
    counter.dataset.band = String(band);
    // Announce only when crossing a threshold, not on every keystroke.
    if (band !== lastBand) {
      counterLive.textContent = band === 2 ? "Character limit reached." : band === 1 ? `${MAX - n} characters left.` : "";
      lastBand = band;
    }
  };
  msg.addEventListener("input", onCount);
  onCount();

  /* ---------- Validation ---------- */
  const baseDescribedBy = new Map();
  const setError = (field, errEl, text) => {
    if (!baseDescribedBy.has(field)) baseDescribedBy.set(field, field.getAttribute("aria-describedby") || "");
    const base = baseDescribedBy.get(field);
    errEl.querySelector("span").textContent = text || "";
    errEl.hidden = !text;
    if (text) {
      field.setAttribute("aria-invalid", "true");
      field.setAttribute("aria-describedby", `${errEl.id} ${base}`.trim());
    } else {
      field.removeAttribute("aria-invalid");
      if (base) field.setAttribute("aria-describedby", base);
    }
  };
  const checkEmail = () => {
    const v = email.value.trim();
    const bad = v !== "" && !EMAIL.test(v);
    setError(email, emailErr, bad ? "Enter an address like name@example.com, or leave it empty." : "");
    return !bad;
  };
  const checkMessage = () => {
    const ok = msg.value.trim() !== "";
    setError(msg, msgErr, ok ? "" : "Write a message first.");
    return ok;
  };
  const validate = () => {
    const bad = [];
    if (!checkEmail()) bad.push(email);
    if (!checkMessage()) bad.push(msg);
    return bad; // in document order
  };
  // Once a field has shown an error, re-check it as the visitor fixes it.
  email.addEventListener("input", () => email.hasAttribute("aria-invalid") && checkEmail());
  email.addEventListener("blur", checkEmail);
  msg.addEventListener("input", () => msg.hasAttribute("aria-invalid") && checkMessage());

  /* ---------- Compose ---------- */
  const compose = () => {
    const t = currentType();
    const who = name.value.trim();
    const reply = email.value.trim();
    const subject = `Keystore Studio: ${t}${who ? ` from ${who}` : ""}`;
    const lines = [msg.value.trim(), "", "---", `Type: ${t}`];
    if (t === "Bug report") {
      lines.push(`App version: ${version.value.trim() || "not given"}`);
      lines.push(`Operating system: ${os.value.trim() || "not given"}`);
    }
    if (who) lines.push(`Name: ${who}`);
    if (reply) lines.push(`Reply to: ${reply}`);
    lines.push("Sent from https://keystore-studio.app/feedback/");
    const body = lines.join("\n").replace(/\r?\n/g, "\r\n"); // RFC 6068: line breaks in a mailto body are CRLF
    const href = `mailto:${TO}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    const text = `To: ${TO}\nSubject: ${subject}\n\n${lines.join("\n")}`;
    return { subject, body, href, text };
  };
  // Exposed for testing: window.KSFeedback.compose() returns the mailto: link without opening it.
  window.KSFeedback = { compose };

  const showDone = (text, { focus = true } = {}) => {
    preview.textContent = text;
    done.hidden = false;
    if (focus) done.focus({ preventScroll: true });
    done.scrollIntoView({ behavior: smooth(), block: "nearest" });
  };

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const bad = validate();
    if (bad.length) {
      bad[0].focus();
      return;
    }
    const mail = compose();
    showDone(mail.text);
    if (scene) {
      scene.dataset.state = "sent";
      window.setTimeout(() => {
        if (scene.dataset.state === "sent") delete scene.dataset.state;
      }, 2600);
    }
    window.location.href = mail.href;
  });

  /* ---------- Copy message (fallback for visitors without a mail app) ---------- */
  const setCopyLabels = (text) =>
    document.querySelectorAll("[data-fb-copy-label]").forEach((el) => (el.textContent = text));
  document.querySelectorAll("[data-fb-copy]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const bad = validate();
      if (bad.length) {
        bad[0].focus();
        return;
      }
      const mail = compose();
      try {
        await navigator.clipboard.writeText(mail.text);
        setCopyLabels("Copied");
        btn.classList.add("is-copied");
        window.setTimeout(() => {
          setCopyLabels("Copy message");
          btn.classList.remove("is-copied");
        }, 1600);
        if (done.hidden) showDone(mail.text, { focus: false });
        else preview.textContent = mail.text;
      } catch {
        // Clipboard blocked: show the message and select it so it can be copied by hand.
        showDone(mail.text);
        const details = done.querySelector("details");
        if (details) details.open = true;
        const range = document.createRange();
        range.selectNodeContents(preview);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
      }
    });
  });

  form.querySelector("[data-fb-reset]")?.addEventListener("click", () => {
    form.reset();
    setError(email, emailErr, "");
    setError(msg, msgErr, "");
    done.hidden = true;
    preview.textContent = "";
    fillOS();
    onType();
    onCount();
    msg.focus();
  });

  /* ---------- The envelope opens while the visitor is writing ---------- */
  if (scene) {
    form.addEventListener("focusin", () => {
      if (scene.dataset.state !== "sent") scene.dataset.state = "open";
    });
    form.addEventListener("focusout", (e) => {
      if (!form.contains(e.relatedTarget) && scene.dataset.state === "open") delete scene.dataset.state;
    });
  }
})();
