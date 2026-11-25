/* Keystore Studio website — behaviour for the secondary pages (downloads, privacy).
   Loaded after site.js, which sets :root[data-os] and handles theme, nav, reveal and copy buttons. */
(() => {
  "use strict";

  /* =====================================================================
     RELEASE — the one place to change when a new installer ships.
     Installers are served from Cloudflare R2 at downloads.keystore-studio.app, not from the site:
     Workers static assets cap files at 25 MiB. .github/workflows/website.yml uploads every
     installer in website/downloads/ to R2 under v<version>/, with the same file name.
     A relative `url` is resolved against the site root, which is handy for local previews.
     The HTML carries the same values as a no-JavaScript fallback (see website/README.md).
     ===================================================================== */
  const RELEASE = {
    version: "1.0.0",
    file: "Keystore Studio_1.0.0_x64-setup.exe",
    url: "https://downloads.keystore-studio.app/v1.0.0/Keystore%20Studio_1.0.0_x64-setup.exe",
    bytes: 301845656,
    sha256: "0e5715def11e0b6fceefe942080ea18e367698a2cb0d9c0117d8c7f92e730e1f",
  };

  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const script = document.currentScript;
  const siteRoot = script ? new URL("../../", script.src) : new URL("./", location.href);

  /* ---------- Release values ---------- */
  const sizeMB = `${(RELEASE.bytes / 1048576).toFixed(1)} MB`;
  const downloadHref = new URL(RELEASE.url, siteRoot).href;
  document.querySelectorAll("[data-download]").forEach((a) => {
    a.href = downloadHref;
  });
  const fill = (key, value) => document.querySelectorAll(`[data-release="${key}"]`).forEach((el) => (el.textContent = value));
  fill("size", sizeMB);
  fill("file", RELEASE.file);
  fill("bytes", RELEASE.bytes.toLocaleString("en-US"));
  fill("version", RELEASE.version);
  fill("sha256-short", `${RELEASE.sha256.slice(0, 8)}…${RELEASE.sha256.slice(-8)}`);
  document.querySelectorAll('[data-release="sha256-short"]').forEach((el) => (el.title = RELEASE.sha256));
  document.querySelectorAll('[data-release="sha256-grouped"]').forEach((el) => {
    el.replaceChildren(
      ...RELEASE.sha256.match(/.{8}/g).map((g) => {
        const s = document.createElement("span");
        s.textContent = g;
        return s;
      })
    );
  });
  document.querySelectorAll('[data-release-copy="sha256"]').forEach((b) => (b.dataset.copy = RELEASE.sha256));

  /* ---------- Platform picker (downloads) ---------- */
  const pick = document.querySelector(".os-pick");
  const scene = document.querySelector('.iso-scene[data-scene="platforms"]');
  const OS_NAMES = { windows: "Windows", macos: "macOS", linux: "Linux" };
  // Phones and tablets report Linux (Android) or Mac OS X (iPad); neither runs the desktop app.
  const handheld = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent) || (navigator.maxTouchPoints > 1 && /Macintosh/.test(navigator.userAgent));
  if (handheld) root.dataset.os = "other";
  const detected = OS_NAMES[root.dataset.os] ? root.dataset.os : null;

  const setPick = (os, { animate = true } = {}) => {
    if (!pick || !OS_NAMES[os]) return;
    pick.dataset.pick = os;
    pick.querySelectorAll(".os-switch [data-pick-btn]").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.pickBtn === os)));
    if (animate) {
      pick.classList.remove("is-switched");
      void pick.offsetWidth; // restart the entry animation
      pick.classList.add("is-switched");
    }
    // Panels revealed while hidden never intersected; show them now.
    pick.querySelectorAll(`.os-panel[data-for="${os}"] .reveal`).forEach((el) => el.classList.add("is-in"));
    if (scene) scene.dataset.active = os;
  };

  if (pick) {
    setPick(detected || "windows", { animate: false });
    const note = document.querySelector("[data-os-note]");
    if (note) {
      if (detected === "windows") note.textContent = "We've picked Windows for you. The installer is ready.";
      else if (detected) note.textContent = `We've picked ${OS_NAMES[detected]} for you. There's no installer yet, so here's how to build one.`;
      else if (handheld) note.textContent = "Keystore Studio is a desktop app. Open this page on your computer to install it.";
    }
    document.addEventListener("click", (e) => {
      const btn = e.target.closest("[data-pick-btn]");
      if (!btn) return;
      setPick(btn.dataset.pickBtn);
      if (btn.hasAttribute("data-pick-scroll") || !btn.closest(".os-switch")) {
        document.getElementById("get")?.scrollIntoView({ behavior: reduceMotion.matches ? "auto" : "smooth", block: "start" });
      }
    });
    // Arrow keys move between the three switch buttons.
    pick.querySelector(".os-switch")?.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      const order = ["windows", "macos", "linux"];
      const i = order.indexOf(pick.dataset.pick);
      const next = order[(i + (e.key === "ArrowRight" ? 1 : order.length - 1)) % order.length];
      setPick(next);
      pick.querySelector(`.os-switch [data-pick-btn="${next}"]`)?.focus();
      e.preventDefault();
    });
  } else if (scene && detected) {
    scene.dataset.active = detected;
  }

  /* ---------- Tabs inside terminals ---------- */
  const activateTab = (tab, focus) => {
    const list = tab.closest('[role="tablist"]');
    const box = tab.closest("[data-tabs]");
    list.querySelectorAll('[role="tab"]').forEach((t) => {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      const panel = box.querySelector(`#${t.getAttribute("aria-controls")}`);
      if (panel) panel.hidden = !on;
    });
    if (focus) tab.focus();
  };
  document.querySelectorAll("[data-tabs]").forEach((box) => {
    const tabs = [...box.querySelectorAll('[role="tab"]')];
    tabs.forEach((t, i) => {
      t.addEventListener("click", () => activateTab(t));
      t.addEventListener("keydown", (e) => {
        let j = null;
        if (e.key === "ArrowRight") j = (i + 1) % tabs.length;
        if (e.key === "ArrowLeft") j = (i - 1 + tabs.length) % tabs.length;
        if (e.key === "Home") j = 0;
        if (e.key === "End") j = tabs.length - 1;
        if (j === null) return;
        e.preventDefault();
        activateTab(tabs[j], true);
      });
    });
    // Open the visitor's OS tab first (Linux visitors get the Debian/Ubuntu tab).
    const want = { windows: "win", macos: "mac", linux: "deb" }[root.dataset.os];
    const first = want && tabs.find((t) => t.id.endsWith(`-${want}`));
    if (first) activateTab(first);
  });

  /* ---------- Paste-to-compare checksum ---------- */
  document.querySelectorAll("[data-hash-check]").forEach((form) => {
    form.addEventListener("submit", (e) => e.preventDefault());
    const input = form.querySelector("input");
    const out = form.querySelector("output");
    const check = () => {
      const raw = input.value.trim();
      const found = raw.match(/[0-9a-f]{64}/i);
      if (!raw) {
        delete form.dataset.result;
        out.textContent = "";
        return;
      }
      if (!found) {
        form.dataset.result = "partial";
        out.textContent = "Looking for a 64-character SHA-256…";
        return;
      }
      const ok = found[0].toLowerCase() === RELEASE.sha256;
      form.dataset.result = ok ? "match" : "mismatch";
      out.innerHTML = ok
        ? '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg>Matches. This is the published file.'
        : '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/></svg>Doesn’t match. Don’t run this file; download it again.';
    };
    input.addEventListener("input", check);
  });

  /* ---------- SmartScreen walkthrough ---------- */
  const mock = document.querySelector("[data-ss]");
  if (mock) {
    const steps = [...document.querySelectorAll("[data-ss-step]")];
    const more = mock.querySelector("[data-ss-more]");
    const run = mock.querySelector("[data-ss-run]");
    let timers = [];
    const later = (ms, fn) => timers.push(window.setTimeout(fn, ms));
    const clear = () => {
      timers.forEach(window.clearTimeout);
      timers = [];
    };
    const mark = (n) => steps.forEach((li) => li.classList.toggle("is-active", Number(li.dataset.ssStep) === n));
    const pointAt = (el) => {
      const m = mock.getBoundingClientRect();
      const r = el.getBoundingClientRect();
      mock.style.setProperty("--cx", `${r.left - m.left + Math.min(r.width * 0.5, 40)}px`);
      mock.style.setProperty("--cy", `${r.top - m.top + r.height * 0.55}px`);
    };
    const click = () => {
      mock.classList.remove("is-clicking");
      void mock.offsetWidth;
      mock.classList.add("is-clicking");
    };
    const play = () => {
      clear();
      mock.dataset.state = "a";
      mark(1);
      if (reduceMotion.matches) {
        // No pointer movement: step through the states with pauses instead.
        later(1600, () => ((mock.dataset.state = "b"), mark(2)));
        later(3600, () => ((mock.dataset.state = "c"), mark(3)));
        return;
      }
      mock.classList.remove("has-cursor");
      const m = mock.getBoundingClientRect();
      mock.style.setProperty("--cx", `${m.width * 0.82}px`);
      mock.style.setProperty("--cy", `${m.height * 1.05}px`);
      later(500, () => mock.classList.add("has-cursor"));
      later(900, () => pointAt(more));
      later(2000, () => {
        click();
        mock.dataset.state = "b";
        mark(2);
      });
      later(3300, () => pointAt(run));
      later(4400, () => {
        click();
        mock.dataset.state = "c";
        mark(3);
      });
      later(6200, () => mock.classList.remove("has-cursor"));
    };
    if ("IntersectionObserver" in window) {
      const io = new IntersectionObserver(
        (entries) => {
          if (entries.some((en) => en.isIntersecting)) {
            io.disconnect();
            later(400, play);
          }
        },
        { threshold: 0.6 }
      );
      io.observe(mock);
    } else {
      mock.dataset.state = "b";
    }
    document.querySelector("[data-ss-replay]")?.addEventListener("click", play);
  }

  /* ---------- Privacy: table-of-contents scroll-spy and reading progress ---------- */
  const toc = document.querySelector(".toc");
  if (toc) {
    const links = [...toc.querySelectorAll('a[href^="#"]')];
    const targets = links.map((a) => document.getElementById(a.getAttribute("href").slice(1))).filter(Boolean);
    const bar = toc.querySelector(".toc-progress span");
    const prose = document.querySelector(".prose");
    let ticking = false;
    const update = () => {
      ticking = false;
      const line = window.innerHeight * 0.3;
      let current = targets[0];
      targets.forEach((t) => {
        if (t.getBoundingClientRect().top <= line) current = t;
      });
      // At the very bottom, the last section is current even if it is short.
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) current = targets[targets.length - 1];
      links.forEach((a) => a.setAttribute("aria-current", String(a.getAttribute("href") === `#${current?.id}`)));
      if (bar && prose) {
        const r = prose.getBoundingClientRect();
        const p = Math.min(1, Math.max(0, (line - r.top) / Math.max(1, r.height - line)));
        bar.style.setProperty("--p", p.toFixed(3));
      }
    };
    const onScroll = () => {
      if (!ticking) {
        ticking = true;
        window.requestAnimationFrame(update);
      }
    };
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
  }

  /* ---------- Downloads: local sub-nav scroll-spy ---------- */
  const subnav = document.querySelector(".subnav");
  if (subnav && "IntersectionObserver" in window) {
    const links = [...subnav.querySelectorAll('a[href^="#"]')];
    const map = new Map(links.map((a) => [a.getAttribute("href").slice(1), a]));
    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          links.forEach((a) => a.setAttribute("aria-current", String(a === map.get(entry.target.id))));
          const active = map.get(entry.target.id);
          const ul = subnav.querySelector("ul");
          if (active && ul && ul.scrollWidth > ul.clientWidth) {
            ul.scrollTo({ left: active.offsetLeft - 16, behavior: reduceMotion.matches ? "auto" : "smooth" });
          }
        });
      },
      { rootMargin: "-40% 0px -55% 0px" }
    );
    map.forEach((_, id) => {
      const el = document.getElementById(id);
      if (el) spy.observe(el);
    });
  }
})();
