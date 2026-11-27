/* Keystore Studio website — behaviour for the secondary pages (downloads, privacy).
   Loaded after site.js, which sets :root[data-os] and handles theme, nav, reveal and copy buttons. */
(() => {
  "use strict";

  const root = document.documentElement;
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

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
      if (detected) note.textContent = `We've picked ${OS_NAMES[detected]} for you.${detected === "linux" ? " There's no package yet, so here's how to build one." : ""}`;
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
