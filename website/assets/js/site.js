/* Keystore Studio website — shared behaviour for every page.
   Theme (system / light / dark), nav state, mobile menu, reveal-on-scroll, scroll-spy, copy buttons.
   The theme is first applied by the inline script in <head> to avoid a flash; this file keeps it in sync. */
(() => {
  "use strict";

  const root = document.documentElement;
  const KEY = "ks-theme";
  const CONSENT_KEY = "ks-consent";
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  /* ---------- Theme ---------- */
  const readPref = () => {
    try {
      const v = localStorage.getItem(KEY);
      return v === "light" || v === "dark" ? v : "system";
    } catch {
      return "system";
    }
  };
  const readConsent = () => {
    try {
      return localStorage.getItem(CONSENT_KEY);
    } catch {
      return null;
    }
  };
  // The theme choice is stored only once the visitor has accepted; "system" is the default, so it stores nothing.
  const savePref = (pref) => {
    try {
      if (pref === "system" || readConsent() !== "accepted") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, pref);
    } catch {
      /* storage unavailable: theme still applies for this page view */
    }
  };
  const resolved = (pref) => (pref === "system" ? (media.matches ? "dark" : "light") : pref);

  const applyTheme = (pref) => {
    root.dataset.themePref = pref;
    if (pref === "system") delete root.dataset.theme;
    else root.dataset.theme = pref;
    const mode = resolved(pref);
    const meta = document.querySelector('meta[name="theme-color"]:not([media])');
    if (meta) meta.setAttribute("content", mode === "dark" ? "#000000" : "#fbfbfd");
    document.querySelectorAll(".theme-toggle").forEach((btn) => {
      const next = { system: "light", light: "dark", dark: "system" }[pref];
      btn.setAttribute("aria-label", `Theme: ${pref}. Switch to ${next}.`);
      btn.title = `Theme: ${pref[0].toUpperCase()}${pref.slice(1)}`;
    });
    window.dispatchEvent(new CustomEvent("ks:theme", { detail: { pref, mode } }));
  };

  applyTheme(readPref());
  media.addEventListener("change", () => {
    if (readPref() === "system") applyTheme("system");
  });

  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".theme-toggle");
    if (!btn) return;
    // Cycle from the applied preference, so the toggle still works when storage is blocked.
    const next = { system: "light", light: "dark", dark: "system" }[root.dataset.themePref || readPref()];
    savePref(next);
    root.classList.add("theme-switching");
    applyTheme(next);
    window.setTimeout(() => root.classList.remove("theme-switching"), 400);
  });

  /* ---------- Cookie consent: shown until the visitor accepts or declines ---------- */
  if (!["accepted", "declined"].includes(readConsent())) {
    const privacy = new URL("../../privacy/#website", document.currentScript.src).href;
    const box = document.createElement("section");
    box.className = "consent";
    box.setAttribute("aria-label", "Cookie consent");
    box.innerHTML = `
      <p>No tracking cookies. May we remember your theme in this browser? <a class="text-link" href="${privacy}">Privacy</a></p>
      <div class="consent-actions">
        <button class="btn btn-sm" type="button" data-consent="accepted">Accept</button>
        <button class="btn btn-sm btn-secondary" type="button" data-consent="declined">Decline</button>
      </div>`;
    box.addEventListener("click", (e) => {
      const choice = e.target.closest("[data-consent]")?.dataset.consent;
      if (!choice) return;
      try {
        localStorage.setItem(CONSENT_KEY, choice);
      } catch {
        /* storage unavailable: the banner returns on the next page */
      }
      savePref(root.dataset.themePref);
      box.remove();
    });
    document.body.append(box);
  }

  /* ---------- Nav: scrolled state + mobile menu ---------- */
  const nav = document.querySelector(".nav");
  if (nav) {
    const onScroll = () => nav.classList.toggle("is-scrolled", window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });

    const menuBtn = nav.querySelector(".nav-menu-btn");
    const setOpen = (open) => {
      nav.classList.toggle("is-open", open);
      if (menuBtn) menuBtn.setAttribute("aria-expanded", String(open));
    };
    menuBtn?.addEventListener("click", () => setOpen(!nav.classList.contains("is-open")));
    nav.querySelectorAll(".nav-links a").forEach((a) => a.addEventListener("click", () => setOpen(false)));
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && nav.classList.contains("is-open")) {
        setOpen(false);
        menuBtn?.focus();
      }
    });
  }

  /* ---------- Reveal on scroll ---------- */
  const revealEls = document.querySelectorAll(".reveal, .reveal-scale");
  if (!("IntersectionObserver" in window) || reduceMotion.matches) {
    revealEls.forEach((el) => el.classList.add("is-in"));
  } else {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-in");
            io.unobserve(entry.target);
          }
        });
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 }
    );
    revealEls.forEach((el) => io.observe(el));
  }

  /* ---------- Scroll-spy for in-page nav links ---------- */
  const spyLinks = [...document.querySelectorAll('.nav-links a[href^="#"]')];
  const spyTargets = spyLinks
    .map((a) => document.getElementById(a.getAttribute("href").slice(1)))
    .filter(Boolean);
  if (spyTargets.length && "IntersectionObserver" in window) {
    const spy = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          spyLinks.forEach((a) =>
            a.setAttribute("aria-current", String(a.getAttribute("href") === `#${entry.target.id}`))
          );
        });
      },
      { rootMargin: "-45% 0px -50% 0px" }
    );
    spyTargets.forEach((t) => spy.observe(t));
  }

  /* ---------- Copy buttons: <button data-copy="text"> or data-copy-target="#id" ---------- */
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-copy], [data-copy-target]");
    if (!btn) return;
    const text = btn.dataset.copy ?? document.querySelector(btn.dataset.copyTarget)?.textContent?.trim() ?? "";
    try {
      await navigator.clipboard.writeText(text);
      btn.classList.add("is-copied");
      const label = btn.querySelector("[data-copy-label]");
      const prev = label?.textContent;
      if (label) label.textContent = "Copied";
      window.setTimeout(() => {
        btn.classList.remove("is-copied");
        if (label && prev) label.textContent = prev;
      }, 1600);
    } catch {
      /* clipboard blocked: leave the text selectable */
    }
  });

  /* ---------- Current year ---------- */
  document.querySelectorAll("[data-year]").forEach((el) => (el.textContent = String(new Date().getFullYear())));

  /* ---------- Platform hint: [data-os-hint] gets the visitor's OS name ---------- */
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? "windows" : /Mac OS X|Macintosh/i.test(ua) ? "macos" : /Linux/i.test(ua) ? "linux" : "other";
  root.dataset.os = os;
})();
