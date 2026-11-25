/* Keystore Studio website — landing page section behaviour.
   Sticky tour screenshot swapper, scroll-driven window tilt, hero parallax, count-up stats,
   the Convert command demo and the interop terminal. Transform and opacity only.
   `?static` renders every animated element in its final state (for screenshots and audits). */
(() => {
  "use strict";

  const root = document.documentElement;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const isStatic = new URLSearchParams(location.search).has("static");
  const hasIO = "IntersectionObserver" in window;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);

  if (isStatic) {
    root.classList.add("is-static");
    document.querySelectorAll(".reveal, .reveal-scale, .term[data-term]").forEach((el) => el.classList.add("is-in"));
  }

  /* ---------- Commands wrap between words, never at a flag's hyphen ---------- */
  const tokenize = (el, text = el.textContent) => {
    el.textContent = "";
    text.split(" ").forEach((word, i) => {
      if (i) el.append(" ");
      const tok = document.createElement("span");
      tok.className = "tok";
      tok.textContent = word;
      el.append(tok);
    });
  };
  document.querySelectorAll(".compare-cli code, [data-cmd-demo] code").forEach((el) => tokenize(el));

  /* ---------- Interop terminal: stagger lines ---------- */
  document.querySelectorAll(".term[data-term]").forEach((term) => {
    term.querySelectorAll(".t-line").forEach((line, i) => line.style.setProperty("--l", String(i)));
  });

  /* ---------- Scroll-driven effects (tilt + parallax) ---------- */
  const tilts = [...document.querySelectorAll("[data-tilt]")];
  const parallax = [...document.querySelectorAll("[data-parallax]")];
  const animated = !reduce && !isStatic;

  if (!animated) {
    tilts.forEach((el) => el.style.setProperty("--p", "1"));
  } else {
    const visible = new Set();
    let ticking = false;

    const update = () => {
      ticking = false;
      const vh = window.innerHeight || 1;
      visible.forEach((el) => {
        if (el.hasAttribute("data-tilt")) {
          const r = el.getBoundingClientRect();
          // 0 when the window's top edge enters at the bottom; 1 once it reaches ~35% of the viewport.
          const p = clamp((vh - r.top) / (vh * 0.65), 0, 1);
          el.style.setProperty("--p", easeOut(p).toFixed(4));
        } else {
          const k = parseFloat(el.dataset.parallax) || 0;
          const r = el.parentElement.getBoundingClientRect();
          const offset = (r.top + r.height / 2 - vh / 2) * k;
          el.style.transform = `translate3d(0, ${offset.toFixed(1)}px, 0)`;
        }
      });
    };
    const request = () => {
      if (!ticking) {
        ticking = true;
        requestAnimationFrame(update);
      }
    };

    if (hasIO) {
      const io = new IntersectionObserver(
        (entries) => {
          entries.forEach((e) => (e.isIntersecting ? visible.add(e.target) : visible.delete(e.target)));
          request();
        },
        { rootMargin: "25% 0px 25% 0px" }
      );
      [...tilts, ...parallax].forEach((el) => io.observe(el));
    } else {
      [...tilts, ...parallax].forEach((el) => visible.add(el));
    }
    // Initial state before the observer reports, so nothing pops on first paint.
    tilts.forEach((el) => visible.add(el));
    update();
    tilts.forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.top > window.innerHeight * 1.25 || r.bottom < -window.innerHeight * 0.25) visible.delete(el);
    });
    window.addEventListener("scroll", request, { passive: true });
    window.addEventListener("resize", request, { passive: true });
  }

  /* ---------- Sticky tour: swap the screenshot as steps scroll by ---------- */
  const tour = document.querySelector("[data-tour]");
  if (tour) {
    const steps = [...tour.querySelectorAll(".tour-step")];
    const frames = [...tour.querySelectorAll(".tour-frame")];
    const dots = [...tour.querySelectorAll(".tour-dots li")];
    const title = tour.querySelector("[data-tour-title]");
    let current = -1;

    const activate = (i) => {
      if (i === current) return;
      current = i;
      steps.forEach((s, n) => s.classList.toggle("is-active", n === i));
      frames.forEach((f, n) => f.classList.toggle("is-active", n === i));
      dots.forEach((d, n) => {
        d.classList.toggle("is-active", n === i);
        d.classList.toggle("is-done", n < i);
      });
      if (title) title.textContent = `Keystore Studio — ${steps[i].dataset.title}`;
    };
    activate(0);

    if (hasIO && !isStatic) {
      const io = new IntersectionObserver(
        (entries) => {
          entries.forEach((e) => {
            if (e.isIntersecting) activate(steps.indexOf(e.target));
          });
        },
        { rootMargin: "-48% 0px -48% 0px" }
      );
      steps.forEach((s) => io.observe(s));
    }
  }

  /* ---------- Count-up stats ---------- */
  const counters = [...document.querySelectorAll("[data-count]")];
  if (animated && hasIO) {
    const run = (el) => {
      const to = parseFloat(el.dataset.count);
      const from = parseFloat(el.dataset.from || "0");
      const dur = 1400;
      const start = performance.now();
      const step = (now) => {
        const t = clamp((now - start) / dur, 0, 1);
        const v = from + (to - from) * (1 - Math.pow(2, -10 * t));
        el.textContent = String(Math.round(t >= 1 ? to : v));
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    };
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (!e.isIntersecting) return;
          io.unobserve(e.target);
          run(e.target);
        });
      },
      { threshold: 0.6 }
    );
    counters.forEach((el) => {
      el.textContent = el.dataset.from || "0";
      io.observe(el);
    });
  }

  /* ---------- Convert demo: the keytool command for each target format (mirrors src/lib/convert.ts) ---------- */
  const demo = document.querySelector("[data-cmd-demo]");
  if (demo) {
    const code = demo.querySelector("code");
    const radios = [...demo.querySelectorAll('[role="radio"]')];
    const EXT = { PKCS12: "p12", JKS: "jks", JCEKS: "jceks", BKS: "bks", UBER: "uber", BCFKS: "bcfks" };
    const BC = ["BKS", "UBER", "BCFKS"];
    const BC_FLAGS = " -providerpath bcprov.jar -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider";
    const command = (type) =>
      `keytool -importkeystore -srckeystore partner-truststore.jks -srcstoretype JKS -destkeystore partner-truststore.${EXT[type]} -deststoretype ${type}${
        BC.includes(type) ? BC_FLAGS : ""
      }`;

    const select = (btn, focus) => {
      radios.forEach((r) => {
        const on = r === btn;
        r.setAttribute("aria-checked", String(on));
        r.tabIndex = on ? 0 : -1;
      });
      if (focus) btn.focus();
      demo.classList.add("is-swapping");
      window.setTimeout(
        () => {
          tokenize(code, command(btn.dataset.type));
          demo.classList.remove("is-swapping");
        },
        reduce ? 0 : 120
      );
    };
    radios.forEach((r, i) => {
      r.tabIndex = i === 0 ? 0 : -1;
      r.addEventListener("click", () => select(r, false));
      r.addEventListener("keydown", (e) => {
        const dir = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
        if (!dir) return;
        e.preventDefault();
        select(radios[(i + dir + radios.length) % radios.length], true);
      });
    });
  }
})();
