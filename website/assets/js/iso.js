/* Keystore Studio website — interactive isometric scenes.
   Every <div class="iso-scene" data-scene="NAME"></div> on the page is built here with real CSS 3D
   (preserve-3d cuboids, true isometric camera: rotateX(54.7356deg) rotateZ(45deg)).
   Faces are coloured with the theme tokens from base.css, so theme switches need no re-render.

   Scenes: hero, formats, convert, audit, vault, local, platforms, apps, changelog, feedback.
   API: window.KSIso = { mount(el), mountAll(root?) }. */
(() => {
  "use strict";

  const ISO_X = 54.7356; /* arctan(sqrt 2): true isometric tilt */
  const ISO_Z = 45;
  const D2R = Math.PI / 180;
  const docEl = document.documentElement;
  const mqReduce = window.matchMedia("(prefers-reduced-motion: reduce)");
  const mqCoarse = window.matchMedia("(hover: none), (pointer: coarse)");
  const reduced = () => mqReduce.matches || docEl.dataset.isoMotion === "reduce";
  const coarse = () => mqCoarse.matches;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const lerp = (a, b, t) => a + (b - a) * t;
  const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
  const easeOut = (t) => 1 - Math.pow(1 - t, 3);
  const r2 = (n) => Math.round(n * 100) / 100;
  const px = (n) => `${r2(n)}px`;
  const t3 = (x, y, z) => `translate3d(${px(x)},${px(y)},${px(z)})`;

  let lastPointer = "mouse";
  document.addEventListener("pointerdown", (e) => (lastPointer = e.pointerType || "mouse"), { capture: true, passive: true });

  /* ---------- DOM helpers ---------- */
  function h(tag, cls, parent, attrs) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (attrs) {
      for (const k in attrs) {
        if (k === "text") e.textContent = attrs[k];
        else if (k === "style") e.style.cssText = attrs[k];
        else e.setAttribute(k, attrs[k]);
      }
    }
    if (parent) parent.appendChild(e);
    return e;
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, parent) {
    const e = document.createElementNS(SVGNS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }

  /* World -> screen, relative to the camera origin. x right-down, y left-down, z up. */
  function project(x, y, z, rx = ISO_X, rz = ISO_Z) {
    const c = Math.cos(rz * D2R);
    const sn = Math.sin(rz * D2R);
    const x1 = x * c - y * sn;
    const y1 = x * sn + y * c;
    return [x1, y1 * Math.cos(rx * D2R) - z * Math.sin(rx * D2R)];
  }

  /* ---------- Geometry: groups, planes and cuboids ---------- */
  function group(parent, cls, x = 0, y = 0, z = 0) {
    const g = h("div", `iso-g${cls ? " " + cls : ""}`, parent);
    if (x || y || z) g.style.transform = t3(x, y, z);
    return g;
  }
  /* A flat rectangle lying in the floor plane (xy) at height z. */
  function plane(parent, { x = 0, y = 0, z = 0, w, d, cls = "" }) {
    const p = h("div", `iso-plane ${cls}`, parent);
    p.style.width = px(w);
    p.style.height = px(d);
    p.style.transform = t3(x, y, z);
    return p;
  }

  /* Face transforms for a w (x) by d (y) by h (z) box whose min corner is the local origin.
     Each face element is laid out at (0,0) with transform-origin 0 0 and its outward normal
     pointing away from the box, so backface-visibility hides the faces that look away. */
  const FACE = {
    top: (w, d, hh) => [w, d, `translate3d(0,0,${px(hh)})`],
    bottom: (w, d) => [w, d, `translate3d(0,${px(d)},0) rotateX(180deg)`],
    front: (w, d, hh) => [w, hh, `translate3d(0,${px(d)},${px(hh)}) rotateX(-90deg)`],
    back: (w, d, hh) => [w, hh, `translate3d(${px(w)},0,${px(hh)}) rotateX(-90deg) rotateY(180deg)`],
    right: (w, d, hh) => [d, hh, `translate3d(${px(w)},${px(d)},${px(hh)}) rotateZ(-90deg) rotateX(-90deg)`],
    left: (w, d, hh) => [d, hh, `translate3d(0,0,${px(hh)}) rotateZ(90deg) rotateX(-90deg)`],
  };

  /* cuboid({w,d,h,x,y,z,cls,faces}) -> { el, f: {top, front, right, ...}, w, d, h }
     faces: space-separated subset of "top bottom front back left right". The default
     "top front right" is what the isometric camera sees (front = +y, screen left; right = +x). */
  function cuboid(parent, { w, d, h: hh, x = 0, y = 0, z = 0, cls = "", faces = "top front right" }) {
    const el = h("div", `iso-g iso-box${cls ? " " + cls : ""}`, parent);
    el.style.transform = t3(x, y, z);
    const f = {};
    for (const name of faces.split(/\s+/)) {
      if (!FACE[name]) continue;
      const [fw, fh, tr] = FACE[name](w, d, hh);
      const fe = h("div", `iso-f f-${name}`, el);
      fe.style.width = px(fw);
      fe.style.height = px(fh);
      fe.style.transform = tr;
      f[name] = fe;
    }
    return { el, f, w, d, h: hh };
  }

  /* Text printed on a face. rot -90 on a top face reads up-right along -y. */
  function faceText(face, text, cls, rot = 0) {
    const wrap = h("div", `iso-ft${cls ? " " + cls : ""}`, face);
    if (rot) {
      const w = parseFloat(face.style.width);
      const hh = parseFloat(face.style.height);
      if (Math.abs(rot) === 90) {
        wrap.style.width = px(hh);
        wrap.style.height = px(w);
        wrap.style.left = px((w - hh) / 2);
        wrap.style.top = px((hh - w) / 2);
      }
      wrap.style.transform = `rotate(${rot}deg)`;
    }
    if (text != null) h("span", "", wrap, { text });
    return wrap;
  }

  /* ---------- Motion helpers ---------- */
  function spring(st, target, dt, k = 170, c = 20) {
    if (reduced()) {
      st.x = target;
      st.v = 0;
      return false;
    }
    const n = Math.max(1, Math.ceil(dt / 0.006));
    const step = dt / n;
    for (let i = 0; i < n; i++) {
      const a = -k * (st.x - target) - c * st.v;
      st.v += a * step;
      st.x += st.v * step;
    }
    if (Math.abs(st.x - target) < 1e-4 && Math.abs(st.v) < 1e-4) {
      st.x = target;
      st.v = 0;
      return false;
    }
    return true;
  }
  /* Unit step response of a damped spring (omega 12.2, zeta 0.62): slight overshoot, settled by ~1s. */
  function springAt(t) {
    const w = 12.2;
    const z = 0.62;
    const wd = w * Math.sqrt(1 - z * z);
    return 1 - Math.exp(-z * w * t) * (Math.cos(wd * t) + ((z * w) / wd) * Math.sin(wd * t));
  }
  const follow = (cur, target, dt, rate) => (reduced() ? target : target + (cur - target) * Math.exp(-rate * dt));

  /* One "hot" item per scene: mouse hover with a short grace period, tap toggles on touch. */
  function hotSet(apply) {
    let cur = null;
    let timer = 0;
    const set = (it) => {
      clearTimeout(timer);
      if (it === cur) return;
      const prev = cur;
      cur = it;
      apply(it, prev);
    };
    return {
      get cur() {
        return cur;
      },
      set,
      bind(el, it) {
        el.addEventListener("pointerenter", (e) => {
          if (e.pointerType !== "touch") set(it);
        });
        el.addEventListener("pointerleave", (e) => {
          if (e.pointerType === "touch") return;
          clearTimeout(timer);
          timer = setTimeout(() => set(null), 140);
        });
        el.addEventListener("click", () => {
          if (lastPointer === "touch") set(cur === it ? null : it);
        });
      },
    };
  }

  /* ---------- Frame loop (shared), paused offscreen and in hidden tabs ---------- */
  const scenes = new Set();
  const live = new Set();
  let raf = 0;
  let last = 0;
  function frame(now) {
    const dt = clamp((now - last) / 1000, 0.001, 0.1);
    last = now;
    const t = now / 1000;
    for (const sc of live) {
      let keep = false;
      try {
        keep = sc.tick(t, dt);
      } catch (err) {
        console.error(err);
      }
      if (!keep || !sc.visible || document.hidden) live.delete(sc);
    }
    raf = live.size ? requestAnimationFrame(frame) : 0;
  }
  function wake(sc) {
    if (!sc || !sc.tick || !sc.visible || document.hidden) return;
    live.add(sc);
    if (!raf) {
      last = performance.now();
      raf = requestAnimationFrame(frame);
    }
  }
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) scenes.forEach(wake);
  });
  const onMotionChange = () => scenes.forEach((sc) => (sc.onMotion ? sc.onMotion() : wake(sc)));
  mqReduce.addEventListener?.("change", onMotionChange);

  const io =
    "IntersectionObserver" in window
      ? new IntersectionObserver(
          (entries) => {
            for (const e of entries) {
              const sc = e.target.__iso;
              if (!sc) continue;
              sc.visible = e.isIntersecting;
              sc.root.classList.toggle("is-off", !sc.visible);
              if (sc.visible) {
                if (!sc.entered && e.intersectionRatio > 0) {
                  sc.entered = true;
                  sc.onEnter && sc.onEnter();
                }
                wake(sc);
              }
            }
          },
          { rootMargin: "60px 0px", threshold: [0, 0.15] }
        )
      : null;

  /* ---------- Scene scaffold ---------- */
  function base(root, { W, H, ox, oy, label, role = "img", topCompact = false }) {
    root.textContent = "";
    root.classList.add("iso-scene", "is-ready");
    root.setAttribute("role", role);
    root.setAttribute("aria-label", root.dataset.label || label);
    const stage = h("div", "iso-stage", root);
    stage.style.width = px(W);
    stage.style.height = px(H);
    const cam = h("div", "iso-cam", stage);
    cam.style.left = px(ox);
    cam.style.top = px(oy);
    const ui = h("div", "iso-ui", root, { "aria-hidden": "true" });
    const S = { root, stage, cam, ui, W, H, ox, oy, k: 1, dx: 0, dy: 0, rx: ISO_X, rz: ISO_Z, visible: !io, entered: false };
    S.at = (x, y, z) => {
      const p = project(x, y, z, S.rx, S.rz);
      return [S.ox + p[0], S.oy + p[1]];
    };
    /* Screen position (CSS px inside the scene box) of a world point. */
    S.screen = (x, y, z) => {
      const [a, b] = S.at(x, y, z);
      return [S.dx + a * S.k, S.dy + b * S.k];
    };
    S.pin = (el, x, y, z) => {
      const [a, b] = S.screen(x, y, z);
      el.style.transform = `translate3d(${px(a)},${px(b)},0)`;
      return [a, b];
    };
    S.setCam = () => (cam.style.transform = `rotateX(${r2(S.rx)}deg) rotateZ(${r2(S.rz)}deg)`);
    S.setCam();
    S.topCompact = !!topCompact;
    const fit = () => {
      const cw = root.clientWidth;
      if (!cw) return;
      const compact = cw < 560;
      root.classList.toggle("is-compact", compact);
      const ch = root.clientHeight || (cw * H) / W;
      const k = Math.min(cw / W, ch / H);
      S.k = k;
      S.cw = cw;
      S.ch = ch;
      S.dx = (cw - W * k) / 2;
      S.dy = compact && S.topCompact ? 0 : (ch - H * k) / 2;
      stage.style.transform = `translate(${px(S.dx)},${px(S.dy)}) scale(${k.toFixed(5)})`;
      S.layout && S.layout();
    };
    S.fit = fit;
    if ("ResizeObserver" in window) new ResizeObserver(fit).observe(root);
    else window.addEventListener("resize", fit);
    fit();
    return S;
  }

  /* A floating label card in the unscaled UI layer (real px text, never squashed). */
  function card(S, cls, html) {
    const pin = h("div", "iso-pin", S.ui);
    const c = h("div", `iso-card ${cls || ""}`, pin);
    c.innerHTML = html;
    return { pin, c };
  }
  /* Keep a pinned card inside the scene box horizontally (no overflow at 320px). */
  function clampPin(S, pin, c, ax, ay, align = "left", gap = 12) {
    const w = c.offsetWidth || 160;
    ay = Math.max(ay, (c.offsetHeight || 40) + 4);
    let x;
    if (align === "center") x = ax - w / 2;
    else if (align === "right") x = ax - w - gap;
    else x = ax + gap;
    x = clamp(x, 6, Math.max(6, (S.cw || S.W) - w - 6));
    pin.style.transform = `translate3d(${px(x)},${px(ay)},0)`;
  }

  /* =====================================================================
     1. HERO — the app icon, rebuilt in 3D: an open hexagonal frame of two
        L-shaped beams holding three slabs (key pair, certificate, secret key).
     ===================================================================== */
  function hero(root) {
    const S = base(root, {
      W: 720,
      H: 640,
      ox: 336,
      oy: 446,
      role: "group",
      label: "Keystore Studio: a keystore frame holding three entries — a key pair, a trusted certificate and a secret key",
    });
    const world = group(S.cam, "iso-hero");
    const shadow = plane(world, { x: -330, y: -330, z: -2, w: 660, d: 660, cls: "iso-shadow" });
    const ring = plane(world, { x: -250, y: -250, z: -1, w: 500, d: 500, cls: "iso-hero-ring" });
    shadow.setAttribute("aria-hidden", "true");
    ring.setAttribute("aria-hidden", "true");

    const T = 50;
    const beam = "is-ink is-beam";
    const L1 = group(world, "iso-part");
    const L2 = group(world, "iso-part");
    L1.setAttribute("aria-hidden", "true");
    L2.setAttribute("aria-hidden", "true");
    /* Back L: top-back rail, stub along the top-left edge, right post. */
    cuboid(L1, { x: -150, y: -150, z: 250, w: 300, d: T, h: T, cls: beam });
    cuboid(L1, { x: -150, y: -100, z: 250, w: T, d: T, h: T, cls: beam });
    cuboid(L1, { x: 100, y: -150, z: 0, w: T, d: T, h: 250, cls: beam, faces: "front right" });
    /* Front L: left post and bottom-front rail. */
    cuboid(L2, { x: -150, y: 100, z: 50, w: T, d: T, h: 250, cls: beam });
    cuboid(L2, { x: -150, y: 100, z: 0, w: 300, d: T, h: T, cls: beam });

    const SL = [
      { c: 66, ink: true, title: "Key pair", meta: "RSA 4096 · SHA-256", tag: "RSA 4096", aria: "Key pair, RSA 4096" },
      { c: 0, ink: false, title: "Trusted certificate", meta: "Expires in 212 days", dot: "ok", tag: "X.509", aria: "Trusted certificate, expires in 212 days" },
      { c: -66, ink: true, title: "Secret key", meta: "AES-256", tag: "AES-256", aria: "Secret key, AES-256" },
    ];
    const SW = 156;
    const SD = 22;
    const SZ = 72;
    const OUT = 122;
    const slabs = SL.map((d, i) => {
      const g = group(world, "iso-slab");
      g.setAttribute("role", "button");
      g.setAttribute("tabindex", "0");
      g.setAttribute("aria-pressed", "false");
      g.setAttribute("aria-label", `${d.aria}. Slide out`);
      const hit = h("div", "iso-hit", g);
      hit.style.width = px(SW);
      hit.style.height = px(SW);
      hit.style.transform = `translate3d(${px(-SW / 2)},${px(SD / 2)},${px(SZ + SW)}) rotateX(-90deg)`;
      const mv = group(g, "iso-slab-mv");
      const box = cuboid(mv, { x: -SW / 2, y: -SD / 2, z: SZ, w: SW, d: SD, h: SW, cls: d.ink ? "is-ink" : "is-paper" });
      /* Engraving on the face: an index tab rule and the entry's type. */
      h("div", "iso-slab-rule", box.f.front);
      const tg = h("div", "iso-slab-tag", box.f.front, { text: d.tag });
      if (d.dot) h("i", `iso-slab-dot ${d.dot}`, tg);
      const cd = card(
        S,
        "iso-card-hero",
        `<div class="iso-card-k">${d.title}</div><div class="iso-card-v">${d.dot ? `<span class="dot"></span>` : ""}${d.meta}</div>`
      );
      return { ...d, i, g, mv, out: { x: 0, v: 0 }, pressed: false, hover: false, focus: false, cd, intro: { x: 0, v: 0 } };
    });

    let current = null;
    const setCurrent = (sl) => {
      current = sl;
      wake(S);
    };
    const want = (sl) => sl.pressed || sl.hover || sl.focus;
    slabs.forEach((sl) => {
      let leaveT = 0;
      sl.g.addEventListener("pointerenter", (e) => {
        if (e.pointerType === "touch") return;
        clearTimeout(leaveT);
        sl.hover = true;
        setCurrent(sl);
      });
      sl.g.addEventListener("pointerleave", (e) => {
        if (e.pointerType === "touch") return;
        clearTimeout(leaveT);
        leaveT = setTimeout(() => {
          sl.hover = false;
          if (current === sl && !want(sl)) current = slabs.find((o) => o !== sl && want(o)) || null;
          wake(S);
        }, 160);
      });
      const toggle = () => {
        sl.pressed = !sl.pressed;
        sl.g.setAttribute("aria-pressed", String(sl.pressed));
        if (sl.pressed) setCurrent(sl);
        else {
          if (lastPointer === "touch") sl.hover = false;
          if (current === sl && !want(sl)) current = slabs.find((o) => o !== sl && want(o)) || null;
          wake(S);
        }
      };
      sl.g.addEventListener("click", toggle);
      sl.g.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          toggle();
        }
      });
      sl.g.addEventListener("focus", () => {
        sl.focus = true;
        if (sl.g.matches(":focus-visible")) setCurrent(sl);
        else sl.focus = false;
      });
      sl.g.addEventListener("blur", () => {
        sl.focus = false;
        if (current === sl && !want(sl)) current = slabs.find((o) => want(o)) || null;
        wake(S);
      });
    });

    /* Intro: frame halves and slabs fly in and lock with a spring. */
    const parts = [
      { el: L1, off: [120, -120, 190], delay: 0, st: { x: 0, v: 0 } },
      { el: L2, off: [-120, 120, -70], delay: 0.07, st: { x: 0, v: 0 } },
    ];
    slabs.forEach((sl, i) => parts.push({ el: sl.g, slab: sl, off: [0, 0, 260], delay: 0.26 + i * 0.09, st: sl.intro }));
    let introT0 = null;
    let introDone = false;
    const finishIntro = () => {
      parts.forEach((p) => {
        p.st.x = 1;
        p.st.v = 0;
        p.el.style.removeProperty("--o");
      });
      shadow.style.removeProperty("--o");
      introDone = true;
    };

    /* Pointer tilt (fine pointers) */
    let pnx = 0;
    let pny = 0;
    window.addEventListener(
      "pointermove",
      (e) => {
        if (e.pointerType === "touch" || coarse() || !S.visible) return;
        const r = root.getBoundingClientRect();
        pnx = clamp((e.clientX - (r.left + r.width / 2)) / (r.width * 0.75), -1, 1);
        pny = clamp((e.clientY - (r.top + r.height / 2)) / (r.height * 0.75), -1, 1);
        wake(S);
      },
      { passive: true }
    );
    root.addEventListener("pointerleave", () => {
      pnx = pny = 0;
    });

    /* Scroll explode: progress through the parent section spreads the slabs apart. */
    const section = root.closest("section, header, [data-iso-section]") || root.parentElement;
    let scrollDirty = true;
    let exTarget = 0;
    let ex = 0;
    window.addEventListener(
      "scroll",
      () => {
        scrollDirty = true;
        wake(S);
      },
      { passive: true }
    );

    const apply = (t) => {
      S.setCam();
      for (const p of parts) {
        const u = p.st.x;
        const k = 1 - u;
        if (p.slab) continue;
        p.el.style.transform = t3(p.off[0] * k, p.off[1] * k, p.off[2] * k);
        if (!introDone) p.el.style.setProperty("--o", clamp(u * 1.8, 0, 1).toFixed(3));
      }
      for (const sl of slabs) {
        const u = sl.intro.x;
        const k = 1 - u;
        const sign = sl.c === 0 ? 0 : Math.sign(sl.c);
        const y = sl.c + sign * ex * 46;
        sl.g.style.transform = t3(0, y, 260 * k);
        if (!introDone) sl.g.style.setProperty("--o", clamp(u * 1.8, 0, 1).toFixed(3));
        const breathe = reduced() ? 0 : Math.sin(t * 1.35 + sl.i * 1.9) * 4.5 * u;
        const o = sl.out.x;
        sl.mv.style.transform = t3(o * OUT, 0, o * 10 + breathe);
        sl.g.classList.toggle("is-out", want(sl));
        sl.y = y;
        sl.zb = breathe;
      }
      if (!introDone) shadow.style.setProperty("--o", clamp(parts[0].st.x, 0, 1).toFixed(3));
      layoutCards();
    };
    const layoutCards = () => {
      for (const sl of slabs) {
        const on = sl === current && want(sl);
        sl.cd.pin.classList.toggle("is-on", on);
        if (!on && !sl.cd.pin.classList.contains("was-on")) continue;
        sl.cd.pin.classList.toggle("was-on", on);
        const o = sl.out.x;
        const [ax, ay] = S.screen(SW / 2 + o * OUT, sl.y + SD / 2, SZ + SW + o * 10 + sl.zb);
        clampPin(S, sl.cd.pin, sl.cd.c, ax, ay, "left", 14);
      }
    };
    S.layout = () => apply(performance.now() / 1000);

    S.onEnter = () => {
      if (reduced()) finishIntro();
      else introT0 = null;
      wake(S);
      /* Safety net: if frames are starved (throttled tab, embedded frame), never leave the mark hidden. */
      setTimeout(() => {
        if (!introDone) {
          finishIntro();
          apply(performance.now() / 1000);
        }
      }, 2600);
    };
    S.onMotion = () => {
      if (reduced()) {
        finishIntro();
        S.rx = ISO_X;
        S.rz = ISO_Z;
        ex = exTarget = 0;
      }
      wake(S);
    };
    S.tick = (t, dt) => {
      let busy = false;
      if (!introDone) {
        if (reduced()) finishIntro();
        else {
          if (introT0 == null) introT0 = t;
          /* Closed-form damped spring (time based, so dropped frames never stretch the intro). */
          let moving = false;
          for (const p of parts) {
            const e = t - introT0 - p.delay;
            if (e >= 1.05) p.st.x = 1;
            else {
              moving = true;
              p.st.x = e <= 0 ? 0 : springAt(e);
            }
          }
          if (!moving) finishIntro();
          busy = true;
        }
      }
      if (!reduced()) {
        let tz = 0;
        let tx = 0;
        if (coarse()) {
          tz = Math.sin(t * 0.32) * 4;
          tx = Math.sin(t * 0.21) * 1.5;
        } else {
          tz = pnx * 7;
          tx = -pny * 4;
        }
        S.rz = follow(S.rz, ISO_Z + tz, dt, 4.5);
        S.rx = follow(S.rx, ISO_X + tx, dt, 4.5);
        if (scrollDirty && section) {
          scrollDirty = false;
          const r = section.getBoundingClientRect();
          exTarget = clamp(-r.top / Math.max(1, r.height * 0.8), 0, 1);
        }
        ex = follow(ex, exTarget, dt, 7);
      }
      for (const sl of slabs) busy = spring(sl.out, want(sl) ? 1 : 0, dt, 210, 22) || busy;
      apply(t);
      return !reduced() || busy;
    };
    /* Initial pose (before the intro runs) */
    if (reduced()) finishIntro();
    apply(0);
    return S;
  }

  /* =====================================================================
     2. FORMATS — extruded format tiles on a plinth; a wave rolls through.
     ===================================================================== */
  function formats(root) {
    const LIST = [
      ["PKCS#12", "ks"],
      ["JKS", "ks"],
      ["JCEKS", "ks"],
      ["BKS", "ks"],
      ["UBER", "ks"],
      ["BCFKS", "ks"],
      ["PEM", "enc"],
      ["DER", "enc"],
      ["PKCS#7", "enc"],
      ["JWK", "enc"],
      ["OpenSSH", "enc"],
    ];
    const S = base(root, {
      W: 720,
      H: 470,
      ox: 360,
      oy: 262,
      label: `Supported formats: keystores ${LIST.filter((f) => f[1] === "ks").map((f) => f[0]).join(", ")}; files ${LIST.filter((f) => f[1] === "enc").map((f) => f[0]).join(", ")}`,
    });
    const COLS = 4;
    const ROWS = 3;
    const TS = 100;
    const P = 116;
    const M = 26;
    const gw = COLS * P - (P - TS);
    const gd = ROWS * P - (P - TS);
    const PH = 30;
    const world = group(S.cam, "iso-formats");
    plane(world, { x: -gw / 2 - 90, y: -gd / 2 - 90, z: -1, w: gw + 180, d: gd + 180, cls: "iso-shadow" });
    const plinth = cuboid(world, { x: -gw / 2 - M, y: -gd / 2 - M, z: 0, w: gw + 2 * M, d: gd + 2 * M, h: PH, cls: "iso-plinth" });
    h("div", "iso-groove", plinth.f.top);
    faceText(plinth.f.front, "READ · WRITE · CONVERT", "iso-engrave");
    faceText(plinth.f.right, "11 FORMATS", "iso-engrave");

    const tiles = [];
    let n = 0;
    for (let j = 0; j < ROWS; j++) {
      for (let i = 0; i < COLS; i++) {
        const x = -gw / 2 + i * P;
        const y = -gd / 2 + j * P;
        if (n >= LIST.length) {
          /* The empty twelfth socket: a recessed slot. */
          plane(world, { x, y, z: PH + 0.5, w: TS, d: TS, cls: "iso-socket" });
          continue;
        }
        const [name, kind] = LIST[n++];
        const g = group(world, "iso-tile", x, y, PH);
        const lift = group(g, "iso-lift");
        const b = cuboid(lift, { w: TS, d: TS, h: 24, cls: kind === "ks" ? "is-ink" : "is-paper-soft" });
        faceText(b.f.top, name, `iso-tl${name.length > 5 ? " is-long" : ""}`, -90);
        h("i", "iso-pip", b.f.top);
        tiles.push({ g, lift, i, j, x, y, name });
      }
    }
    const hot = hotSet((it, prev) => {
      prev && prev.g.classList.remove("is-hot");
      it && it.g.classList.add("is-hot");
    });
    tiles.forEach((tl) => hot.bind(tl.g, tl));

    const apply = (t) => {
      for (const tl of tiles) {
        let z = 0;
        if (!reduced()) {
          const ph = t * 1.25 - (tl.i + tl.j) * 0.62;
          const w = Math.max(0, Math.sin(ph));
          z = Math.pow(w, 3) * 14;
        }
        tl.g.style.transform = t3(tl.x, tl.y, PH + z);
      }
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    apply(0);
    return S;
  }

  /* =====================================================================
     3. CONVERT — a block rides a conveyor through a gate and leaves re-shaped.
     ===================================================================== */
  function convert(root) {
    const PAIRS = [
      {
        a: "JKS",
        af: "app.jks",
        b: "PKCS#12",
        bf: "app.p12",
        cmd: "keytool -importkeystore -srckeystore app.jks -srcstoretype JKS -destkeystore app.p12 -deststoretype PKCS12",
        ok: "Imported 3 entries · 0 skipped",
      },
      {
        a: "PKCS#12",
        af: "app.p12",
        b: "PEM",
        bf: "bundle.pem",
        cmd: "openssl pkcs12 -in app.p12 -out bundle.pem -noenc",
        ok: "Wrote key + 2 certificates",
      },
    ];
    const S = base(root, {
      W: 720,
      H: 500,
      ox: 372,
      oy: 250,
      topCompact: true,
      label: "Conversion pipeline: a JKS keystore passes through a gate and comes out as PKCS#12, with the equivalent keytool command",
    });
    const world = group(S.cam, "iso-convert");
    const L = 380;
    plane(world, { x: -L - 60, y: -150, z: -1, w: 2 * L + 120, d: 300, cls: "iso-shadow" });
    const baseB = cuboid(world, { x: -L, y: -60, z: 0, w: 2 * L, d: 120, h: 22, cls: "iso-rail" });
    h("div", "iso-bolts", baseB.f.front);
    h("div", "iso-bolts", baseB.f.right);
    const belt = cuboid(world, { x: -L + 22, y: -44, z: 22, w: 2 * L - 44, d: 88, h: 6, cls: "is-ink iso-belt" });
    const strip = h("div", "iso-belt-strip", belt.f.top);
    cuboid(world, { x: -L + 10, y: -60, z: 22, w: 2 * L - 20, d: 12, h: 14, cls: "iso-guard" });
    cuboid(world, { x: -L + 10, y: 48, z: 22, w: 2 * L - 20, d: 12, h: 14, cls: "iso-guard" });
    /* End stops */
    cuboid(world, { x: -L, y: -60, z: 22, w: 10, d: 120, h: 18, cls: "iso-guard" });
    cuboid(world, { x: L - 10, y: -60, z: 22, w: 10, d: 120, h: 18, cls: "iso-guard" });
    /* Gate */
    const GX = 0;
    cuboid(world, { x: GX - 24, y: -86, z: 0, w: 48, d: 22, h: 172, cls: "iso-gate" });
    cuboid(world, { x: GX - 24, y: 64, z: 0, w: 48, d: 22, h: 172, cls: "iso-gate" });
    const lintel = cuboid(world, { x: GX - 24, y: -86, z: 172, w: 48, d: 172, h: 26, cls: "is-ink iso-gate" });
    h("i", "iso-gate-led", lintel.f.front);
    faceText(lintel.f.right, "CONVERT", "iso-engrave is-onink");
    const light = h("div", "iso-gate-light", world);
    light.style.width = px(128);
    light.style.height = px(144);
    light.style.transform = `translate3d(${px(GX)},${px(64)},${px(172)}) rotateZ(-90deg) rotateX(-90deg)`;

    const mkBlock = (cls, w, hh, label, file) => {
      const g = group(world, "iso-blk");
      const b = cuboid(g, { x: -w / 2, y: -w / 2, z: 0, w, d: w, h: hh, cls });
      const tl = faceText(b.f.top, label, `iso-tl iso-blk-tl${label.length > 4 ? " is-long" : ""}`, -90);
      const fl = faceText(b.f.front, file, "iso-blk-file");
      return { g, tl, fl };
    };
    const A = mkBlock("is-paper", 88, 58, PAIRS[0].a, PAIRS[0].af);
    const B = mkBlock("is-ink", 80, 84, PAIRS[0].b, PAIRS[0].bf);

    /* Terminal chip */
    const term = h("div", "iso-term", S.ui);
    term.innerHTML =
      '<div class="iso-term-bar"><i></i><i></i><i></i><span>Equivalent command</span></div>' +
      '<div class="iso-term-body"><span class="iso-term-p">$</span> <span class="iso-term-cmd"></span><span class="iso-term-caret"></span>' +
      '<div class="iso-term-ok"><span class="dot"></span><span class="iso-term-okt"></span></div></div>';
    const cmdEl = term.querySelector(".iso-term-cmd");
    const okEl = term.querySelector(".iso-term-ok");
    const okT = term.querySelector(".iso-term-okt");
    const chipA = card(S, "iso-chip", `<span class="iso-chip-k">Source</span><span class="iso-chip-v"></span>`);
    const chipB = card(S, "iso-chip", `<span class="iso-chip-k">Output</span><span class="iso-chip-v"></span>`);

    const PER = 6.6;
    let pairI = -1;
    let typed = -1;
    let beltOff = 0;
    let lastX = -320;
    const setPair = (i) => {
      pairI = i;
      const p = PAIRS[i];
      A.tl.firstChild.textContent = p.a;
      A.tl.classList.toggle("is-long", p.a.length > 4);
      A.fl.firstChild.textContent = p.af;
      B.tl.firstChild.textContent = p.b;
      B.tl.classList.toggle("is-long", p.b.length > 4);
      B.fl.firstChild.textContent = p.bf;
      chipA.c.querySelector(".iso-chip-v").textContent = p.a;
      chipB.c.querySelector(".iso-chip-v").textContent = p.b;
      okT.textContent = p.ok;
      typed = -1;
    };
    setPair(0);

    const blockAt = (g, x, sc, show) => {
      g.style.transform = `${t3(x, 0, 28)} scale3d(1,1,${Math.max(0.001, sc).toFixed(3)})`;
      g.style.visibility = show && sc > 0.01 ? "visible" : "hidden";
    };
    const pop = (u) => {
      /* overshooting 0..1 */
      if (u <= 0) return 0;
      if (u >= 1) return 1;
      return 1 + 2.2 * Math.pow(u - 1, 3) + 1.2 * Math.pow(u - 1, 2);
    };
    S.layout = () => {
      /* Under each end of the track, where nothing moves. */
      const [ax, ay] = S.screen(-L + 30, 60, 0);
      clampPin(S, chipA.pin, chipA.c, ax, ay + (chipA.c.offsetHeight || 40) + 12, "center");
      const [bx, by] = S.screen(L, 0, 0);
      clampPin(S, chipB.pin, chipB.c, bx, by + (chipB.c.offsetHeight || 40) + 16, "center");
    };
    const render = (t) => {
      let tau;
      let loop;
      if (reduced()) {
        /* A still, complete composition: both blocks and the full command. */
        blockAt(A.g, -230, 1, true);
        blockAt(B.g, 230, 1, true);
        light.style.opacity = "0.35";
        if (typed !== 1e9) {
          cmdEl.textContent = PAIRS[pairI].cmd;
          typed = 1e9;
        }
        okEl.classList.add("is-on");
        strip.style.transform = "translate3d(0,0,0)";
        return;
      }
      loop = Math.floor(t / PER);
      tau = t - loop * PER;
      const pi = loop % PAIRS.length;
      if (pi !== pairI) setPair(pi);
      /* Timeline (s): 0–.5 materialise A, .5–2.9 travel to gate, 2.9–3.4 swap, 3.4–5.6 travel out, 5.6–6.2 dissolve B */
      let x;
      if (tau < 0.5) {
        x = -320;
        blockAt(A.g, x, pop(tau / 0.5), true);
        blockAt(B.g, 0, 0, false);
      } else if (tau < 2.9) {
        x = lerp(-320, 0, easeInOut((tau - 0.5) / 2.4));
        blockAt(A.g, x, 1, true);
        blockAt(B.g, 0, 0, false);
      } else if (tau < 3.4) {
        x = 0;
        const u = (tau - 2.9) / 0.5;
        blockAt(A.g, 0, 1 - easeOut(clamp(u * 2, 0, 1)), u < 0.5);
        blockAt(B.g, 0, pop(clamp((u - 0.35) / 0.65, 0, 1)), u > 0.35);
      } else if (tau < 5.6) {
        x = lerp(0, 320, easeInOut((tau - 3.4) / 2.2));
        blockAt(A.g, 0, 0, false);
        blockAt(B.g, x, 1, true);
      } else {
        x = 320;
        const u = clamp((tau - 5.6) / 0.45, 0, 1);
        blockAt(A.g, 0, 0, false);
        blockAt(B.g, x, 1 - easeInOut(u), u < 1);
      }
      const flash = tau > 2.8 && tau < 4 ? Math.exp(-Math.pow((tau - 3.15) / 0.28, 2)) : 0;
      light.style.opacity = (0.22 + 0.78 * flash).toFixed(3);
      lintel.el.classList.toggle("is-flash", flash > 0.3);
      /* Belt follows the block speed */
      const v = x - lastX;
      lastX = x;
      beltOff = (beltOff + Math.max(0, v)) % 40;
      strip.style.transform = `translate3d(${px(beltOff - 40)},0,0)`;
      /* Typing 0.3 → 2.9s, result after the swap */
      const cmd = PAIRS[pairI].cmd;
      const nChars = Math.floor(clamp((tau - 0.3) / 2.5, 0, 1) * cmd.length);
      if (nChars !== typed) {
        typed = nChars;
        cmdEl.textContent = cmd.slice(0, nChars);
      }
      okEl.classList.toggle("is-on", tau > 3.35);
      term.classList.toggle("is-typing", tau > 0.3 && tau < 2.9);
      chipA.pin.classList.add("is-on");
      chipB.pin.classList.toggle("is-on", tau > 3.2);
    };
    S.onEnter = () => {
      chipA.pin.classList.add("is-on");
      if (reduced()) chipB.pin.classList.add("is-on");
      S.layout();
    };
    S.onMotion = () => {
      typed = -1;
      wake(S);
    };
    S.tick = (t) => {
      render(t);
      return !reduced();
    };
    render(0.2);
    if (reduced()) {
      chipA.pin.classList.add("is-on");
      chipB.pin.classList.add("is-on");
    }
    return S;
  }

  /* =====================================================================
     4. AUDIT — a city of certificate columns; height = days until expiry.
     ===================================================================== */
  function audit(root) {
    const CERTS = [
      ["partner-root-ca", 1820, "ok", "Root CA"],
      ["acme-issuing-ca-g2", 912, "ok", "Intermediate CA"],
      ["docs.acme.dev", 340, "ok"],
      ["auth.acme.dev", 301, "ok"],
      ["ci.acme.dev", 256, "ok"],
      ["s3-gateway.acme.internal", 233, "ok"],
      ["api.acme.dev", 212, "ok"],
      ["sso.acme.dev", 199, "ok"],
      ["mail.acme.dev", 164, "ok"],
      ["webhooks.acme.dev", 152, "ok"],
      ["grafana.acme.internal", 139, "ok"],
      ["kafka.acme.internal", 121, "ok"],
      ["shop.acme.dev", 95, "ok"],
      ["cdn.acme.dev", 88, "ok"],
      ["status.acme.dev", 73, "ok"],
      ["jenkins.acme.internal", 66, "ok"],
      ["ldap.acme.internal", 58, "ok"],
      ["vpn.acme.internal", 47, "ok"],
      ["payments.acme.dev", 18, "warn", "RSA 2048"],
      ["legacy-sha1.acme.internal", -12, "bad", "SHA-1 signature"],
    ];
    const SCORE = 77;
    const S = base(root, {
      W: 720,
      H: 520,
      ox: 392,
      oy: 330,
      label: `Security audit: ${CERTS.length} certificates as columns whose height is days until expiry. Health score ${SCORE}; one certificate expires in 18 days and one has expired.`,
    });
    const world = group(S.cam, "iso-audit");
    const COLS = 5;
    const ROWS = 4;
    const P = 64;
    const FP = 40;
    const bw = COLS * P + 28;
    const bd = ROWS * P + 28;
    plane(world, { x: -bw / 2 - 80, y: -bd / 2 - 80, z: -1, w: bw + 160, d: bd + 160, cls: "iso-shadow" });
    const plat = cuboid(world, { x: -bw / 2, y: -bd / 2, z: 0, w: bw, d: bd, h: 18, cls: "iso-plinth" });
    h("div", "iso-grid", plat.f.top);
    const scan = h("div", "iso-scan", plat.f.top);
    faceText(plat.f.front, "EXPIRY HORIZON", "iso-engrave");
    faceText(plat.f.right, "HEALTH · 20 ENTRIES", "iso-engrave");

    /* Back cells first so the tall CAs stand behind the short columns. */
    const cells = [];
    for (let j = 0; j < ROWS; j++) for (let i = 0; i < COLS; i++) cells.push([i, j]);
    cells.sort((a, b) => a[0] + a[1] - (b[0] + b[1]) || a[1] - b[1]);
    const cols = CERTS.map((c, n) => {
      const [i, j] = cells[n];
      const [name, days, st, note] = c;
      const hh = days < 0 ? 7 : 12 + Math.sqrt(Math.min(days, 900)) * 5.4;
      const cx = -bw / 2 + 14 + i * P + (P - FP) / 2;
      const cy = -bd / 2 + 14 + j * P + (P - FP) / 2;
      const g = group(world, "iso-col", cx, cy, 18);
      const grow = group(g, "iso-grow");
      const b = cuboid(grow, { w: FP, d: FP, h: hh, cls: `iso-colbox is-${st}` });
      if (st !== "ok") h("i", `iso-halo is-${st}`, plat.f.top, { style: `left:${px(cx + bw / 2 + FP / 2)};top:${px(cy + bd / 2 + FP / 2)}` });
      return { g, grow, b, name, days, st, note, hh, cx, cy, n, gs: { x: 0, v: 0 } };
    });

    const tip = card(S, "iso-tip", "");
    const hot = hotSet((it, prev) => {
      prev && prev.g.classList.remove("is-hot");
      if (it) {
        it.g.classList.add("is-hot");
        const when = it.days < 0 ? `Expired ${-it.days} days ago` : `Expires in ${it.days} days`;
        const status = it.st === "bad" ? "Expired" : it.st === "warn" ? "Expiring soon" : "Healthy";
        tip.c.innerHTML = `<div class="iso-card-k">${it.name}</div><div class="iso-card-v">${when}</div><div class="iso-tip-st is-${it.st}"><span class="dot${it.st === "ok" ? "" : " " + it.st}"></span>${status}${it.note ? ` · ${it.note}` : ""}</div>`;
        placeTip(it);
        tip.pin.classList.add("is-on");
      } else tip.pin.classList.remove("is-on");
    });
    const placeTip = (it) => {
      const [ax, ay] = S.screen(it.cx + FP / 2, it.cy + FP / 2, 18 + it.hh);
      const w = tip.c.offsetWidth || 180;
      const hgt = tip.c.offsetHeight || 70;
      const x = clamp(ax - w / 2, 6, Math.max(6, S.cw - w - 6));
      const y = Math.max(4, ay - hgt - 14);
      tip.pin.style.transform = `translate3d(${px(x)},${px(y)},0)`;
    };
    cols.forEach((c) => hot.bind(c.g, c));

    /* Score badge */
    const badge = h("div", "iso-score", S.ui);
    const R = 25;
    const CIRC = 2 * Math.PI * R;
    badge.innerHTML = `<svg viewBox="0 0 64 64" aria-hidden="true"><circle class="iso-score-track" cx="32" cy="32" r="${R}"/><circle class="iso-score-arc" cx="32" cy="32" r="${R}" stroke-dasharray="${r2(CIRC)}" stroke-dashoffset="${r2(CIRC)}"/></svg><div class="iso-score-n">0</div><div class="iso-score-t"><b>Health score</b><span>1 expired · 1 expiring</span></div>`;
    const arc = badge.querySelector(".iso-score-arc");
    const num = badge.querySelector(".iso-score-n");
    let t0 = null;
    let shown = -1;
    const setScore = (u) => {
      const v = Math.round(SCORE * u);
      if (v !== shown) {
        shown = v;
        num.textContent = String(v);
      }
      arc.setAttribute("stroke-dashoffset", r2(CIRC * (1 - (SCORE / 100) * u)));
    };

    S.layout = () => hot.cur && placeTip(hot.cur);
    S.onEnter = () => {
      t0 = null;
      wake(S);
      setTimeout(() => {
        if (grown) return;
        grown = true;
        cols.forEach((c) => (c.grow.style.transform = ""));
        setScore(1);
      }, 3500);
    };
    let grown = false;
    S.tick = (t, dt) => {
      if (reduced()) {
        cols.forEach((c) => (c.grow.style.transform = ""));
        setScore(1);
        grown = true;
        return false;
      }
      if (!S.entered) return false;
      if (t0 == null) t0 = t;
      const e = t - t0;
      let moving = false;
      if (!grown) {
        for (const c of cols) {
          if (e > 0.15 + c.n * 0.035) moving = spring(c.gs, 1, dt, 120, 14) || moving;
          else moving = true;
          c.grow.style.transform = `scale3d(1,1,${Math.max(0.001, c.gs.x).toFixed(3)})`;
        }
        if (!moving) grown = true;
      }
      setScore(easeOut(clamp((e - 0.2) / 1.6, 0, 1)));
      return true; /* idle scan runs in CSS; JS only during the count-up */
    };
    /* Before entering view: columns flat (no-motion users see them fully grown). */
    if (!reduced()) cols.forEach((c) => (c.grow.style.transform = "scale3d(1,1,0.001)"));
    else setScore(1);
    const origTick = S.tick;
    S.tick = (t, dt) => {
      const r = origTick(t, dt);
      return r && !(grown && t0 != null && t - t0 > 2);
    };
    return S;
  }

  /* =====================================================================
     5. VAULT — a safe whose lid opens to reveal key tiles.
     ===================================================================== */
  function vault(root) {
    const S = base(root, {
      W: 640,
      H: 540,
      ox: 320,
      oy: 352,
      role: "group",
      label: "Password vault: Argon2id key derivation and AES-256-GCM encryption",
    });
    const world = group(S.cam, "iso-vault");
    plane(world, { x: -200, y: -200, z: -1, w: 400, d: 400, cls: "iso-shadow" });
    const deco = group(world, "iso-vault-body");
    deco.setAttribute("aria-hidden", "true");
    const ctl = group(world, "iso-vault-ctl");
    ctl.setAttribute("role", "button");
    ctl.setAttribute("tabindex", "0");
    ctl.setAttribute("aria-pressed", "false");
    ctl.setAttribute("aria-label", "Open the vault");

    const Hb = 168;
    const Wt = 18;
    /* plinth + floor */
    const floor = cuboid(ctl, { x: -104, y: -104, z: 0, w: 208, d: 208, h: 20, cls: "is-ink iso-vplinth" });
    h("div", "iso-bolts is-onink", floor.f.front);
    h("div", "iso-bolts is-onink", floor.f.right);
    cuboid(ctl, { x: -100 + Wt, y: -100 + Wt, z: 20, w: 200 - 2 * Wt, d: 200 - 2 * Wt, h: 2, cls: "iso-vfloor", faces: "top" });
    /* walls */
    cuboid(ctl, { x: -100, y: -100, z: 20, w: 200 - Wt, d: Wt, h: Hb, cls: "iso-vwall" }); /* back */
    cuboid(ctl, { x: -100, y: -100 + Wt, z: 20, w: Wt, d: 200 - 2 * Wt, h: Hb, cls: "iso-vwall", faces: "top right" }); /* left */
    const right = cuboid(ctl, { x: 100 - Wt, y: -100, z: 20, w: Wt, d: 200, h: Hb, cls: "iso-vwall" });
    const front = cuboid(ctl, { x: -100, y: 100 - Wt, z: 20, w: 200 - Wt, d: Wt, h: Hb, cls: "iso-vwall" });
    /* Front panel: dial, handle, rivets. */
    const fp = front.f.front;
    h("div", "iso-vframe", fp);
    const dial = h("div", "iso-dial", fp);
    const dialFace = h("div", "iso-dial-face", dial);
    h("i", "iso-dial-mark", dial);
    const handle = h("div", "iso-handle", fp);
    h("i", "", handle);
    const rp = right.f.right;
    h("div", "iso-vframe", rp);
    h("i", "iso-hinge a", rp);
    h("i", "iso-hinge b", rp);
    faceText(rp, "VAULT", "iso-engrave iso-vlabel");

    /* Key tiles */
    const KEYS = [
      ["RSA", "is-ink", -50],
      ["EC", "is-paper", 0],
      ["AES", "is-ink", 50],
    ];
    const keys = KEYS.map(([lab, cls, x], i) => {
      const g = group(ctl, "iso-key", x, 0, 22);
      const b = cuboid(g, { x: -19, y: -30, z: 0, w: 38, d: 60, h: 10, cls });
      h("i", "iso-keyglyph", b.f.top);
      faceText(b.f.top, lab, "iso-keylab", -90);
      return { g, i, x, st: { x: 0, v: 0 } };
    });

    /* Lid, hinged on the back edge (y = -100, z = top). */
    const hinge = group(ctl, "iso-hingeg", -100, -100, 20 + Hb);
    const lidG = group(hinge, "iso-lidg");
    const lid = cuboid(lidG, { x: 0, y: 0, z: 0, w: 200, d: 200, h: 26, cls: "is-ink iso-lid", faces: "top bottom front back left right" });
    h("div", "iso-lid-groove", lid.f.top);
    h("div", "iso-lid-scan", lid.f.top);
    h("i", "iso-lid-grip", lid.f.front);
    h("div", "iso-lid-under", lid.f.bottom);

    const chipA = card(S, "iso-chip is-on", `<span class="iso-chip-k">Key derivation</span><span class="iso-chip-v">Argon2id</span>`);
    const chipB = card(S, "iso-chip is-on", `<span class="iso-chip-k">Encryption</span><span class="iso-chip-v">AES-256-GCM</span>`);
    const state = card(S, "iso-state", `<span class="iso-state-dot"></span><span class="iso-state-t">Locked</span>`);
    const stateT = state.c.querySelector(".iso-state-t");
    chipA.pin.classList.add("is-on");
    chipB.pin.classList.add("is-on");
    state.pin.classList.add("is-on");

    const open = { x: 0, v: 0 };
    let hover = false;
    let pinned = false;
    let focus = false;
    const target = () => (hover || pinned || focus ? 1 : 0);
    ctl.addEventListener("pointerenter", (e) => {
      if (e.pointerType === "touch") return;
      hover = true;
      wake(S);
    });
    ctl.addEventListener("pointerleave", (e) => {
      if (e.pointerType === "touch") return;
      hover = false;
      wake(S);
    });
    const toggle = () => {
      pinned = !pinned;
      if (!pinned && lastPointer !== "touch") hover = false;
      ctl.setAttribute("aria-pressed", String(pinned));
      ctl.setAttribute("aria-label", pinned ? "Close the vault" : "Open the vault");
      wake(S);
    };
    ctl.addEventListener("click", toggle);
    ctl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        toggle();
      }
    });
    ctl.addEventListener("focus", () => {
      focus = ctl.matches(":focus-visible");
      wake(S);
    });
    ctl.addEventListener("blur", () => {
      focus = false;
      wake(S);
    });

    S.layout = () => {
      const [ax, ay] = S.screen(-100, 100, 20 + Hb * 0.55);
      clampPin(S, chipA.pin, chipA.c, ax, ay, "right", 26);
      const [bx, by] = S.screen(100, -100, 20 + Hb * 0.55);
      clampPin(S, chipB.pin, chipB.c, bx, by, "left", 26);
      const [cx, cy] = S.screen(104, 104, 0);
      clampPin(S, state.pin, state.c, cx, cy + 22, "center");
    };
    let lastLabel = "";
    const apply = (t) => {
      const o = open.x;
      lidG.style.transform = `rotateX(${r2(o * 104)}deg)`;
      keys.forEach((k) => {
        const u = clamp((o - 0.3 - k.i * 0.08) / 0.55, 0, 1.15);
        const bob = reduced() ? 0 : Math.sin(t * 1.6 + k.i * 1.3) * 3 * Math.min(1, u);
        k.g.style.transform = t3(k.x, 0, 22 + u * 118 + bob);
      });
      dialFace.style.transform = `rotate(${r2(o * -300 + (reduced() ? 0 : Math.sin(t * 0.4) * 4 * (1 - o)))}deg)`;
      const lab = o > 0.5 ? "Unlocked" : "Locked";
      if (lab !== lastLabel) {
        lastLabel = lab;
        stateT.textContent = lab;
        state.c.classList.toggle("is-open", o > 0.5);
      }
      root.classList.toggle("is-open", target() === 1);
    };
    S.tick = (t, dt) => {
      const busy = spring(open, target(), dt, 70, 13);
      apply(t);
      return !reduced() || busy;
    };
    apply(0);
    return S;
  }

  /* =====================================================================
     6. LOCAL — the machine inside a boundary; packets never leave.
        Lines light up only when you start a network action.
     ===================================================================== */
  function local(root) {
    const S = base(root, {
      W: 760,
      H: 520,
      ox: 380,
      oy: 268,
      label: "Local only: everything stays on your machine. The network is used only for TLS inspection, connection tests, revocation checks and RFC 3161 timestamps that you start.",
    });
    const world = group(S.cam, "iso-local");
    const PL = 240;
    const PZ = 20;
    const R = 166;
    plane(world, { x: -PL - 70, y: -PL - 70, z: -1, w: 2 * PL + 140, d: 2 * PL + 140, cls: "iso-shadow" });
    const plat = cuboid(world, { x: -PL, y: -PL, z: 0, w: 2 * PL, d: 2 * PL, h: PZ, cls: "iso-plinth" });
    const top = plat.f.top;
    const ringEl = (r, cls) => h("i", `iso-ring ${cls}`, top, { style: `left:${px(PL - r)};top:${px(PL - r)};width:${px(2 * r)};height:${px(2 * r)}` });
    ringEl(R, "is-boundary");
    ringEl(124, "is-faint");
    ringEl(70, "is-faint");
    faceText(plat.f.front, "ON-DEVICE", "iso-engrave");
    faceText(plat.f.right, "NO TELEMETRY", "iso-engrave");

    /* Laptop */
    const lap = group(world, "iso-laptop");
    const lb = cuboid(lap, { x: -72, y: -46, z: PZ, w: 144, d: 92, h: 7, cls: "iso-lapbase" });
    h("div", "iso-keys", lb.f.top);
    h("div", "iso-pad", lb.f.top);
    const hingeG = group(lap, "iso-scrhinge", -72, -46, PZ + 7);
    hingeG.style.transform = `${t3(-72, -46, PZ + 7)} rotateX(14deg)`;
    const scr = cuboid(hingeG, { x: 0, y: 0, z: 0, w: 144, d: 5, h: 96, cls: "is-ink iso-lid-scr" });
    const ui = h("div", "iso-screen", scr.f.front);
    ui.innerHTML = "<i class='a'></i><i class='b'></i><i class='c'></i><i class='d'></i><b></b>";

    /* Packets orbiting inside the boundary */
    const packets = [0, 1, 2, 3, 4, 5].map((i) => {
      const g = group(world, "iso-pkt");
      cuboid(g, { x: -5, y: -5, z: 0, w: 10, d: 10, h: 10, cls: i % 2 ? "is-paper iso-pktbox" : "is-ink iso-pktbox" });
      return { g, r: 112 + (i % 3) * 11, w: (0.3 + (i % 3) * 0.06) * (i % 2 ? -1 : 1), a0: i * 1.05, z: 26 + ((i * 7) % 5) * 9, ph: i * 0.8 };
    });

    /* Endpoints: left, right, front corners */
    const EP = [
      { name: "TLS inspect", dir: [-1, 1], align: "right" },
      { name: "Connection test", dir: [1, -1], align: "left" },
      { name: "RFC 3161 timestamp", dir: [1, 1], align: "center" },
      { name: "Revocation check", dir: [-1, -1], align: "back" },
    ];
    const NODE = 200;
    const eps = EP.map((e) => {
      const nx = e.dir[0] * NODE;
      const ny = e.dir[1] * NODE;
      const g = group(world, "iso-ep", nx, ny, PZ);
      const b = cuboid(g, { x: -20, y: -20, z: 0, w: 40, d: 40, h: 28, cls: "iso-epbox" });
      h("i", "iso-ep-led", b.f.top);
      /* Wire on the platform top, from the boundary to the node. */
      const ang = Math.atan2(e.dir[1], e.dir[0]);
      const r0 = R + 4;
      const r1 = Math.hypot(nx, ny) - 30;
      const wire = h("div", "iso-wire", top);
      wire.style.width = px(r1 - r0);
      wire.style.transform = `translate3d(${px(PL + Math.cos(ang) * r0)},${px(PL + Math.sin(ang) * r0)},0) rotate(${r2(ang / D2R)}deg)`;
      wire.style.setProperty("--len", px(r1 - r0));
      h("i", "iso-wire-dot", wire);
      const lab = card(S, "iso-chip iso-ep-chip is-on", `<span class="iso-chip-v">${e.name}</span><span class="iso-chip-k">Only when you start it</span>`);
      lab.pin.classList.add("is-on");
      return { ...e, g, wire, lab, nx, ny };
    });
    const hot = hotSet((it, prev) => {
      if (prev) {
        prev.g.classList.remove("is-on");
        prev.wire.classList.remove("is-on");
        prev.lab.pin.classList.remove("is-live");
      }
      if (it) {
        it.g.classList.add("is-on");
        it.wire.classList.add("is-on");
        it.lab.pin.classList.add("is-live");
      }
      root.classList.toggle("is-net", !!it);
    });
    eps.forEach((e) => {
      hot.bind(e.g, e);
      e.lab.pin.classList.add("is-interactive");
      hot.bind(e.lab.pin, e);
    });

    /* Dome (SVG, drawn over the 3D layer): upper semicircle + front half of the floor ellipse. */
    const svg = s("svg", { class: "iso-dome", width: S.W, height: S.H, viewBox: `0 0 ${S.W} ${S.H}`, "aria-hidden": "true" }, S.stage);
    const [cx, cy] = S.at(0, 0, PZ);
    const ry = R * Math.cos(ISO_X * D2R);
    const defs = s("defs", {}, svg);
    const grad = s("radialGradient", { id: `iso-dome-g-${Math.random().toString(36).slice(2, 7)}`, cx: "38%", cy: "22%", r: "80%" }, defs);
    s("stop", { offset: "0", class: "iso-dome-s0" }, grad);
    s("stop", { offset: "0.55", class: "iso-dome-s1" }, grad);
    s("stop", { offset: "1", class: "iso-dome-s2" }, grad);
    const d = `M ${r2(cx - R)} ${r2(cy)} A ${R} ${R} 0 0 1 ${r2(cx + R)} ${r2(cy)} A ${R} ${r2(ry)} 0 0 1 ${r2(cx - R)} ${r2(cy)} Z`;
    s("path", { d, class: "iso-dome-fill", fill: `url(#${grad.id})` }, svg);
    s("path", { d: `M ${r2(cx - R)} ${r2(cy)} A ${R} ${R} 0 0 1 ${r2(cx + R)} ${r2(cy)}`, class: "iso-dome-edge" }, svg);
    s("path", { d: `M ${r2(cx - R * 0.78)} ${r2(cy - R * 0.42)} A ${R * 0.92} ${R * 0.92} 0 0 1 ${r2(cx - R * 0.18)} ${r2(cy - R * 0.9)}`, class: "iso-dome-hi" }, svg);
    for (const k of [0.33, 0.66]) {
      const zz = R * k;
      const rr = Math.sqrt(R * R - zz * zz);
      const [lx, ly] = S.at(0, 0, PZ + zz);
      s("path", { d: `M ${r2(lx - rr)} ${r2(ly)} A ${r2(rr)} ${r2(rr * Math.cos(ISO_X * D2R))} 0 0 0 ${r2(lx + rr)} ${r2(ly)}`, class: "iso-dome-lat" }, svg);
    }
    const tag = card(S, "iso-state", `<span class="iso-state-dot"></span><span class="iso-state-t">On-device · 0 bytes sent</span>`);
    tag.pin.classList.add("is-on");
    const tagT = tag.c.querySelector(".iso-state-t");

    S.layout = () => {
      for (const e of eps) {
        if (e.align === "center") {
          const [ax, ay] = S.screen(e.nx + 20, e.ny - 20, PZ + 14);
          clampPin(S, e.lab.pin, e.lab.c, ax, ay + 6, "left", 18);
        } else if (e.align === "back") {
          const [ax, ay] = S.screen(e.nx - 20, e.ny + 20, PZ + 28);
          clampPin(S, e.lab.pin, e.lab.c, ax, ay - 16, "right", 18);
        } else if (e.align === "right") {
          const [ax, ay] = S.screen(e.nx - 20, e.ny - 20, PZ + 28);
          clampPin(S, e.lab.pin, e.lab.c, ax, ay - 16, "center");
        } else {
          const [ax, ay] = S.screen(e.nx - 20, e.ny - 20, PZ + 28);
          clampPin(S, e.lab.pin, e.lab.c, ax, ay - 16, "center");
        }
      }
      const [tx, ty] = S.screen(0, 0, PZ + R);
      /* Beside the dome's peak, clear of the back (revocation) node. */
      clampPin(S, tag.pin, tag.c, tx + 40, ty - 18, "left", 0);
    };
    let netLabel = "";
    const apply = (t) => {
      for (const p of packets) {
        const a = p.a0 + (reduced() ? 0 : t * p.w);
        const z = p.z + (reduced() ? 0 : Math.sin(t * 1.3 + p.ph) * 6);
        p.g.style.transform = `${t3(Math.cos(a) * p.r, Math.sin(a) * p.r, PZ + z)} rotateZ(${r2(a / D2R)}deg)`;
      }
      const lab = hot.cur ? `${hot.cur.name} · you started it` : "On-device · 0 bytes sent";
      if (lab !== netLabel) {
        netLabel = lab;
        tagT.textContent = lab;
        tag.c.classList.toggle("is-open", !!hot.cur);
      }
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    root.addEventListener("pointerleave", () => wake(S));
    apply(0);
    return S;
  }

  /* =====================================================================
     7. PLATFORMS — three pedestals: Windows, macOS and Linux (Linux from source for now).
     ===================================================================== */
  function platforms(root) {
    const PL = [
      { id: "windows", name: "Windows", sub: "x64", ready: true, ext: ".exe", arch: "x64" },
      { id: "macos", name: "macOS", sub: "Apple silicon", ready: true, ext: ".dmg", arch: "arm64" },
      { id: "linux", name: "Linux", sub: "x64 · arm64", ready: false },
    ];
    const S = base(root, {
      W: 780,
      H: 460,
      ox: 390,
      oy: 300,
      label: "Platforms: Windows and macOS available, Linux builds from source",
    });
    const world = group(S.cam, "iso-plats");
    const D = 176;
    const PW = 156;
    const PH = 54;
    plane(world, { x: -D - 200, y: -D - 200, z: -1, w: 2 * D + 400, d: 2 * D + 400, cls: "iso-shadow" });
    const peds = PL.map((p, i) => {
      const cxw = (i - 1) * D;
      const cyw = -(i - 1) * D;
      const g = group(world, `iso-ped is-${p.id}${p.ready ? " is-ready" : ""}`, cxw, cyw, 0);
      const lift = group(g, "iso-lift");
      const body = cuboid(lift, { x: -PW / 2, y: -PW / 2, z: 0, w: PW, d: PW, h: PH, cls: "iso-pedbox" });
      faceText(body.f.front, p.name, "iso-pedname");
      faceText(body.f.right, p.ready ? "AVAILABLE" : "FROM SOURCE", "iso-engrave");
      const plate = cuboid(lift, { x: -PW / 2 + 12, y: -PW / 2 + 12, z: PH, w: PW - 24, d: PW - 24, h: 6, cls: p.ready ? "is-ink iso-pedplate" : "is-paper-soft iso-pedplate" });
      h("div", "iso-groove", plate.f.top);
      if (p.ready) h("i", "iso-glow", plate.f.top);
      const bob = group(lift, "iso-bob");
      const spin = group(bob, "iso-spin");
      const BX = 70;
      const box = cuboid(spin, {
        x: -BX / 2,
        y: -BX / 2,
        z: 0,
        w: BX,
        d: BX,
        h: BX,
        cls: p.ready ? "is-paper iso-inst" : "iso-ghost",
        faces: p.ready ? "top front back left right" : "top bottom front back left right",
      });
      if (p.ready) {
        faceText(box.f.top, "1.0.0", "iso-tl iso-inst-tl", -90);
        faceText(box.f.front, p.ext, "iso-inst-f");
        faceText(box.f.right, p.arch, "iso-inst-f");
        faceText(box.f.back, p.ext, "iso-inst-f");
        faceText(box.f.left, p.arch, "iso-inst-f");
      }
      const lab = card(
        S,
        `iso-chip iso-ped-chip${p.ready ? " is-ready" : ""}`,
        p.ready
          ? `<span class="iso-chip-v"><span class="dot"></span>Available</span><span class="iso-chip-k">${p.sub}</span>`
          : `<span class="iso-chip-v"><span class="iso-long">Build from source</span><span class="iso-short">From source</span></span><span class="iso-chip-k">${p.sub}</span>`
      );
      lab.pin.classList.add("is-on");
      return { ...p, i, g, lift, bob, spin, lab, cxw, cyw };
    });
    const hot = hotSet((it, prev) => {
      prev && prev.g.classList.remove("is-hot");
      it && it.g.classList.add("is-hot");
      peds.forEach((p) => p.lab.pin.classList.toggle("is-hot", p === it));
    });
    peds.forEach((p) => hot.bind(p.g, p));
    const syncActive = () => {
      const a = (root.dataset.active || "").toLowerCase();
      peds.forEach((p) => {
        p.g.classList.toggle("is-active", p.id === a);
        p.lab.pin.classList.toggle("is-active", p.id === a);
      });
      root.classList.toggle("has-active", peds.some((p) => p.id === a));
    };
    syncActive();
    new MutationObserver(syncActive).observe(root, { attributes: true, attributeFilter: ["data-active"] });

    S.layout = () => {
      for (const p of peds) {
        const [ax, ay] = S.screen(p.cxw, p.cyw, PH + 6 + 150);
        clampPin(S, p.lab.pin, p.lab.c, ax, ay - 8, "center");
      }
    };
    const apply = (t) => {
      for (const p of peds) {
        const bob = reduced() ? 0 : Math.sin(t * 1.2 + p.i * 1.1) * (p.ready ? 6 : 3.5);
        p.bob.style.transform = t3(0, 0, PH + 6 + 26 + bob);
        const sw = reduced() ? 0 : p.ready ? Math.sin(t * 0.45) * 14 : Math.sin(t * 0.3 + p.i) * 5;
        p.spin.style.transform = `rotateZ(${r2(sw)}deg)`;
      }
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    apply(0);
    return S;
  }

  /* =====================================================================
     8. APPS — More apps page: a stepped shelf with one tier per platform and
        one block per app. data-active="<app id>" or "<tier id>" (set by the page)
        lifts and names it; clicking a block dispatches "iso:pick" { id }.
     ===================================================================== */
  function apps(root) {
    const TIERS = [
      {
        id: "cli",
        label: "MCP · CLI",
        name: "MCP &amp; CLI tools",
        apps: [
          ["mcp-secure-remote", "mcp-secure-remote", "MCP proxy · npm, PyPI"],
          ["pr-comments", "pr-comments", "CLI · npm, PyPI"],
        ],
      },
      {
        id: "vscode",
        label: "VS CODE",
        name: "VS Code extensions",
        apps: [
          ["vsgit", "VsGit", "VS Code extension"],
          ["mule-aes", "MuleSoft AES", "VS Code extension"],
          ["certi", "Certificate Utility", "Pairs with Keystore Studio", true],
          ["dev-x", "Developer Utility", "VS Code extension"],
        ],
      },
      {
        id: "windows",
        label: "WINDOWS",
        name: "Windows apps",
        apps: [
          ["anchor", "Anchor", "Windows app", true],
          ["swiftx", "SwiftX", "Windows app", true],
          ["dockdev", "DockDev", "Windows app"],
        ],
      },
    ];
    const S = base(root, {
      W: 600,
      H: 470,
      ox: 300,
      oy: 290,
      label: "Nine apps on three shelves: Windows apps, VS Code extensions, and MCP and CLI tools",
    });
    const world = group(S.cam, "iso-apps");
    const D = 104; /* tier depth */
    const B = 66; /* block size */
    const P = 86; /* block pitch */
    const BH = 28;
    const STEP = 22;
    const L = 4 * P - (P - B) + 52;
    plane(world, { x: -L / 2 - 80, y: -1.5 * D - 80, z: -1, w: L + 160, d: 3 * D + 160, cls: "iso-shadow" });
    const blocks = [];
    const tiers = TIERS.map((T, i) => {
      const y0 = -1.5 * D + i * D;
      const th = (3 - i) * STEP;
      const tier = cuboid(world, { x: -L / 2, y: y0, z: 0, w: L, d: D, h: th, cls: "iso-shelf" });
      faceText(tier.f.right, T.label, "iso-engrave");
      const span = T.apps.length * P - (P - B);
      T.apps.forEach(([id, name, kind, feat], k) => {
        const x = -span / 2 + k * P;
        const y = y0 + (D - B) / 2;
        const g = group(world, `iso-appblk${feat ? " is-feat" : ""}`, x, y, th);
        const lift = group(g, "iso-lift");
        const b = cuboid(lift, { w: B, d: B, h: BH, cls: feat ? "is-ink" : "is-paper" });
        h("i", "iso-appglyph", b.f.top);
        g.addEventListener("click", () => {
          if (lastPointer !== "touch") root.dispatchEvent(new CustomEvent("iso:pick", { detail: { id }, bubbles: true }));
        });
        blocks.push({ id, name, kind, tier: T.id, g, x, y, z: th, n: blocks.length });
      });
      return { ...T, th, y0 };
    });

    const chip = card(S, "iso-chip iso-app-chip", "");
    let shown = null;
    const sync = () => {
      const a = root.dataset.active || "";
      const hb = hot.cur;
      const tier = hb ? null : tiers.find((t) => t.id === a);
      const one = hb || (tier ? null : blocks.find((b) => b.id === a)) || null;
      blocks.forEach((b) => b.g.classList.toggle("is-hot", one ? b === one : !!tier && b.tier === tier.id));
      root.classList.toggle("has-hot", !!(one || tier));
      if (one) {
        chip.c.innerHTML = `<span class="iso-chip-k">${one.kind}</span><span class="iso-chip-v">${one.name}</span>`;
        shown = one;
      } else if (tier) {
        chip.c.innerHTML = `<span class="iso-chip-k">${tier.apps.length} apps</span><span class="iso-chip-v">${tier.name}</span>`;
        shown = { x: -B / 2, y: tier.y0 + (D - B) / 2, z: tier.th };
      } else shown = null;
      chip.pin.classList.toggle("is-on", !!shown);
      S.layout();
    };
    const hot = hotSet(() => sync());
    blocks.forEach((b) => hot.bind(b.g, b));
    new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-active"] });

    S.layout = () => {
      if (!shown) return;
      const [ax, ay] = S.screen(shown.x + B / 2, shown.y + B / 2, shown.z + BH + 36);
      clampPin(S, chip.pin, chip.c, ax, ay, "center");
    };
    const apply = (t) => {
      const still = reduced() || root.classList.contains("has-hot");
      for (const b of blocks) {
        const w = still ? 0 : Math.pow(Math.max(0, Math.sin(t * 1.15 - b.n * 0.55)), 3) * 7;
        b.g.style.transform = t3(b.x, b.y, b.z + w);
      }
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    apply(0);
    sync();
    return S;
  }

  /* =====================================================================
     9. CHANGELOG — the road to 1.0 as a stack of milestone slabs, oldest at
        the bottom and 1.0.0 on top. data-active="<index>" slides that slab out
        and labels it; hovering a slab dispatches "iso:hot" { index }.
     ===================================================================== */
  function changelog(root) {
    const M = [
      ["24 Oct 2026", "First commit"],
      ["9 Nov 2026", "Renamed Keystore Studio"],
      ["10 Nov 2026", "OCSP and trust anchors"],
      ["13 Nov 2026", "Undo and redo, new icons"],
      ["14 Nov 2026", "Monochrome, tool detection"],
      ["15 Nov 2026", "MD5 fingerprints removed"],
      ["17 Nov 2026", "Formats and help"],
      ["23 Nov 2026", "Title bar and sidebar"],
      ["25 Nov 2026", "1.0.0 ships"],
    ];
    const S = base(root, {
      W: 420,
      H: 380,
      ox: 196,
      oy: 254,
      label: "A stack of nine milestone slabs, the first commit at the bottom and version 1.0.0 on top",
    });
    const world = group(S.cam, "iso-log");
    const SW = 200;
    const SD = 136;
    const T = 11;
    const G = 5;
    const PH = 18;
    const OUT = 58;
    plane(world, { x: -SW / 2 - 90, y: -SD / 2 - 90, z: -1, w: SW + 180, d: SD + 180, cls: "iso-shadow" });
    const plinth = cuboid(world, { x: -SW / 2 - 18, y: -SD / 2 - 18, z: 0, w: SW + 36, d: SD + 36, h: PH, cls: "iso-plinth" });
    faceText(plinth.f.front, "ROAD TO 1.0", "iso-engrave");
    faceText(plinth.f.right, "9 MILESTONES", "iso-engrave");
    const slabs = M.map(([date, label], i) => {
      const top = i === M.length - 1;
      const th = top ? T + 5 : T;
      const z = PH + i * (T + G);
      const rot = top ? 0 : ((i % 3) - 1) * 2.4;
      const g = group(world, `iso-mslab${top ? " is-top" : ""}`);
      g.style.transform = `${t3(0, 0, z)} rotateZ(${rot}deg)`;
      const out = group(g, "iso-mout");
      const b = cuboid(out, { x: -SW / 2, y: -SD / 2, z: 0, w: SW, d: SD, h: th, cls: top ? "is-ink" : "is-paper-soft" });
      faceText(b.f.front, date.replace(/ 2026$/, "").toUpperCase(), "iso-engrave iso-mdate");
      if (top) {
        h("div", "iso-groove", b.f.top);
        faceText(b.f.top, "1.0.0", "iso-tl", -90);
      }
      return { i, date, label, g, z, th, rot };
    });

    const chip = card(S, "iso-chip iso-log-chip", "");
    let shown = null;
    const hot = hotSet((it) => {
      root.dispatchEvent(new CustomEvent("iso:hot", { detail: { index: it ? it.i : null }, bubbles: true }));
      sync();
    });
    slabs.forEach((s) => hot.bind(s.g, s));
    const sync = () => {
      const a = root.dataset.active;
      const cur = hot.cur || (a != null && a !== "" ? slabs[Number(a)] : null) || null;
      slabs.forEach((s) => s.g.classList.toggle("is-active", s === cur));
      root.classList.toggle("has-active", !!cur);
      if (cur) chip.c.innerHTML = `<span class="iso-chip-k">${cur.date}</span><span class="iso-chip-v">${cur.label}</span>`;
      shown = cur;
      chip.pin.classList.toggle("is-on", !!cur);
      S.layout();
    };
    new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-active"] });

    S.layout = () => {
      if (!shown) return;
      const [ax, ay] = S.screen(SW / 2 + OUT, 0, shown.z + shown.th);
      clampPin(S, chip.pin, chip.c, ax, ay, "left", 10);
    };
    const topSlab = slabs[slabs.length - 1];
    const apply = (t) => {
      const lift = reduced() || root.classList.contains("has-active") ? 0 : (Math.sin(t * 1.2) * 0.5 + 0.5) * 8;
      topSlab.g.style.transform = `${t3(0, 0, topSlab.z + lift)} rotateZ(${topSlab.rot}deg)`;
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    apply(0);
    sync();
    return S;
  }

  /* =====================================================================
     10. FEEDBACK — an envelope with a letter in it. data-state="open" (or a
         hover) lifts the flap and the letter; "sent" sends the letter up and
         away. data-type is printed on the letter.
     ===================================================================== */
  function feedback(root) {
    const S = base(root, {
      W: 480,
      H: 340,
      ox: 250,
      oy: 205,
      label: "An envelope with a letter in it: your message goes out through your own mail app",
    });
    const world = group(S.cam, "iso-mail");
    const EW = 168;
    const ED = 248;
    const EH = 18;
    const WT = 6;
    plane(world, { x: -EW / 2 - 80, y: -ED / 2 - 80, z: -1, w: EW + 160, d: ED + 160, cls: "iso-shadow" });
    const env = group(world, "iso-env");
    cuboid(env, { x: -EW / 2, y: -ED / 2, z: 0, w: EW, d: ED, h: 3, cls: "is-ink iso-env-floor" });
    cuboid(env, { x: -EW / 2, y: -ED / 2, z: 3, w: EW, d: WT, h: EH - 3, cls: "is-ink iso-env-wall" });
    cuboid(env, { x: -EW / 2, y: -ED / 2 + WT, z: 3, w: WT, d: ED - 2 * WT, h: EH - 3, cls: "is-ink iso-env-wall" });
    const side = cuboid(env, { x: EW / 2 - WT, y: -ED / 2 + WT, z: 3, w: WT, d: ED - 2 * WT, h: EH - 3, cls: "is-ink iso-env-wall" });
    cuboid(env, { x: -EW / 2, y: ED / 2 - WT, z: 3, w: EW, d: WT, h: EH - 3, cls: "is-ink iso-env-wall" });
    faceText(side.f.right, "HELLO@KEYSTORE-STUDIO.APP", "iso-engrave iso-env-addr");

    const lpos = group(env, "", -EW / 2 + 16, -ED / 2 + 18, 3.5);
    const lift = group(lpos, "iso-letter-lift");
    const letter = cuboid(lift, { w: EW - 32, d: ED - 36, h: 3, cls: "is-paper iso-letter" });
    h("div", "iso-letter-lines", letter.f.top);
    h("i", "iso-stamp", letter.f.top);
    const typeText = faceText(letter.f.top, root.dataset.type || "Feedback", "iso-tl iso-letter-type", -90);

    const hinge = group(env, "", -EW / 2, -ED / 2, EH);
    const fold = group(hinge, "iso-flap");
    const flap = h("div", "iso-flap-face", fold);
    flap.style.width = px(EW * 0.64);
    flap.style.height = px(ED);

    const syncType = () => {
      const span = typeText.querySelector("span");
      if (span) span.textContent = root.dataset.type || "Feedback";
    };
    new MutationObserver(syncType).observe(root, { attributes: true, attributeFilter: ["data-type"] });
    root.addEventListener("click", () => {
      if (lastPointer === "touch") root.classList.toggle("is-tapped");
    });

    const apply = (t) => {
      const z = reduced() ? 0 : Math.sin(t * 1.1) * 4;
      env.style.transform = t3(0, 0, z);
    };
    S.tick = (t) => {
      apply(t);
      return !reduced();
    };
    apply(0);
    return S;
  }

  /* ---------- Mounting ---------- */
  const BUILDERS = { hero, formats, convert, audit, vault, local, platforms, apps, changelog, feedback };
  function mount(el) {
    if (!el || !(el instanceof Element)) return null;
    if (el.__iso) return el.__iso;
    const b = BUILDERS[el.dataset.scene];
    if (!b) return null;
    const sc = b(el);
    sc.name = el.dataset.scene;
    el.__iso = sc;
    scenes.add(sc);
    if (io) io.observe(el);
    else {
      sc.visible = true;
      sc.entered = true;
      sc.onEnter && sc.onEnter();
      wake(sc);
    }
    return sc;
  }
  function mountAll(rootEl) {
    return [...(rootEl || document).querySelectorAll(".iso-scene[data-scene]")].map(mount).filter(Boolean);
  }
  window.KSIso = { mount, mountAll, cuboid, project };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => mountAll());
  else mountAll();
})();
