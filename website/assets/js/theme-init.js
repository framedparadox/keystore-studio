/* Applies the saved theme before first paint. Load it synchronously in <head>, before the
   stylesheets. A file rather than an inline script so the CSP in _headers can forbid inline JS.
   Mirrors assets/js/site.js. */
(function () {
  var d = document.documentElement;
  d.classList.remove("no-js");
  d.classList.add("js");
  try {
    var t = localStorage.getItem("ks-theme");
    if (t === "light" || t === "dark") {
      d.setAttribute("data-theme", t);
      d.setAttribute("data-theme-pref", t);
    } else d.setAttribute("data-theme-pref", "system");
  } catch (e) {
    d.setAttribute("data-theme-pref", "system");
  }
})();
