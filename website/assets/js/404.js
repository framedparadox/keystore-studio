/* 404 page: show the requested path on the certificate card. */
(function () {
  var el = document.getElementById("nf-path");
  if (!el || !location.pathname) return;
  var path = location.pathname;
  try { path = decodeURIComponent(path); } catch (e) {}
  el.textContent = path.slice(0, 120);
})();
