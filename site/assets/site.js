/* Theme toggle, copy buttons, mobile menu, client-side search, table-of-contents highlight. No dependencies. */
(function () {
  var root = document.documentElement;
  try { var t = localStorage.getItem("vs-theme"); if (t) root.setAttribute("data-theme", t); } catch (e) {}

  document.addEventListener("click", function (e) {
    var b = e.target.closest(".copy");
    if (b) {
      var code = b.parentNode.querySelector("code").innerText;
      (navigator.clipboard ? navigator.clipboard.writeText(code) : Promise.reject()).then(
        function () { b.textContent = "Copied"; setTimeout(function () { b.textContent = "Copy"; }, 1400); },
        function () { b.textContent = "Press Ctrl+C"; });
      return;
    }
    if (e.target.closest("#theme")) {
      var cur = root.getAttribute("data-theme") || "light";
      var n = cur === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", n);
      try { localStorage.setItem("vs-theme", n); } catch (x) {}
      return;
    }
    var m = e.target.closest("#menu");
    if (m) { var s = document.getElementById("side"); m.setAttribute("aria-expanded", String(s.classList.toggle("open"))); return; }
    if (!e.target.closest("#results") && e.target.id !== "q") { var r = document.getElementById("results"); if (r) r.style.display = "none"; }
  });

  // search
  var q = document.getElementById("q"), res = document.getElementById("results"), index = null;
  function load(cb) {
    if (index) return cb();
    fetch(document.documentElement.getAttribute("data-base") + "search.json").then(function (r) { return r.json(); }).then(function (j) { index = j; cb(); }).catch(function () { index = []; cb(); });
  }
  function show(term) {
    var t = term.toLowerCase().trim();
    if (!t) { res.style.display = "none"; return; }
    var hits = index.map(function (p) {
      var s = 0; if (p.title.toLowerCase().indexOf(t) >= 0) s += 10;
      p.heads.forEach(function (h) { if (h.toLowerCase().indexOf(t) >= 0) s += 4; });
      if (p.text.toLowerCase().indexOf(t) >= 0) s += 1;
      return { p: p, s: s };
    }).filter(function (x) { return x.s > 0; }).sort(function (a, b) { return b.s - a.s; }).slice(0, 8);
    var base = document.documentElement.getAttribute("data-base");
    res.textContent = "";
    function row(href, title, desc) {
      var a = document.createElement("a"), s = document.createElement("small");
      a.href = href; a.appendChild(document.createTextNode(title));
      s.textContent = desc; a.appendChild(s); res.appendChild(a);
    }
    if (hits.length) hits.forEach(function (x) { row(base + x.p.url, x.p.title, x.p.desc); });
    else row("#", "No match", 'Try a rule id such as VS-SECRET-001, or "baseline"');
    res.style.display = "block";
  }
  if (q) {
    q.addEventListener("input", function () { load(function () { show(q.value); }); });
    q.addEventListener("focus", function () { if (q.value) load(function () { show(q.value); }); });
    document.addEventListener("keydown", function (e) {
      if ((e.key === "/" || (e.key === "k" && (e.ctrlKey || e.metaKey))) && document.activeElement.tagName !== "INPUT") { e.preventDefault(); q.focus(); }
      if (e.key === "Escape") { res.style.display = "none"; q.blur(); }
    });
  }

  // highlight current heading in the table of contents
  var links = [].slice.call(document.querySelectorAll(".toc a"));
  if (links.length && "IntersectionObserver" in window) {
    var map = {}; links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (en) { if (en.isIntersecting && map[en.target.id]) { links.forEach(function (l) { l.classList.remove("on"); }); map[en.target.id].classList.add("on"); } });
    }, { rootMargin: "-10% 0px -80% 0px" });
    Object.keys(map).forEach(function (id) { var el = document.getElementById(id); if (el) io.observe(el); });
  }
})();
