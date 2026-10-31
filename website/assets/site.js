// meshvpn website: theme toggle, mobile menu, copy buttons, the current tutorial step.
(function () {
  var root = document.documentElement;
  try {
    var saved = localStorage.getItem("theme");
    if (saved === "dark" || saved === "light") root.setAttribute("data-theme", saved);
  } catch (e) {}

  document.addEventListener("DOMContentLoaded", function () {
    var t = document.querySelector(".theme-btn");
    if (t) t.addEventListener("click", function () {
      var dark = root.getAttribute("data-theme") === "dark" ||
        (!root.getAttribute("data-theme") && matchMedia("(prefers-color-scheme: dark)").matches);
      var next = dark ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("theme", next); } catch (e) {}
    });

    var m = document.querySelector(".menu-btn"), nav = document.querySelector(".nav");
    if (m && nav) m.addEventListener("click", function () {
      var open = nav.classList.toggle("open");
      m.setAttribute("aria-expanded", open ? "true" : "false");
    });

    // A copy button on every code block; prompts ("$ ") and comments aren't copied.
    document.querySelectorAll(".code").forEach(function (box) {
      var pre = box.querySelector("pre");
      if (!pre) return;
      var b = document.createElement("button");
      b.className = "copy"; b.type = "button"; b.textContent = "copy";
      b.addEventListener("click", function () {
        var clone = pre.cloneNode(true);
        clone.querySelectorAll(".p, .c, .o").forEach(function (n) { n.remove(); });
        var text = clone.textContent.replace(/[ \t]+$/gm, "").replace(/\n{2,}/g, "\n").trim();
        var done = function () { b.textContent = "copied"; setTimeout(function () { b.textContent = "copy"; }, 1600); };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(done, function () { select(pre); });
        } else { select(pre); }
      });
      box.appendChild(b);
    });
    function select(el) { var r = document.createRange(); r.selectNodeContents(el); var s = getSelection(); s.removeAllRanges(); s.addRange(r); }

    // Tutorials: mark the step in view.
    var links = document.querySelectorAll(".tut-nav a[href^='#']");
    if (links.length && "IntersectionObserver" in window) {
      var map = {};
      links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
      var io = new IntersectionObserver(function (es) {
        es.forEach(function (e) {
          if (e.isIntersecting && map[e.target.id]) {
            links.forEach(function (a) { a.classList.remove("on"); });
            map[e.target.id].classList.add("on");
          }
        });
      }, { rootMargin: "-20% 0px -70% 0px" });
      Object.keys(map).forEach(function (id) { var s = document.getElementById(id); if (s) io.observe(s); });
    }
  });
})();
