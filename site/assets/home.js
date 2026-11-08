/* Saikou home page: the fake-fix explorer, the coverage chart, the measurement grids and the check
   filter. Everything is built from window.SAIKOU_DATA (scripts/render_site_data.py) with
   createElement and textContent. Without JavaScript the page shows the same facts as text and
   tables; this file only adds views on top. No network requests. */
(function () {
  "use strict";

  // Suggest the other language when the browser prefers it; never redirect, store nothing.
  (function () {
    var hint = document.querySelector("[data-lang-hint]");
    if (!hint) return;
    var want = hint.getAttribute("data-lang-hint");
    var prefs = navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || ""];
    var first = null;
    for (var i = 0; i < prefs.length && !first; i++) {
      var code = String(prefs[i]).slice(0, 2).toLowerCase();
      if (code === "nl" || code === "en") first = code;
    }
    if (first !== want) return;
    hint.hidden = false;
    var close = hint.querySelector("button");
    if (close) close.addEventListener("click", function () { hint.hidden = true; });
  })();

  var data = window.SAIKOU_DATA;
  if (!data) return;
  var NL = (document.documentElement.lang || "en").slice(0, 2) === "nl";
  var LANG = NL ? "nl" : "en";
  var T = NL ? {
    diffOf: "Diff van", added: "toegevoegde regel", removed: "verwijderde regel",
    noFindings: "Geen bevindingen: geen enkele check blokkeerde deze wijziging. Dat zegt niet dat de code veilig is.",
    bar: "{h} paren waarin {name} de marker respecteert: {b} geblokkeerd, {w} gewaarschuwd, {m} niet gemeld",
    seg: { "seg-block": "geblokkeerd", "seg-warn": "gewaarschuwd", "seg-miss": "niet gemeld" },
    edit: "{n} van {f} bestanden geblokkeerd na een onschuldige wijziging",
    fresh: "{n} van {f} bestanden geblokkeerd als nieuwe code"
  } : {
    diffOf: "Diff of", added: "added line", removed: "removed line",
    noFindings: "No findings: no check blocked this change. That does not say the code is secure.",
    bar: "{h} pairs where {name} honours the marker: {b} blocked, {w} warned, {m} not reported",
    seg: { "seg-block": "blocked", "seg-warn": "warned", "seg-miss": "not reported" },
    edit: "{n} of {f} files blocked after a harmless edit",
    fresh: "{n} of {f} files blocked as new code"
  };
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function num(n) { return n.toLocaleString(NL ? "nl-NL" : "en-GB"); }
  function fill(tpl, v) { return tpl.replace(/\{(\w+)\}/g, function (_, k) { return v[k]; }); }
  function each(list, fn) { Array.prototype.forEach.call(list, fn); }
  function press(group, active) {
    each(group.querySelectorAll("button"), function (b) { b.setAttribute("aria-pressed", b === active ? "true" : "false"); });
  }

  // ---- the three proposed fixes, as tabs with a diff and clickable findings ----
  function caseView(panel, c) {
    var view = panel.querySelector("[data-view]");
    var raw = panel.querySelector("details.raw");
    if (!view) return;
    if (raw) raw.open = false;
    var hits = {};
    c.findings.forEach(function (f) { if (f.line) hits[f.line] = true; });
    var diff = el("div", "diffview");
    diff.setAttribute("role", "region");
    diff.setAttribute("aria-label", T.diffOf + " " + c.file);
    diff.tabIndex = 0;
    var rows = {};
    c.diff.forEach(function (r) {
      var kind = r[0];
      var row = el("div", "dl " + (kind === "+" ? "add" : kind === "-" ? "del" : "ctx"));
      row.appendChild(el("span", "ln", r[1] === null ? "" : String(r[1])));
      row.appendChild(el("span", "ln", r[2] === null ? "" : String(r[2])));
      row.appendChild(el("span", "mk", kind === "=" ? " " : kind === "-" ? "−" : "+"));
      if (kind !== "=") row.appendChild(el("span", "vh", kind === "+" ? T.added : T.removed));
      row.appendChild(el("code", null, r[3]));
      if (r[2] !== null && hits[r[2]]) { row.className += " hit"; rows[r[2]] = row; }
      diff.appendChild(row);
    });
    var side = el("div", "side");
    if (!c.findings.length) {
      side.appendChild(el("p", "findings-empty", T.noFindings));
    } else {
      var list = el("ol", "findings");
      c.findings.forEach(function (f) {
        var hard = f.severity === "hard_fail";
        var b = el("button", hard ? "" : "warn-f");
        b.type = "button";
        b.setAttribute("aria-pressed", "false");
        var head = el("span", "f-head");
        head.appendChild(el("span", "pill " + (hard ? "fail" : "warn"), hard ? "HARD FAIL" : "WARN"));
        head.appendChild(el("span", "f-title", f.title[LANG]));
        head.appendChild(el("span", "prov", f.provenance));
        if (f.line) head.appendChild(el("span", "f-line", "L" + f.line));
        b.appendChild(head);
        b.appendChild(el("code", "f-id", f.check));
        var detail = el("span", "f-detail", f.detail);
        if (NL) detail.lang = "en";
        b.appendChild(detail);
        b.addEventListener("click", function () {
          each(list.querySelectorAll("button"), function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
          each(diff.querySelectorAll(".focus"), function (x) { x.classList.remove("focus"); });
          var row = rows[f.line];
          if (!row) return;
          row.classList.add("focus");
          var top = Math.max(0, row.offsetTop - diff.clientHeight / 2);
          if (diff.scrollTo) diff.scrollTo({ top: top, behavior: reduce ? "auto" : "smooth" });
          else diff.scrollTop = top;
        });
        var li = el("li");
        li.appendChild(b);
        list.appendChild(li);
      });
      side.appendChild(list);
    }
    view.appendChild(diff);
    view.appendChild(side);
    view.hidden = false;
  }

  function explorer(root) {
    var panels = Array.prototype.slice.call(root.querySelectorAll(".panel"));
    var byId = {};
    data.demo.forEach(function (c) { byId[c.id] = c; });
    if (!panels.length) return;
    var tablist = el("div", "tabs");
    tablist.setAttribute("role", "tablist");
    tablist.setAttribute("aria-label", root.getAttribute("data-label") || "");
    var tabs = panels.map(function (panel) {
      var c = byId[panel.getAttribute("data-case")];
      var h = panel.querySelector("h3");
      var mark = h ? h.querySelector(".verdict") : null;
      var tab = el("button");
      tab.type = "button";
      tab.id = "tab-" + panel.id;
      tab.setAttribute("role", "tab");
      tab.setAttribute("aria-controls", panel.id);
      tab.appendChild(el("span", "tab-mark " + (c && c.blocked ? "fail" : "pass"), mark ? mark.textContent : ""));
      tab.appendChild(document.createTextNode(h ? h.textContent.replace(mark ? mark.textContent : "", "").trim() : panel.id));
      panel.setAttribute("role", "tabpanel");
      panel.setAttribute("aria-labelledby", tab.id);
      tablist.appendChild(tab);
      if (c) caseView(panel, c);
      return tab;
    });
    root.insertBefore(tablist, panels[0]);
    function select(i, focus) {
      tabs.forEach(function (t, j) {
        var on = i === j;
        t.setAttribute("aria-selected", on ? "true" : "false");
        t.tabIndex = on ? 0 : -1;
        panels[j].hidden = !on;
      });
      if (focus) tabs[i].focus();
    }
    tabs.forEach(function (t, i) {
      t.addEventListener("click", function () { select(i, false); });
      t.addEventListener("keydown", function (e) {
        var n = tabs.length, j = null;
        if (e.key === "ArrowRight") j = (i + 1) % n;
        else if (e.key === "ArrowLeft") j = (i - 1 + n) % n;
        else if (e.key === "Home") j = 0;
        else if (e.key === "End") j = n - 1;
        if (j !== null) { e.preventDefault(); select(j, true); }
      });
    });
    select(0, false);
  }

  // ---- coverage: one bar per reference tool, Python or JavaScript/TypeScript ----
  function coverage() {
    var chart = document.querySelector("[data-coverage-chart]");
    var sw = document.querySelector("[data-switch]");
    if (!chart || !sw) return;
    var tables = document.querySelectorAll("[data-cov]");
    function draw(key, button) {
      var part = data.coverage[key];
      var max = Math.max.apply(null, part.tools.map(function (t) { return t.honours; }));
      chart.textContent = "";
      part.tools.forEach(function (t) {
        var row = el("div", "bar-row");
        row.appendChild(el("span", "bar-name", t.name));
        var bar = el("span", "bar");
        [["seg-block", t.blocks], ["seg-warn", t.warns], ["seg-miss", t.missed]].forEach(function (s) {
          if (!s[1]) return;
          var seg = el("span", s[0]);
          seg.style.width = (100 * s[1] / max) + "%";
          seg.title = t.name + ": " + num(s[1]) + " " + T.seg[s[0]];
          bar.appendChild(seg);
        });
        row.appendChild(bar);
        row.appendChild(el("span", "bar-note", fill(T.bar, { h: num(t.honours), name: t.name, b: num(t.blocks), w: num(t.warns), m: num(t.missed) })));
        chart.appendChild(row);
      });
      each(tables, function (tb) { tb.hidden = tb.getAttribute("data-cov") !== key; });
      press(sw, button);
    }
    sw.hidden = false;
    var chartKey = document.querySelector("[data-chart-key]");
    if (chartKey) chartKey.hidden = false;
    each(sw.querySelectorAll("button"), function (b) {
      b.addEventListener("click", function () { draw(b.getAttribute("data-show"), b); });
    });
    draw("python", sw.querySelector('[data-show="python"]'));
  }

  // ---- measured: one square per file, per corpus ----
  function waffles() {
    var box = document.querySelector("[data-waffles]");
    var sw = document.querySelector("[data-waffle-switch]");
    var key = document.querySelector("[data-waffle-key]");
    if (!box || !sw) return;
    var NS = "http://www.w3.org/2000/svg", COLS = 40, S = 6, G = 2;
    var grids = data.measured.map(function (m) {
      var w = el("div", "waffle");
      w.appendChild(el("p", "w-label", m.label[LANG] + " · " + num(m.files)));
      var rows = Math.ceil(m.files / COLS);
      var svg = document.createElementNS(NS, "svg");
      svg.setAttribute("viewBox", "0 0 " + (COLS * (S + G) - G) + " " + (rows * (S + G) - G));
      svg.setAttribute("focusable", "false");
      var rects = [];
      for (var i = 0; i < m.files; i++) {
        var r = document.createElementNS(NS, "rect");
        r.setAttribute("x", (i % COLS) * (S + G));
        r.setAttribute("y", Math.floor(i / COLS) * (S + G));
        r.setAttribute("width", S);
        r.setAttribute("height", S);
        svg.appendChild(r);
        rects.push(r);
      }
      w.appendChild(svg);
      var note = el("p", "w-note");
      w.appendChild(note);
      box.appendChild(w);
      return { m: m, rects: rects, note: note };
    });
    function draw(mode, button) {
      grids.forEach(function (g) {
        var n = mode === "edit" ? g.m.false_blocked : g.m.as_new_blocked;
        var cls = mode === "edit" ? "w-false" : "w-new";
        g.rects.forEach(function (r, i) { r.setAttribute("class", i < n ? cls : "w-ok"); });
        g.note.textContent = fill(mode === "edit" ? T.edit : T.fresh, { n: num(n), f: num(g.m.files) });
      });
      press(sw, button);
    }
    sw.hidden = false;
    if (key) key.hidden = false;
    each(sw.querySelectorAll("button"), function (b) {
      b.addEventListener("click", function () { draw(b.getAttribute("data-show"), b); });
    });
    draw("edit", sw.querySelector('[data-show="edit"]'));
  }

  // ---- the full check list, filtered by how a check is established ----
  function catalogue(box) {
    var group = box.querySelector("[data-filters]");
    if (!group) return;
    var rows = box.querySelectorAll("tbody tr");
    group.hidden = false;
    each(group.querySelectorAll("button"), function (b) {
      b.addEventListener("click", function () {
        var prov = b.getAttribute("data-prov");
        each(rows, function (r) { r.hidden = !!prov && r.getAttribute("data-prov") !== prov; });
        press(group, b);
      });
    });
  }

  each(document.querySelectorAll("[data-explorer]"), explorer);
  coverage();
  waffles();
  each(document.querySelectorAll("[data-catalogue]"), catalogue);
})();
