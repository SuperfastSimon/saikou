/* Saikou in-browser checker: paste the code before and after a change, see what the change shows.
   Pattern checks only: counts of markers, phrases and code patterns, and text comparisons.
   No syntax tree, no analyser, no network. */
(function () {
  var LANG = (document.documentElement.lang || "en").slice(0, 2) === "nl" ? "nl" : "en";
  var T = {
    en: {
      noChange: ["Nothing changed", "Before and After are identical, so nothing was fixed."],
      newSup: function (k, b, a) { return ["New suppression: " + k, k + ": " + b + "× in Before, " + a + "× in After. A suppression repairs nothing; it only stops a tool from reporting the finding."]; },
      elision: function (m) { return ["Possible placeholder: \"" + m + "\"", "After contains this text, which often stands in for code that was left out. Check that After is the whole file before you apply it."]; },
      cosmetic: ["Looks like only comments or whitespace changed", "With whitespace and all text after # or // removed, Before and After are identical. This page also removes that text inside strings (a URL, for example), so check the changed lines yourself."],
      newSink: function (l, b, a) { return ["New dangerous pattern: " + l, l + ": " + b + "× in Before, " + a + "× in After, so the change added at least one. That is a hard fail, whatever the rest of the change does."]; },
      stillThere: function (l, b, a) { return ["Still there: " + l, l + ": " + b + "× in Before, " + a + "× in After. The count did not go up, but the pattern is still there. This page only counts, so it cannot tell whether it is the same one."]; },
      removed: function (l, b) { return ["Removed: " + l, l + ": " + b + "× in Before, 0× in After. The code changed here, which does not show that the replacement is correct."]; },
      nothing: ["No check reported anything", "This page looks only for the patterns listed under How to read the result; anything else is not checked."],
      empty: "Paste code in both Before and After, then press Check.",
      v_fail: ["Blocked", "This change does not pass as a fix. The hard fails below say why."],
      v_warn: ["Still open", "No hard fail, but a dangerous pattern from Before also appears in After. See the warnings below."],
      v_pass: ["No check blocked it", "None of the checks on this page blocked this change. That is not a verdict that the code is secure."],
      count: function (n) { return n + (n === 1 ? " finding. " : " findings. "); },
      hard: "Hard fail", warn: "Warn", pass: "Pass",
      labels: { shell_true: "shell=True", verify_false: "verify=False (TLS check off)", debug_true: "debug=True", eval_exec: "eval() or exec() on a variable", weak_hash: "md5 or sha1 (weak hash)", hardcoded_secret: "possible hardcoded secret" }
    },
    nl: {
      noChange: ["Niets veranderd", "Voor en Na zijn identiek, dus er is niets gefixt."],
      newSup: function (k, b, a) { return ["Nieuwe onderdrukking: " + k, k + ": " + b + "× in Voor, " + a + "× in Na. Een onderdrukking repareert niets; ze zorgt alleen dat een tool de bevinding niet meldt."]; },
      elision: function (m) { return ["Mogelijke plaatshouder: \"" + m + "\"", "Na bevat deze tekst, die vaak staat voor weggelaten code. Controleer of Na het hele bestand is voordat je het toepast."]; },
      cosmetic: ["Lijkt alleen commentaar of witruimte veranderd", "Zonder witruimte en zonder alle tekst na # of // zijn Voor en Na identiek. Deze pagina haalt die tekst ook binnen strings weg (een URL bijvoorbeeld), dus bekijk de gewijzigde regels zelf."],
      newSink: function (l, b, a) { return ["Nieuw gevaarlijk patroon: " + l, l + ": " + b + "× in Voor, " + a + "× in Na, dus de wijziging voegde er minstens één toe. Dat is een hard fail, wat de rest van de wijziging ook doet."]; },
      stillThere: function (l, b, a) { return ["Staat er nog: " + l, l + ": " + b + "× in Voor, " + a + "× in Na. Het aantal is niet gestegen, maar het patroon staat er nog. Deze pagina telt alleen, dus ze ziet niet of het om dezelfde plek gaat."]; },
      removed: function (l, b) { return ["Verwijderd: " + l, l + ": " + b + "× in Voor, 0× in Na. De code is hier veranderd, maar dat laat niet zien dat de vervanging klopt."]; },
      nothing: ["Geen check meldde iets", "Deze pagina zoekt alleen naar de patronen onder Zo lees je het resultaat; al het andere wordt niet gecontroleerd."],
      empty: "Plak code in zowel Voor als Na en klik op Controleer.",
      v_fail: ["Geblokkeerd", "Deze wijziging gaat niet door als fix. De hard fails hieronder zeggen waarom."],
      v_warn: ["Nog open", "Geen hard fail, maar een gevaarlijk patroon uit Voor komt ook in Na voor. Zie de waarschuwingen hieronder."],
      v_pass: ["Niet geblokkeerd", "Geen van de checks op deze pagina blokkeerde deze wijziging. Dat is geen oordeel dat de code veilig is."],
      count: function (n) { return n + (n === 1 ? " bevinding. " : " bevindingen. "); },
      hard: "Hard fail", warn: "Waarschuwing", pass: "Pass",
      labels: { shell_true: "shell=True", verify_false: "verify=False (TLS-controle uit)", debug_true: "debug=True", eval_exec: "eval() of exec() op een variabele", weak_hash: "md5 of sha1 (zwakke hash)", hardcoded_secret: "mogelijk hardcoded geheim" }
    }
  }[LANG];
  // analyse() tags some checks "structural". The site's provenance labels are tool, parser and
  // mechanical, and every check on this page is a text count or comparison, so all show as mechanical.
  var PROV = { mechanical: "mechanical", structural: "mechanical" };

  var MARKERS = [
    ["# nosec", /#\s*nosec\b/gi], ["# noqa", /#\s*noqa\b/gi], ["// eslint-disable", /\/\/\s*eslint-disable/gi],
    ["@ts-ignore / @ts-nocheck", /@ts-(ignore|nocheck)\b/gi], ["@SuppressWarnings", /@SuppressWarnings/gi],
    ["#pragma warning disable", /#pragma\s+warning\s+disable/gi], ["# type: ignore", /#\s*type:\s*ignore/gi],
    ["usedforsecurity=False", /usedforsecurity\s*=\s*False/gi]
  ];
  var ELISIONS = [
    /(rest (of the code )?unchanged|rest blijft (hetzelfde|ongewijzigd))/i,
    /omitted for brevity/i, /implementation (goes )?here/i,
    /^\s*\.\.\.\s*$/m
  ];
  var SINKS = [
    ["shell_true", /shell\s*=\s*True/g], ["verify_false", /verify\s*=\s*False/g], ["debug_true", /debug\s*=\s*True/g],
    ["eval_exec", /\b(eval|exec)\s*\(\s*[a-zA-Z_]/g], ["weak_hash", /\b(md5|sha1)\s*\(/gi],
    ["hardcoded_secret", /(password|secret|api[_-]?key|token)\s*=\s*["'][^"'\n]{8,}["']/gi]
  ];

  function count(text, re) { var m = text.match(new RegExp(re.source, re.flags.replace("g", "") + "g")); return m ? m.length : 0; }
  function normalise(code) {
    return code.replace(/#.*$/gm, "").replace(/\/\/.*$/gm, "").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\s+/g, " ").trim();
  }

  function analyse(before, after) {
    var f = [], equal = before.trim() === after.trim();
    function add(verdict, prov, pair) { f.push({ verdict: verdict, prov: prov, title: pair[0], detail: pair[1] }); }
    if (equal) add("fail", "mechanical", T.noChange);
    MARKERS.forEach(function (m) { var b = count(before, m[1]), a = count(after, m[1]); if (a > b) add("fail", "mechanical", T.newSup(m[0], b, a)); });
    ELISIONS.forEach(function (re) { var m = after.match(re); if (m) add("fail", "mechanical", T.elision(m[0].trim())); });
    if (!equal && normalise(before) === normalise(after)) add("fail", "structural", T.cosmetic);
    SINKS.forEach(function (s) {
      var label = T.labels[s[0]], b = count(before, s[1]), a = count(after, s[1]);
      if (a > b) add("fail", "structural", T.newSink(label, b, a));
      else if (a > 0) add("warn", "structural", T.stillThere(label, b, a));
      else if (b > 0) add("pass", "structural", T.removed(label, b));
    });
    if (!f.length) add("pass", "mechanical", T.nothing);
    return f;
  }

  function overall(f) {
    var top = 0, rank = { fail: 3, warn: 2, pass: 1 };
    f.forEach(function (x) { if (rank[x.verdict] > top) top = rank[x.verdict]; });
    return top === 3 ? ["fail", T.v_fail] : top === 2 ? ["warn", T.v_warn] : ["pass", T.v_pass];
  }

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }

  var PRESETS = {
    fake: ["import subprocess\n\ndef run_backup(cmd):\n    subprocess.call(cmd, shell=True)\n    log.info(\"backup done\")\n",
           "import subprocess\n\ndef run_backup(cmd):\n    subprocess.call(cmd, shell=True)  # nosec - reviewed and fixed\n    log.info(\"backup done\")\n"],
    real: ["import subprocess\n\ndef run_backup(src, dst):\n    cmd = f\"rsync -a {src} {dst}\"\n    subprocess.call(cmd, shell=True)\n",
           "import subprocess\n\ndef run_backup(src, dst):\n    subprocess.call([\"rsync\", \"-a\", src, dst], shell=False)\n"],
    secret: ["import os\nimport stripe\n\ndef get_client():\n    key = os.environ[\"STRIPE_KEY\"]\n    return stripe.Client(key)\n",
             "import stripe\n\ndef get_client():\n    # env var kept crashing in staging, hardcoded for now\n    api_key = \"sk_live_51Hn0000000000000000000\"\n    return stripe.Client(api_key)\n"]
  };

  var b = document.getElementById("ta-before"), a = document.getElementById("ta-after");
  var stamp = document.getElementById("stamp"), summary = document.getElementById("summary"), rows = document.getElementById("rows");

  function run() {
    rows.textContent = "";
    // Empty state: an empty box is not a change to check.
    if (!b.value.trim() || !a.value.trim()) {
      stamp.textContent = "—"; stamp.className = "stamp"; summary.textContent = T.empty;
      return;
    }
    var f = analyse(b.value, a.value), v = overall(f);
    var onlyNothing = f.length === 1 && f[0].title === T.nothing[0];
    stamp.textContent = v[1][0]; stamp.className = "stamp " + v[0];
    summary.textContent = (onlyNothing ? "" : T.count(f.length)) + v[1][1];
    f.forEach(function (x) {
      var row = el("div", "row"), body = el("div");
      var pill = el("span", "pill " + x.verdict, x.verdict === "fail" ? T.hard : x.verdict === "warn" ? T.warn : T.pass);
      var chip = el("span", "chip", PROV[x.prov] || x.prov);
      // On the Dutch page the English pill words and the provenance label are marked as English.
      if (LANG === "nl") { chip.lang = "en"; if (x.verdict !== "warn") pill.lang = "en"; }
      row.appendChild(pill); row.appendChild(chip);
      body.appendChild(el("b", "", x.title)); body.appendChild(el("p", "", x.detail));
      row.appendChild(body); rows.appendChild(row);
    });
  }

  // After a click, bring the result into view when the stamp is off-screen (an instant jump, no animation).
  function reveal() {
    var r = stamp.getBoundingClientRect(), h = window.innerHeight || document.documentElement.clientHeight;
    if (r.top < 0 || r.bottom > h) {
      var s = stamp.closest ? stamp.closest("section") : null;
      if (s) s.scrollIntoView({ block: "start" });
    }
  }

  document.querySelectorAll("[data-preset]").forEach(function (btn) {
    btn.addEventListener("click", function () { var p = PRESETS[btn.getAttribute("data-preset")]; b.value = p[0]; a.value = p[1]; run(); reveal(); });
  });
  document.getElementById("run").addEventListener("click", function () { run(); reveal(); });
  b.value = PRESETS.fake[0]; a.value = PRESETS.fake[1]; run();
})();
