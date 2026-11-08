"""The catalogue of everything Saikou can report, in English and Dutch.

One source of truth for the Checks screen of the app, `GET /v1/checks`, and the docs.
tests/test_catalog.py fails if the engine emits a check that is not described here, or if
the provenance listed here disagrees with what a report would show.
"""

from __future__ import annotations

from typing import Dict, List, Optional

# severity: "hard" (blocks), "warn" (reported, does not block), "depends" (see description)
# modes: "verify" (judging a claimed fix), "gate" (change gating), "both"
# applies: "python", "javascript" (JS/TS), "config" (analyser config files), "all", "harden"
_E: List[dict] = []


def _c(cid: str, prov: str, sev: str, applies: str, modes: str, title: Dict[str, str],
       desc: Dict[str, str], bad: str = "", good: str = "") -> None:
    _E.append({"id": cid, "provenance": prov, "severity": sev, "applies": applies,
               "modes": modes, "title": title, "description": desc, "example_bad": bad,
               "example_good": good})


def _t(en: str, nl: str) -> Dict[str, str]:
    return {"en": en, "nl": nl}


# ---- suppression and configuration -----------------------------------------------------
_c("suppression_introduced", "mechanical", "hard", "all", "both",
   _t("New analyser suppression", "Nieuwe analyzer-onderdrukking"),
   _t("A suppression marker (nosec, NOSONAR, lgtm or codeql[...], nosemgrep, noqa: S..., "
      "eslint-disable on a security rule, usedforsecurity=False, ...) appears more often than "
      "before. Counted per marker kind, so editing a line that was already suppressed is not "
      "flagged. In Python, comment markers count only in real comments, which is where bandit "
      "1.7.3+, Sonar and CodeQL read them; a marker inside a string literal, such as fake-fix test "
      "data, is not counted. bandit 1.7.0-1.7.2 did honour one there, so the analyser extra "
      "requires 1.7.3. noqa and nosemgrep still count anywhere on the line, because flake8 and "
      "semgrep match the raw line. A word glued to a marker (nosecure) counts, because bandit "
      "reads it as a bare marker, and so does a marker that only shows after decoding the "
      "declared source encoding. usedforsecurity set to anything but True counts. A marker "
      "moved onto code that had none, while the number of markers stays the same, is reported "
      "too (in Python, per statement). Python that does not tokenize is counted as text. In "
      "change gating only markers that silence a security analyser block; a bare noqa "
      "counts as one on a statement that makes a call bandit reports (subprocess, eval, yaml.load, "
      "md5, pickle, ...), usedforsecurity does on password material, and other type and style "
      "markers become a warning. In JavaScript and TypeScript, block comments count as well, an "
      "ESLint directive without a rule list counts as a security suppression where it covers a "
      "line that holds a risky call (eval, new Function, child_process, fs, innerHTML, ...), a "
      "marker moved onto another line is reported, and a TypeScript directive is a warning.",
      "Een onderdrukkingsmarker (nosec, NOSONAR, lgtm of codeql[...], nosemgrep, noqa: S..., "
      "eslint-disable op een beveiligingsregel, usedforsecurity=False, ...) komt vaker voor dan "
      "eerst. Geteld per soort, dus een al onderdrukte regel aanpassen wordt niet gemeld. In "
      "Python tellen commentaarmarkers alleen in echt commentaar, waar bandit 1.7.3+, Sonar en "
      "CodeQL ze lezen; een marker binnen een string, zoals nepfix-testdata, telt niet. bandit "
      "1.7.0-1.7.2 volgde daar wel een marker, dus de analyser-extra vereist 1.7.3. noqa en "
      "nosemgrep tellen overal op de regel, omdat flake8 en semgrep de ruwe regel lezen. Een "
      "woord vast aan een marker (nosecure) telt, omdat bandit het als kale marker leest, en een "
      "marker die pas na decoderen met de opgegeven broncodering zichtbaar wordt ook. "
      "usedforsecurity op iets anders dan True telt. Een marker die naar code zonder marker is "
      "verhuisd, terwijl het aantal markers gelijk blijft, wordt ook gemeld (in Python per "
      "statement). Python die niet te tokenizen is, wordt als tekst geteld. Bij "
      "wijzigingscontrole blokkeren alleen markers die een beveiligingsanalyzer het zwijgen "
      "opleggen; een kale noqa telt daarbij op een statement met een aanroep die bandit meldt "
      "(subprocess, eval, yaml.load, md5, pickle, ...), usedforsecurity op wachtwoordmateriaal, "
      "en overige type- en stijlmarkers worden een waarschuwing. In JavaScript en TypeScript "
      "tellen ook blokcommentaren, telt een ESLint-directive zonder regellijst als "
      "beveiligingsonderdrukking waar hij een regel met een risicovolle aanroep dekt (eval, new "
      "Function, child_process, fs, innerHTML, ...), wordt een naar een andere regel verhuisde "
      "marker gemeld, en is een TypeScript-directive een waarschuwing."),
   "subprocess.call(cmd, shell=True)  # nosec B602", "subprocess.run(args, shell=False)")
_c("suppression_added", "mechanical", "warn", "all", "gate",
   _t("Type/style suppression added", "Type-/stijlonderdrukking toegevoegd"),
   _t("A type-checker or style suppression (type: ignore, ts-ignore, pylint disable, ...) was "
      "added in a change. Not blocking: this is ordinary engineering, but worth a glance.",
      "Een onderdrukking voor type-checker of stijl (type: ignore, ts-ignore, pylint disable, ...) "
      "is toegevoegd in een wijziging. Niet blokkerend: dit is gewoon ontwikkelwerk, maar een blik "
      "waard."),
   "x = load()  # type: ignore")
_c("analyser_config_touched", "mechanical", "hard", "all", "verify",
   _t("Analyser config referenced in output", "Analyzer-config genoemd in uitvoer"),
   _t("The proposed output names an analyser configuration file (.bandit, pyproject.toml, "
      ".semgrepignore, ...) that the input did not. Suppression moved out of band is still "
      "suppression.",
      "De voorgestelde uitvoer noemt een analyzer-configuratiebestand (.bandit, pyproject.toml, "
      ".semgrepignore, ...) dat de invoer niet noemde. Onderdrukking buiten het bestand is nog "
      "steeds onderdrukking."))
_c("analyser_config_weakened", "mechanical", "hard", "config", "gate",
   _t("Security analyser configuration weakened", "Beveiligingsanalyzer-config verzwakt"),
   _t("In a changed config file: new skips under [tool.bandit], security rules ignored in "
      "ruff/flake8 (S rules, except S101 which only warns), new .semgrepignore / .gitleaksignore "
      "entries, security ESLint rules switched off, Sonar exclusions, gosec disabled. Comments and "
      "unrelated keys are ignored.",
      "In een gewijzigd configbestand: nieuwe skips onder [tool.bandit], beveiligingsregels "
      "genegeerd in ruff/flake8 (S-regels, behalve S101 dat alleen waarschuwt), nieuwe "
      ".semgrepignore-/.gitleaksignore-regels, beveiligings-ESLint-regels uitgezet, "
      "Sonar-uitsluitingen, gosec uitgeschakeld. Commentaar en niet-gerelateerde sleutels tellen "
      "niet mee."),
   "[tool.bandit]\nskips = [\"B602\"]")
_c("linter_config_relaxed", "mechanical", "warn", "config", "gate",
   _t("Linter configuration relaxed", "Linter-config versoepeld"),
   _t("A style or type linter was relaxed in a config file. Not a security analyser, so it only "
      "warns.",
      "Een stijl- of type-linter is versoepeld in een configbestand. Geen beveiligingsanalyzer, "
      "dus alleen een waarschuwing."))

# ---- completeness -----------------------------------------------------------------------
_c("content_not_checked", "mechanical", "hard", "all", "gate",
   _t("Changed file could not be checked", "Gewijzigd bestand kon niet worden gecontroleerd"),
   _t("The new version of a changed file in a language Saikou checks (by its extension or, "
      "for a script without a recognised one, by its #! line), or of an analyser "
      "configuration file, could not be checked: it has a NUL byte in its first 8 KB (UTF-16 "
      "and UTF-32 with a byte-order mark are read as text), it is larger than 1,000,000 bytes, "
      "it could not be read from the work tree, or the path is now a symbolic link or a "
      "submodule. Change gating blocks such a file instead of skipping it. Otherwise one NUL "
      "byte in a comment, padding past the size limit, or a symlink swapped for a file would "
      "let any change in it through unchecked. When only the old version is unreadable, the "
      "new one is checked as if the file were new. A file that is meant to be like this, such "
      "as a large vendored bundle, can be left out with a pathspec "
      "(-- . ':(exclude)vendor/bundle.js'); --warn-only content_not_checked demotes the check "
      "for every file. Files in languages Saikou does not check are still skipped and listed.",
      "De nieuwe versie van een gewijzigd bestand in een taal die Saikou controleert (volgens "
      "de extensie of, bij een script zonder herkende extensie, volgens de #!-regel), of van "
      "een configuratiebestand van een analyzer, kon niet worden gecontroleerd: er staat een "
      "NUL-byte in de eerste 8 KB (UTF-16 en UTF-32 met een byte-order mark worden als tekst "
      "gelezen), het is groter dan 1.000.000 bytes, het kon niet uit de werkmap worden "
      "gelezen, of het pad is nu een symbolische link of een submodule. De wijzigingscontrole "
      "blokkeert zo'n bestand in plaats van het over te slaan. Anders zou elke wijziging in dat "
      "bestand ongecontroleerd doorgaan, door één NUL-byte in commentaar, door opvulling tot "
      "voorbij de grens, of door een symbolische link die door een bestand wordt vervangen. Is "
      "alleen de oude versie onleesbaar, dan wordt de nieuwe gecontroleerd alsof het bestand "
      "nieuw is. Een bestand dat zo hoort te zijn, zoals een grote meegeleverde bundel, laat je "
      "weg met een pathspec (-- . ':(exclude)vendor/bundle.js'); --warn-only "
      "content_not_checked maakt de check voor elk bestand een waarschuwing. Bestanden in talen "
      "die Saikou niet controleert, worden nog steeds overgeslagen en vermeld."),
   "/* \\0 */ module.exports = (s) => eval(s);")
_c("elided_output", "mechanical", "hard", "all", "both",
   _t("Dropped code marker", "Marker voor weggelaten code"),
   _t("The output contains a phrase like 'rest unchanged', 'implementation here' or "
      "'// ... existing code ...'. Applying it would delete the omitted code. Markers inside "
      "string literals and docstrings are ignored. 'keep the existing code' counts only when it "
      "ends the clause or is followed by here, below, unchanged or as is; in prose such as 'keep "
      "the existing code style' it does not. In change gating, only strong markers block.",
      "De uitvoer bevat een zin als 'rest unchanged', 'implementation here' of "
      "'// ... existing code ...'. Toepassen zou de weggelaten code verwijderen. Markers in "
      "stringliteralen en docstrings tellen niet. 'keep the existing code' telt alleen als de "
      "zin daarmee eindigt of er 'here', 'below', 'unchanged' of 'as is' op volgt; in proza zoals "
      "'keep the existing code style' telt het niet. Bij wijzigingscontrole blokkeren alleen "
      "sterke markers."),
   "def f():\n    # rest of the function unchanged")
_c("elision_phrase", "mechanical", "warn", "all", "gate",
   _t("Reads like dropped code", "Lijkt op weggelaten code"),
   _t("New text such as 'same as above' or 'for brevity'. Usually prose, so it only warns.",
      "Nieuwe tekst als 'same as above' of 'for brevity'. Meestal gewone tekst, dus alleen een "
      "waarschuwing."))
_c("body_gutted", "parser", "hard", "python", "both",
   _t("Function body emptied", "Functiebody leeggemaakt"),
   _t("A function or class that had statements now has only '...' or 'pass'. The implementation "
      "was dropped. A bare '...' that was already there (a Protocol stub) is fine.",
      "Een functie of klasse met statements bevat nu alleen '...' of 'pass'. De implementatie is "
      "weggehaald. Een al bestaande kale '...' (Protocol-stub) is prima."))
_c("empty_output", "mechanical", "hard", "all", "both",
   _t("Output contains no code", "Uitvoer bevat geen code"), _t(
       "The proposed output is empty. In change gating a newly added empty file (such as "
       "tests/__init__.py) is ordinary and not reported.",
       "De voorgestelde uitvoer is leeg. Bij wijzigingscontrole is een nieuw toegevoegd leeg "
       "bestand (zoals tests/__init__.py) gewoon en wordt het niet gemeld."))
_c("truncated_output", "mechanical", "warn", "all", "both",
   _t("Output may be cut off", "Uitvoer mogelijk afgekapt"),
   _t("The last line ends in the middle of an expression.",
      "De laatste regel eindigt midden in een expressie."))
_c("unbalanced_delimiters", "mechanical", "warn", "all", "both",
   _t("Unclosed brackets", "Niet-gesloten haakjes"),
   _t("More opening than closing brackets (a raw count, so string literals can cause noise).",
      "Meer openende dan sluitende haakjes (een ruwe telling, dus stringliteralen kunnen ruis "
      "geven)."))
_c("size_collapse", "mechanical", "warn", "all", "verify",
   _t("Output far shorter than input", "Uitvoer veel korter dan invoer"),
   _t("A complete module was requested but the output has under 60% of the input's non-blank "
      "lines.",
      "Een compleet bestand werd gevraagd maar de uitvoer heeft minder dan 60% van de "
      "niet-lege regels van de invoer."))
_c("no_change", "mechanical", "hard", "all", "verify",
   _t("Nothing changed", "Niets veranderd"),
   _t("The output is identical to the input, so nothing was fixed. Only checked when a fix is "
      "claimed; an ordinary change may leave a file as it was.",
      "De uitvoer is identiek aan de invoer, dus niets is gefixt. Alleen gecontroleerd wanneer een "
      "fix wordt beweerd; een gewone wijziging mag een bestand laten zoals het was."))
_c("cosmetic_only_change", "parser", "hard", "python", "verify",
   _t("Only comments or whitespace changed", "Alleen commentaar of witruimte veranderd"),
   _t("The syntax tree is identical before and after: the edit was comments only, so no "
      "executable behaviour changed.",
      "De syntaxboom is voor en na identiek: de wijziging was alleen commentaar, dus er veranderde "
      "geen uitvoerbaar gedrag."))
_c("parse_failure", "parser", "hard", "python", "both",
   _t("Output no longer parses", "Uitvoer parset niet meer"),
   _t("The input parsed as Python but the output does not. It cannot be verified and would "
      "break at import. Code that nests too deeply for Python to parse or analyse (a very long "
      "chain of +, say, where Python raises RecursionError or MemoryError) blocks too, in either "
      "version and in both modes, because it was not analysed.",
      "De invoer parsete als Python maar de uitvoer niet. Het kan niet worden geverifieerd en "
      "zou bij importeren breken. Code die te diep genest is om door Python te laten parsen of "
      "analyseren (bijvoorbeeld een heel lange reeks +, waarbij Python RecursionError of "
      "MemoryError geeft) blokkeert ook, in beide versies en in beide modi, omdat die niet is "
      "geanalyseerd."))
_c("parse_skipped", "parser", "warn", "python", "both",
   _t("Neither version parses", "Geen van beide versies parset"),
   _t("Both versions fail to parse as Python (a template, Python 2, or a fragment). AST checks "
      "were skipped; only text checks ran.",
      "Beide versies parsen niet als Python (template, Python 2 of een fragment). AST-checks "
      "zijn overgeslagen; alleen tekstchecks draaiden."))

# ---- dangerous sinks --------------------------------------------------------------------
_SINK = _t("Values count as the file itself fixes them: a constant, not, and/or, bool(...), or a "
           "name assigned exactly once in the file with name = value (also a function called "
           "through such a name, as in _e = eval). A parameter, a call result or a name "
           "assigned more than once is unknown and never counts; a list, dict or set counts "
           "through its name only when the name is used nowhere but as **name. "
           "A sink that is new in the output always blocks. One that was already there blocks "
           "only when a fix for that threat class was claimed; otherwise it is a warning "
           "naming what was left alone.",
           "Waarden tellen zoals het bestand ze zelf vastlegt: een constante, not, and/or, "
           "bool(...), of een naam die precies één keer in het bestand wordt toegekend met "
           "naam = waarde (ook een functie die via zo'n naam wordt aangeroepen, zoals "
           "_e = eval). Een parameter, de uitkomst van een aanroep of een naam die vaker wordt "
           "toegekend is onbekend en telt nooit; een list, dict of set telt via zijn naam alleen "
           "als die naam nergens anders dan als **naam wordt gebruikt. "
           "Een sink die nieuw is in de uitvoer blokkeert altijd. Eentje die er al was blokkeert "
           "alleen als een fix voor die dreigingsklasse werd beweerd; anders is het een "
           "waarschuwing die benoemt wat is blijven staan.")


def _sink(cid: str, en: str, nl: str, ed: str, nd: str, bad: str, good: str) -> None:
    _c(cid, "parser", "depends", "python", "both", _t(en, nl),
       _t(ed + " " + _SINK["en"], nd + " " + _SINK["nl"]), bad, good)


_sink("sink_shell_true", "shell=True", "shell=True",
      "A call runs its command through a shell, so injected text becomes commands: shell= "
      "is true (True, 1, not False, ...), also when passed in **{...} or **dict(...).",
      "Een aanroep laat zijn commando via een shell lopen, waardoor ingevoegde tekst "
      "commando's wordt: shell= is waar (True, 1, not False, ...), ook als het via **{...} of "
      "**dict(...) wordt meegegeven.",
      "subprocess.call(\"rsync \" + src, shell=True)", "subprocess.run([\"rsync\", src])")
_sink("sink_tls_verify_off", "TLS verification off", "TLS-controle uit",
      "Certificate checking is switched off: verify= is false (False, 0, None, bool(0), ...) "
      "in a call, also via **{...}, or an attribute is set that way (session.verify = False).",
      "De certificaatcontrole staat uit: verify= is onwaar (False, 0, None, bool(0), ...) in "
      "een aanroep, ook via **{...}, of een attribuut wordt zo gezet (session.verify = False).",
      "requests.get(url, verify=False)", "requests.get(url)")
_sink("sink_debug_true", "debug=True", "debug=True",
      "A web app runs in debug mode, exposing an interactive console: run(...) with debug= "
      "true.",
      "Een webapp draait in debugmodus en toont een interactieve console: run(...) met "
      "debug= waar.",
      "app.run(debug=True)", "app.run()")
_sink("sink_dynamic_exec", "eval/exec on a variable", "eval/exec op een variabele",
      "eval() or exec() on something that is not a literal.",
      "eval() of exec() op iets dat geen literal is.",
      "eval(user_input)", "ast.literal_eval(user_input)")
_sink("sink_sql_interpolated", "SQL built by interpolation", "SQL door samenvoegen",
      "A query string is built with an f-string, % or + and passed to execute().",
      "Een querystring wordt met f-string, % of + opgebouwd en aan execute() gegeven.",
      "cur.execute(f\"SELECT * FROM t WHERE n='{n}'\")", "cur.execute(\"SELECT * FROM t WHERE n=?\", (n,))")
_sink("sink_sql_nonparameterised", "SQL without parameters", "SQL zonder parameters",
      "execute() receives a computed string and no parameter argument, or an empty one "
      "((), [], {}, None). A string literal, or a name assigned one once, is not computed.",
      "execute() krijgt een berekende string zonder parameterargument, of met een leeg "
      "((), [], {}, None). Een stringliteral, of een naam die er één keer een krijgt, is niet "
      "berekend.",
      "cur.execute(query)", "cur.execute(query, params)")
_sink("sink_weak_hash_secret", "Weak hash over a password", "Zwakke hash over wachtwoord",
      "MD5 or SHA-1 applied to password-class data. Use a password KDF (scrypt, argon2, PBKDF2).",
      "MD5 of SHA-1 toegepast op wachtwoordachtige data. Gebruik een wachtwoord-KDF (scrypt, "
      "argon2, PBKDF2).",
      "hashlib.md5(password.encode())", "hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)")
_c("hardcoded_secret_material", "parser", "depends", "python", "both",
   _t("Hardcoded key, salt or secret", "Hardcoded sleutel, salt of geheim"),
   _t("A secret-sounding name (password, api_key, secret_key, ...) is assigned a literal that "
      "looks like real key material. Labels, paths, environment-variable names and dotted "
      "identifiers are not flagged. Blocks, except when gating a change to a test file (under "
      "test/, tests/ or testing/, or test_*.py, *_test.py, conftest.py, tests.py): fixture tokens "
      "are test data, so there it is a warning, unless the value is a recognisable provider key "
      "(AWS, GitHub, Slack, Stripe live, Google, OpenAI, Anthropic) or a private key. Absolute "
      "paths and paths with .. never count as test files. Verifying a claimed fix always blocks.",
      "Een geheim-klinkende naam (password, api_key, secret_key, ...) krijgt een literal die op "
      "echt sleutelmateriaal lijkt. Labels, paden, namen van omgevingsvariabelen en gepunte "
      "identifiers worden niet gemeld. Blokkeert, behalve bij wijzigingscontrole van een "
      "testbestand (onder test/, tests/ of testing/, of test_*.py, *_test.py, conftest.py, "
      "tests.py): fixture-tokens zijn testdata, dus daar is het een waarschuwing, tenzij de "
      "waarde een herkenbare providersleutel is (AWS, GitHub, Slack, Stripe live, Google, OpenAI, "
      "Anthropic) of een private key. Absolute paden en paden met .. tellen nooit als "
      "testbestand. Een beweerde fix controleren blokkeert altijd."),
   "API_KEY = \"sk_live_9f3a2b7c1d8e4f60\"", "API_KEY = os.environ[\"API_KEY\"]")

# ---- guards and wiring ------------------------------------------------------------------
_c("guard_computed_but_unused", "parser", "depends", "python", "both",
   _t("Validation computed but never used", "Validatie berekend maar nooit gebruikt"),
   _t("A value from a validation/sanitising call (sanitize_*, validate_*, os.path.basename, "
      "realpath, ...) is never read, so the unsanitised value still reaches the sink. Blocks when "
      "new or when a fix was claimed; otherwise a warning.",
      "Een waarde uit een validatie-/opschoonaanroep (sanitize_*, validate_*, os.path.basename, "
      "realpath, ...) wordt nooit gelezen, dus de ongezuiverde waarde bereikt nog steeds de "
      "sink. Blokkeert als het nieuw is of als een fix werd beweerd; anders een waarschuwing."),
   "safe = os.path.basename(p)\nreturn open(p)", "safe = os.path.basename(p)\nreturn open(safe)")
_c("shared_sink_injection_path", "parser", "depends", "python", "both",
   _t("Interpolated string reaches a raw sink via a wrapper",
      "Samengestelde string bereikt ruwe sink via een wrapper"),
   _t("A helper forwards its argument into a raw sink, and a caller passes it an interpolated "
      "string. Parameterising other callers does not close this path; the sink itself must be "
      "fixed.",
      "Een hulpfunctie geeft zijn argument door aan een ruwe sink en een aanroeper geeft er een "
      "samengestelde string aan. Andere aanroepers parametriseren sluit dit pad niet; de sink zelf "
      "moet gerepareerd worden."),
   "def q(sql): cur.execute(sql)\nq(f\"... {x}\")", "def q(sql, p=()): cur.execute(sql, p)\nq(\"... ?\", (x,))")
_c("js_guard_computed_but_unused", "mechanical", "depends", "javascript", "both",
   _t("Validation computed but never used (JS/TS)", "Validatie berekend maar nooit gebruikt (JS/TS)"),
   _t("const safe = sanitize(x) appears once in the file and is never referenced again. "
      "Structural check (no parser). A ternary on a guard is not flagged.",
      "const safe = sanitize(x) komt één keer in het bestand voor en wordt nooit meer gebruikt. "
      "Structurele check (geen parser). Een ternary op een guard wordt niet gemeld."))
_c("js_async_guard_in_boolean", "mechanical", "depends", "javascript", "both",
   _t("Async guard used without await", "Async guard zonder await"),
   _t("A function defined async in this file is used as a condition without await. A Promise is "
      "always truthy, so the guard never rejects.",
      "Een functie die in dit bestand async is gedefinieerd wordt zonder await als voorwaarde "
      "gebruikt. Een Promise is altijd truthy, dus de guard weigert nooit."),
   "if (!userCanAccess(req)) throw ...", "if (!(await userCanAccess(req))) throw ...")
_c("js_floating_guard_promise", "mechanical", "depends", "javascript", "both",
   _t("Async guard left floating", "Async guard blijft zweven"),
   _t("assertAllowed(x).catch(log): the code continues before the guard resolves.",
      "assertAllowed(x).catch(log): de code gaat door voordat de guard klaar is."))
_c("js_generated_skipped", "mechanical", "warn", "javascript", "both",
   _t("Minified or bundled file skipped", "Geminificeerd of gebundeld bestand overgeslagen"),
   _t("Structural guard checks assume human-written, line-based code, so generated files are "
      "skipped with this warning. Harden the source, not the build output.",
      "Structurele guard-checks gaan uit van door mensen geschreven, regelgebaseerde code, dus "
      "gegenereerde bestanden worden overgeslagen met deze waarschuwing. Harden de bron, niet de "
      "build-uitvoer."))

# ---- API surface and analyser evidence --------------------------------------------------
_c("api_break", "parser", "hard", "python", "both",
   _t("Public API broken", "Publieke API gebroken"),
   _t("With strict API on: public symbols removed, or a signature changed so that an old call "
      "no longer works. Adding an optional parameter is compatible and not flagged.",
      "Met strikte API aan: publieke symbolen verwijderd, of een signatuur gewijzigd zodat een "
      "oude aanroep niet meer werkt. Een optionele parameter toevoegen is compatibel en wordt "
      "niet gemeld."),
   "def run(cmd) -> def run(cmd, mode)", "def run(cmd) -> def run(cmd, mode=None)")
_c("must_preserve_violated", "parser", "hard", "python", "both",
   _t("Protected symbol altered", "Beschermd symbool gewijzigd"),
   _t("A symbol you marked must-preserve was removed or changed.",
      "Een symbool dat je als te-behouden markeerde is verwijderd of gewijzigd."))
_c("findings_suppressed_not_fixed", "tool", "hard", "python", "both",
   _t("Analyser findings hidden, not fixed", "Analyzer-bevindingen verborgen, niet gefixt"),
   _t("bandit is run twice, normally and with --ignore-nosec. Findings visible only in the "
      "suppression-blind run were silenced, never counted as fixed. Needs bandit installed.",
      "bandit draait twee keer, normaal en met --ignore-nosec. Bevindingen die alleen in de "
      "onderdrukkings-blinde run zichtbaar zijn, zijn het zwijgen opgelegd en tellen nooit als "
      "gefixt. Vereist geïnstalleerde bandit."))
_c("new_analyser_findings", "tool", "warn", "python", "both",
   _t("New analyser findings", "Nieuwe analyzer-bevindingen"),
   _t("bandit reports findings that were not present before the change.",
      "bandit meldt bevindingen die er voor de wijziging niet waren."))

# ---- harden-only ledger items -----------------------------------------------------------
_c("empty_deferred_list", "mechanical", "warn", "harden", "verify",
   _t("Model reported nothing left unfixed", "Model meldde niets onopgelost"),
   _t("On non-trivial input an empty list of unfixed issues is usually a reporting failure.",
      "Bij niet-triviale invoer is een lege lijst van onopgeloste punten meestal een "
      "rapportagefout."))
_c("unsupported_fix_claims", "mechanical", "warn", "harden", "verify",
   _t("Claimed fixes the analyser does not confirm", "Beweerde fixes die de analyzer niet bevestigt"),
   _t("The model claims fixes but the analyser confirms zero removals. Treat the claims as "
      "unverified.",
      "Het model beweert fixes maar de analyzer bevestigt nul verdwenen bevindingen. Behandel de "
      "beweringen als onbevestigd."))
_c("new_findings", "mechanical", "warn", "harden", "verify",
   _t("Analyser findings not present in the input", "Analyzer-bevindingen die niet in de invoer zaten"),
   _t("The hardened output has analyser findings the original did not.",
      "De geharde uitvoer heeft analyzer-bevindingen die het origineel niet had."))

CHECKS: List[dict] = _E
BY_ID: Dict[str, dict] = {c["id"]: c for c in _E}

PROVENANCE_MEANING = {
    "tool": _t("An external analyser (bandit) produced this, run twice: normally and with "
               "suppressions ignored.",
               "Een externe analyzer (bandit) leverde dit, twee keer gedraaid: normaal en met "
               "onderdrukkingen genegeerd."),
    "parser": _t("Computed by parsing both versions into syntax trees and comparing them. Not a "
                 "text guess.",
                 "Berekend door beide versies tot syntaxbomen te parsen en te vergelijken. Geen "
                 "tekstgok."),
    "mechanical": _t("A deterministic text or counting check. Reliable for what it looks for, "
                     "blind to meaning.",
                     "Een deterministische tekst- of telcontrole. Betrouwbaar voor waar ze naar "
                     "zoekt, blind voor betekenis."),
}

TIER_MEANING = {
    "ast_verified": _t("Python: both versions parsed; API surface and sinks computed, not claimed.",
                       "Python: beide versies geparsed; API-oppervlak en sinks berekend, niet "
                       "beweerd."),
    "structural": _t("No parser: textual and structural checks only. Semantics are not verified.",
                     "Geen parser: alleen tekstuele en structurele checks. Semantiek wordt niet "
                     "geverifieerd."),
    "asserted": _t("Unrecognised language: sanity checks only. Any claim of a fix is the "
                   "model's, not Saikou's.",
                   "Onbekende taal: alleen basiscontroles. Elke beweerde fix is van het model, "
                   "niet van Saikou."),
}

LIMITS = [
    _t("It certifies nothing: it reports what was checked and how.",
       "Het certificeert niets: het meldt wat is gecontroleerd en hoe."),
    _t("It does not run your code; behaviour is checked structurally, for Python only.",
       "Het voert je code niet uit; gedrag wordt structureel gecontroleerd, alleen voor Python."),
    _t("It judges changes, not whole systems. Keep your SAST.",
       "Het beoordeelt wijzigingen, geen complete systemen. Houd je SAST."),
    _t("Analyser evidence (bandit) exists for Python only.",
       "Analyzer-bewijs (bandit) bestaat alleen voor Python."),
    _t("One file at a time: no data-flow analysis across files.",
       "Eén bestand tegelijk: geen data-flow-analyse over bestanden heen."),
]


def not_checked(language: str, mode: str) -> List[dict]:
    """Checks in the catalogue that did NOT apply to this language/mode, so a report can say so."""
    lang_key = {"python": "python", "javascript": "javascript", "typescript": "javascript"}.get(language)
    out = []
    for c in CHECKS:
        if c["applies"] in ("harden", "config"):
            continue
        if c["modes"] not in ("both", mode):
            continue
        if c["applies"] not in ("all", lang_key):
            out.append(c)
    return out


def get(check_id: str) -> Optional[dict]:
    return BY_ID.get(check_id)
