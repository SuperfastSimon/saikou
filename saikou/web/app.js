/* Saikou app: one page, vanilla JS, no build step, no third-party requests.
   Served by `saikou ui` (data-mode="local": every screen) and by the hosted API's playground
   (data-mode="hosted": Verify and Checks only). All text from servers or files is inserted
   with textContent, never as HTML. */
(() => {
  "use strict";
  const doc = document;
  const root = doc.documentElement;
  const SVGNS = "http://www.w3.org/2000/svg";
  const MODE = root.getAttribute("data-mode") === "hosted" ? "hosted" : "local";
  const ALL_SCREENS = ["verify", "gate", "harden", "checks", "history"];
  const SCREENS = MODE === "hosted" ? ["verify", "checks"] : ALL_SCREENS;
  const API = MODE === "hosted"
    ? { verify: "/v1/verify", checks: "/v1/checks" }
    : { verify: "/api/verify", checks: "/api/checks", meta: "/api/meta", git: "/api/git/diff",
        providers: "/api/providers", harden: "/api/harden", write: "/api/harden/write",
        read: "/api/file/read" };
  const reducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------------------------------------------------------------------------------------
  // text (English and Dutch, both complete)
  // ---------------------------------------------------------------------------------------
  const STR = {
    en: {
      "skip": "Skip to content", "badge.local": "local", "badge.hosted": "hosted playground",
      "lang.group": "Language", "rail.label": "Screens",
      "theme.system": "System", "theme.light": "Light", "theme.dark": "Dark",
      "theme.aria": "Theme: {name}. Switch theme",
      "nav.verify": "Verify", "nav.gate": "Gate", "nav.harden": "Harden", "nav.checks": "Checks", "nav.history": "History",
      "verify.title": "Verify a change",
      "verify.lede": "Paste the code before and after a security fix. Saikou reports what it can show changed, and blocks what only looks fixed.",
      "verify.sample": "Load an example", "token.label": "API token", "token.save": "Use token",
      "token.hint": "This playground calls the hosted API. The token is kept in this browser tab only and sent as a bearer token.",
      "token.saved": "Token set for this tab.", "token.cleared": "Token removed.",
      "verify.path": "File name", "verify.lang": "Language", "lang.auto": "Detect automatically",
      "verify.policy": "Judge as", "policy.verify": "Claimed fix", "policy.gate": "Ordinary change",
      "verify.strict": "Public API must not break", "verify.analyser": "Also run bandit (Python)",
      "verify.threats": "Claimed to fix",
      "verify.threatsHint": "If a dangerous pattern of a claimed class survives the change, it blocks.",
      "verify.before": "Before", "verify.after": "After", "verify.run": "Verify",
      "editor.open": "Open file", "editor.clear": "Clear", "editor.drop": "Drop a file here",
      "editor.dropBefore": "Paste or drop the original code",
      "editor.dropAfter": "Paste or drop the code after the change",
      "editor.count": "{lines} lines · {chars} characters",
      "gate.title": "Gate a change set",
      "gate.lede": "Check every changed file in a git repository. Only what the change itself introduces blocks, so old code does not fail a new change.",
      "gate.repo": "Repository folder", "gate.base": "Compare with", "gate.staged": "Staged changes only",
      "gate.baseHint": "A branch, tag or commit, for example HEAD, main or origin/main. Without \"staged changes only\" the working tree is compared.",
      "gate.run": "Gate changes",
      "gate.summaryBlocked": "{b} of {n} files blocked", "gate.summaryClear": "Nothing blocked",
      "gate.summaryClearSub": "No check blocked any of the {n} changed files. That is not a verdict that the code is secure.",
      "gate.summaryBlockedSub": "At least one check failed hard on what this change introduces.",
      "gate.base.tag": "base {sha}", "gate.noFiles": "No changed files",
      "gate.noFilesSub": "Nothing differs from {base}.", "gate.noFilesStaged": "Nothing is staged against {base}.",
      "gate.noCheckable": "No checkable files changed",
      "gate.noCheckableSub": "{n} changed file(s) skipped because the language is not recognised; see Skipped below.",
      "gate.skipped": "Skipped ({n})", "gate.files": "Changed files",
      "harden.title": "Harden with your own model",
      "harden.lede": "A model of your choice proposes a hardened version and Saikou verifies it. Only output that passes can be written, and only after you confirm.",
      "harden.path": "File to harden", "harden.pathPh": "Full path, for example C:\\project\\app.py",
      "harden.load": "Load", "harden.loaded": "Loaded {path}. A verified result can be written back to this file.",
      "harden.edited": "Edited since loading, so writing is off. Load the file again to write.",
      "harden.pasted": "Pasted code can be hardened and verified, but not written. Load a file to write.",
      "harden.code": "Code",
      "harden.codePh": "Load a file above, or paste code (pasted code can be hardened but not written)",
      "harden.provider": "Model provider", "harden.model": "Model", "harden.threats": "Threats to address",
      "harden.run": "Harden and verify",
      "provider.openai": "OpenAI-compatible", "provider.ollama": "Ollama cloud", "provider.local": "Local model (Ollama)",
      "provider.keySet": "Key set ({env})", "provider.keyMissing": "No key: set {env} in .env",
      "provider.localUp": "Running, {n} model(s)", "provider.localNone": "Running, but no local model installed",
      "provider.localDown": "Not running: start Ollama",
      "provider.localRemote": "OLLAMA_LOCAL_URL is not on this machine",
      "harden.whereLocal": "Your code stays on this machine.",
      "harden.whereRemote": "Your code is sent to {url}, under that provider's terms.",
      "harden.waiting": "Waiting for {model} ... {s} s",
      "harden.slow": "Local models on an ordinary PC can take several minutes.",
      "harden.verified": "Passed verification",
      "harden.verifiedSub": "No check blocked this output. That is not a verdict that the code is secure.",
      "harden.rejected": "Rejected by verification",
      "harden.rejectedSub": "At least one check blocked this output, so it cannot be written. The diff shows the rejected attempt so you can decide.",
      "harden.diff": "Proposed change", "harden.diffRejected": "Rejected attempt (not written)",
      "harden.noDiff": "The model returned the code unchanged.",
      "harden.ledger": "Findings", "harden.claims": "Claims, grouped by how they were established",
      "harden.unverified": "unverified: the model's own claim", "harden.assumptions": "The model's assumptions",
      "harden.write": "Write to file", "harden.writeHint": "Writes the verified output above to {path}.",
      "harden.writeOffPasted": "Pasted code has no file to write to.",
      "harden.writeOffEdited": "The code was edited after loading, so writing is off.",
      "harden.writeOffRejected": "Rejected output is never written.",
      "harden.written": "Written to {path}.", "harden.writtenNote": "Written. The editor now holds the new file content.",
      "dlg.cancel": "Cancel", "dlg.writeTitle": "Write the verified output?",
      "dlg.writeBody": "This replaces the file below with the output shown in the diff. Saikou first checks that the file still holds the code you hardened; if it changed, nothing is written.",
      "dlg.writeOk": "Write file", "dlg.clearTitle": "Clear history?",
      "dlg.clearBody": "This removes every run summary stored in this browser.", "dlg.clearOk": "Clear history",
      "checks.title": "What Saikou checks",
      "checks.lede": "Every check, how it is established and when it blocks. Nothing is added up into a score.",
      "checks.legend": "How to read this", "checks.search": "Search", "checks.searchPh": "nosec, eval, guard ...",
      "checks.prov": "Established by", "checks.sev": "Severity", "checks.applies": "Applies to", "checks.any": "Any",
      "checks.count": "{n} of {total} checks", "checks.none": "No check matches these filters.",
      "checks.reset": "Reset filters", "checks.example": "Example",
      "legend.prov": "How a finding is established", "legend.tiers": "Verification tiers",
      "sev.hard": "Blocks", "sev.warn": "Warns", "sev.depends": "Blocks or warns, see text",
      "applies.python": "Python", "applies.javascript": "JavaScript / TypeScript", "applies.config": "Analyser config",
      "applies.all": "All languages", "applies.harden": "Harden ledger",
      "modes.verify": "claimed fix only", "modes.gate": "change gating only", "modes.both": "both modes",
      "history.title": "History",
      "history.lede": "Summaries of your recent runs, kept in this browser only. No code is stored.",
      "history.clear": "Clear history", "history.empty": "No runs yet",
      "history.emptySub": "Each run adds a one-line summary here.",
      "history.off": "History is off: this browser does not allow storage for this page.",
      "history.verify": "Verify", "history.gate": "Gate", "history.harden": "Harden",
      "state.loading": "Loading ...", "state.checking": "Checking ...",
      "state.emptyVerify": "Nothing checked yet",
      "state.emptyVerifySub": "Paste the code before and after a change, then press Verify. Or load an example to see a fake fix being caught.",
      "state.emptyGate": "No change set checked yet",
      "state.emptyGateSub": "Point at a git repository and press Gate changes.",
      "state.emptyHarden": "Nothing hardened yet",
      "state.emptyHardenSub": "Load or paste code, pick a model provider and press Harden and verify.",
      "err.title": "That did not work",
      "err.network": "Could not reach the Saikou server. Is it still running?",
      "err.noToken": "The session key is missing or no longer valid (was saikou ui restarted?). Open the link that `saikou ui` printed in your terminal.",
      "err.hostedAuth": "The API refused the token. Paste a valid API token above.",
      "err.notConfigured": "This API instance has no tokens configured and refuses to serve.",
      "err.needAfter": "Paste the code after the change first.", "err.needCode": "Load or paste code first.",
      "err.needRepo": "Enter a repository folder.", "err.needPath": "Enter the full path of a file.",
      "err.needProvider": "Pick a model provider that is ready to use.",
      "err.fileTooBig": "That file is too large (over 2 MB).", "err.binary": "That looks like a binary file.",
      "err.rateLimited": "Too many requests. Wait a moment and try again.",
      "result.blocked": "Blocked", "result.blockedSub": "At least one check failed hard. This does not pass as a fix.",
      "result.blockedGateSub": "At least one check failed hard on what this change introduces.",
      "result.clear": "Nothing blocked",
      "result.clearSub": "No check blocked this change. That is not a verdict that the code is secure.",
      "count.hard1": "1 hard fail", "count.hardN": "{n} hard fails", "count.warn1": "1 warning", "count.warnN": "{n} warnings",
      "pill.hard": "Hard fail", "pill.warn": "Warning",
      "finding.line": "Line {n}", "finding.lineAria": "Line {n}: show it in the After editor",
      "finding.explain": "What this check means", "finding.bad": "Flagged", "finding.good": "Not flagged",
      "report.findings": "Findings",
      "report.noFindings": "No check raised a finding. Absence of a finding is not evidence of a fix.",
      "report.tier": "Verification tier", "report.notChecked": "Not checked for {lang} ({n})",
      "report.limits": "What Saikou does not do", "report.api": "Public API",
      "report.apiRemoved": "Removed: {names}", "report.apiChanged": "Signature changed: {names}",
      "report.analyser": "Analyser evidence (bandit)", "report.analyserLine": "Removed {r} · introduced {i} · newly suppressed {s}",
      "report.export": "Export", "report.notes": "Notes", "report.detailLang": "",
      "change.added": "added", "change.modified": "modified", "change.verify": "claimed fix",
      "live.done": "{verdict}. {hard}, {warn}.", "toast.saved": "Saved {name}",
      "threat.untrusted_input": "Untrusted input", "threat.injection": "Injection", "threat.secrets_handling": "Secrets",
      "threat.path_traversal": "Path traversal", "threat.deserialization": "Deserialisation", "threat.ssrf": "SSRF",
      "threat.authz": "Authorisation", "threat.crypto": "Cryptography", "threat.resource_exhaustion": "Resource exhaustion",
      "threat.concurrency": "Concurrency", "threat.logging_pii": "Personal data in logs", "threat.dependency_risk": "Dependency risk"
    },
    nl: {
      "skip": "Naar de inhoud", "badge.local": "lokaal", "badge.hosted": "online proefomgeving",
      "lang.group": "Taal", "rail.label": "Schermen",
      "theme.system": "Systeem", "theme.light": "Licht", "theme.dark": "Donker",
      "theme.aria": "Thema: {name}. Wissel van thema",
      "nav.verify": "Verifiëren", "nav.gate": "Wijzigingen", "nav.harden": "Harden", "nav.checks": "Checks", "nav.history": "Geschiedenis",
      "verify.title": "Controleer een wijziging",
      "verify.lede": "Plak de code vóór en ná een beveiligingsfix. Saikou meldt wat aantoonbaar veranderd is en blokkeert wat alleen gefikst lijkt.",
      "verify.sample": "Voorbeeld laden", "token.label": "API-token", "token.save": "Token gebruiken",
      "token.hint": "Deze proefomgeving roept de gehoste API aan. Het token blijft alleen in dit browsertabblad en wordt als bearer-token meegestuurd.",
      "token.saved": "Token ingesteld voor dit tabblad.", "token.cleared": "Token verwijderd.",
      "verify.path": "Bestandsnaam", "verify.lang": "Taal", "lang.auto": "Automatisch herkennen",
      "verify.policy": "Beoordeel als", "policy.verify": "Beweerde fix", "policy.gate": "Gewone wijziging",
      "verify.strict": "Publieke API mag niet breken", "verify.analyser": "Ook bandit draaien (Python)",
      "verify.threats": "Beweert te fixen",
      "verify.threatsHint": "Overleeft een gevaarlijk patroon van een beweerde klasse de wijziging, dan blokkeert dat.",
      "verify.before": "Voor", "verify.after": "Na", "verify.run": "Verifiëren",
      "editor.open": "Bestand openen", "editor.clear": "Leegmaken", "editor.drop": "Sleep hier een bestand",
      "editor.dropBefore": "Plak of sleep de oorspronkelijke code",
      "editor.dropAfter": "Plak of sleep de code na de wijziging",
      "editor.count": "{lines} regels · {chars} tekens",
      "gate.title": "Controleer een wijzigingenset",
      "gate.lede": "Controleer elk gewijzigd bestand in een git-repository. Alleen wat de wijziging zelf introduceert blokkeert, dus oude code laat een nieuwe wijziging niet zakken.",
      "gate.repo": "Repositorymap", "gate.base": "Vergelijk met", "gate.staged": "Alleen gestagede wijzigingen",
      "gate.baseHint": "Een branch, tag of commit, bijvoorbeeld HEAD, main of origin/main. Zonder \"alleen gestagede wijzigingen\" wordt de werkmap vergeleken.",
      "gate.run": "Wijzigingen controleren",
      "gate.summaryBlocked": "{b} van {n} bestanden geblokkeerd", "gate.summaryClear": "Niets geblokkeerd",
      "gate.summaryClearSub": "Geen check blokkeerde een van de {n} gewijzigde bestanden. Dat is geen oordeel dat de code veilig is.",
      "gate.summaryBlockedSub": "Minstens één check faalde hard op wat deze wijziging introduceert.",
      "gate.base.tag": "basis {sha}", "gate.noFiles": "Geen gewijzigde bestanden",
      "gate.noFilesSub": "Niets verschilt van {base}.", "gate.noFilesStaged": "Er is niets gestaged ten opzichte van {base}.",
      "gate.noCheckable": "Geen controleerbare bestanden gewijzigd",
      "gate.noCheckableSub": "{n} gewijzigd(e) bestand(en) overgeslagen omdat de taal niet wordt herkend; zie Overgeslagen hieronder.",
      "gate.skipped": "Overgeslagen ({n})", "gate.files": "Gewijzigde bestanden",
      "harden.title": "Harden met je eigen model",
      "harden.lede": "Een model naar keuze stelt een geharde versie voor en Saikou verifieert die. Alleen uitvoer die slaagt kan worden geschreven, en pas na jouw bevestiging.",
      "harden.path": "Bestand om te harden", "harden.pathPh": "Volledig pad, bijvoorbeeld C:\\project\\app.py",
      "harden.load": "Laden", "harden.loaded": "Geladen: {path}. Een geverifieerd resultaat kan naar dit bestand worden teruggeschreven.",
      "harden.edited": "Bewerkt na het laden, dus schrijven staat uit. Laad het bestand opnieuw om te schrijven.",
      "harden.pasted": "Geplakte code kan worden gehard en geverifieerd, maar niet geschreven. Laad een bestand om te schrijven.",
      "harden.code": "Code",
      "harden.codePh": "Laad hierboven een bestand, of plak code (geplakte code kan worden gehard maar niet geschreven)",
      "harden.provider": "Modelaanbieder", "harden.model": "Model", "harden.threats": "Aan te pakken dreigingen",
      "harden.run": "Harden en verifiëren",
      "provider.openai": "OpenAI-compatibel", "provider.ollama": "Ollama cloud", "provider.local": "Lokaal model (Ollama)",
      "provider.keySet": "Sleutel gezet ({env})", "provider.keyMissing": "Geen sleutel: zet {env} in .env",
      "provider.localUp": "Draait, {n} model(len)", "provider.localNone": "Draait, maar er is geen lokaal model geïnstalleerd",
      "provider.localDown": "Draait niet: start Ollama",
      "provider.localRemote": "OLLAMA_LOCAL_URL wijst niet naar deze machine",
      "harden.whereLocal": "Je code blijft op deze machine.",
      "harden.whereRemote": "Je code gaat naar {url}, onder de voorwaarden van die aanbieder.",
      "harden.waiting": "Wachten op {model} ... {s} s",
      "harden.slow": "Lokale modellen op een gewone pc kunnen enkele minuten nodig hebben.",
      "harden.verified": "Geslaagd voor verificatie",
      "harden.verifiedSub": "Geen check blokkeerde deze uitvoer. Dat is geen oordeel dat de code veilig is.",
      "harden.rejected": "Afgekeurd door verificatie",
      "harden.rejectedSub": "Minstens één check blokkeerde deze uitvoer, dus die kan niet worden geschreven. De diff toont de afgekeurde poging zodat je zelf kunt beslissen.",
      "harden.diff": "Voorgestelde wijziging", "harden.diffRejected": "Afgekeurde poging (niet geschreven)",
      "harden.noDiff": "Het model gaf de code ongewijzigd terug.",
      "harden.ledger": "Bevindingen", "harden.claims": "Beweringen, gegroepeerd naar herkomst",
      "harden.unverified": "onbevestigd: bewering van het model zelf", "harden.assumptions": "Aannames van het model",
      "harden.write": "Naar bestand schrijven", "harden.writeHint": "Schrijft de geverifieerde uitvoer hierboven naar {path}.",
      "harden.writeOffPasted": "Geplakte code heeft geen bestand om naar te schrijven.",
      "harden.writeOffEdited": "De code is na het laden bewerkt, dus schrijven staat uit.",
      "harden.writeOffRejected": "Afgekeurde uitvoer wordt nooit geschreven.",
      "harden.written": "Geschreven naar {path}.", "harden.writtenNote": "Geschreven. De editor bevat nu de nieuwe inhoud van het bestand.",
      "dlg.cancel": "Annuleren", "dlg.writeTitle": "Geverifieerde uitvoer schrijven?",
      "dlg.writeBody": "Dit vervangt het bestand hieronder door de uitvoer uit de diff. Saikou controleert eerst of het bestand nog de code bevat die je hebt gehard; is het veranderd, dan wordt er niets geschreven.",
      "dlg.writeOk": "Bestand schrijven", "dlg.clearTitle": "Geschiedenis wissen?",
      "dlg.clearBody": "Dit verwijdert alle samenvattingen die in deze browser zijn opgeslagen.", "dlg.clearOk": "Geschiedenis wissen",
      "checks.title": "Wat Saikou controleert",
      "checks.lede": "Elke check, hoe die wordt vastgesteld en wanneer die blokkeert. Niets wordt opgeteld tot een score.",
      "checks.legend": "Zo lees je dit", "checks.search": "Zoeken", "checks.searchPh": "nosec, eval, guard ...",
      "checks.prov": "Vastgesteld door", "checks.sev": "Ernst", "checks.applies": "Geldt voor", "checks.any": "Alle",
      "checks.count": "{n} van {total} checks", "checks.none": "Geen check past bij deze filters.",
      "checks.reset": "Filters wissen", "checks.example": "Voorbeeld",
      "legend.prov": "Hoe een bevinding wordt vastgesteld", "legend.tiers": "Verificatieniveaus",
      "sev.hard": "Blokkeert", "sev.warn": "Waarschuwt", "sev.depends": "Blokkeert of waarschuwt, zie tekst",
      "applies.python": "Python", "applies.javascript": "JavaScript / TypeScript", "applies.config": "Analyzer-config",
      "applies.all": "Alle talen", "applies.harden": "Harden-logboek",
      "modes.verify": "alleen beweerde fix", "modes.gate": "alleen wijzigingscontrole", "modes.both": "beide standen",
      "history.title": "Geschiedenis",
      "history.lede": "Samenvattingen van je recente runs, alleen bewaard in deze browser. Er wordt geen code opgeslagen.",
      "history.clear": "Geschiedenis wissen", "history.empty": "Nog geen runs",
      "history.emptySub": "Elke run voegt hier een samenvatting van één regel toe.",
      "history.off": "Geschiedenis staat uit: deze browser staat geen opslag toe voor deze pagina.",
      "history.verify": "Verifiëren", "history.gate": "Wijzigingen", "history.harden": "Harden",
      "state.loading": "Laden ...", "state.checking": "Controleren ...",
      "state.emptyVerify": "Nog niets gecontroleerd",
      "state.emptyVerifySub": "Plak de code vóór en ná een wijziging en druk op Verifiëren. Of laad een voorbeeld om een nepfix te zien vallen.",
      "state.emptyGate": "Nog geen wijzigingenset gecontroleerd",
      "state.emptyGateSub": "Kies een git-repository en druk op Wijzigingen controleren.",
      "state.emptyHarden": "Nog niets gehard",
      "state.emptyHardenSub": "Laad of plak code, kies een modelaanbieder en druk op Harden en verifiëren.",
      "err.title": "Dat lukte niet",
      "err.network": "De Saikou-server is niet bereikbaar. Draait hij nog?",
      "err.noToken": "De sessiesleutel ontbreekt of is niet meer geldig (is saikou ui opnieuw gestart?). Open de link die `saikou ui` in je terminal liet zien.",
      "err.hostedAuth": "De API weigerde het token. Plak hierboven een geldig API-token.",
      "err.notConfigured": "Deze API-instantie heeft geen tokens ingesteld en weigert te werken.",
      "err.needAfter": "Plak eerst de code na de wijziging.", "err.needCode": "Laad of plak eerst code.",
      "err.needRepo": "Vul een repositorymap in.", "err.needPath": "Vul het volledige pad van een bestand in.",
      "err.needProvider": "Kies een modelaanbieder die klaar is voor gebruik.",
      "err.fileTooBig": "Dat bestand is te groot (meer dan 2 MB).", "err.binary": "Dat lijkt een binair bestand.",
      "err.rateLimited": "Te veel verzoeken. Wacht even en probeer het opnieuw.",
      "result.blocked": "Geblokkeerd", "result.blockedSub": "Minstens één check faalde hard. Dit gaat niet door als fix.",
      "result.blockedGateSub": "Minstens één check faalde hard op wat deze wijziging introduceert.",
      "result.clear": "Niets geblokkeerd",
      "result.clearSub": "Geen check blokkeerde deze wijziging. Dat is geen oordeel dat de code veilig is.",
      "count.hard1": "1 harde afkeuring", "count.hardN": "{n} harde afkeuringen", "count.warn1": "1 waarschuwing", "count.warnN": "{n} waarschuwingen",
      "pill.hard": "Harde afkeuring", "pill.warn": "Waarschuwing",
      "finding.line": "Regel {n}", "finding.lineAria": "Regel {n}: toon die in de Na-editor",
      "finding.explain": "Wat deze check betekent", "finding.bad": "Gemeld", "finding.good": "Niet gemeld",
      "report.findings": "Bevindingen",
      "report.noFindings": "Geen check meldde iets. Het ontbreken van een bevinding is geen bewijs van een fix.",
      "report.tier": "Verificatieniveau", "report.notChecked": "Niet gecontroleerd voor {lang} ({n})",
      "report.limits": "Wat Saikou niet doet", "report.api": "Publieke API",
      "report.apiRemoved": "Verwijderd: {names}", "report.apiChanged": "Signatuur gewijzigd: {names}",
      "report.analyser": "Analyzer-bewijs (bandit)", "report.analyserLine": "Verdwenen {r} · nieuw {i} · nieuw onderdrukt {s}",
      "report.export": "Exporteren", "report.notes": "Opmerkingen", "report.detailLang": "Toelichting van de engine (Engels):",
      "change.added": "toegevoegd", "change.modified": "gewijzigd", "change.verify": "beweerde fix",
      "live.done": "{verdict}. {hard}, {warn}.", "toast.saved": "Opgeslagen: {name}",
      "threat.untrusted_input": "Onbetrouwbare invoer", "threat.injection": "Injectie", "threat.secrets_handling": "Geheimen",
      "threat.path_traversal": "Path traversal", "threat.deserialization": "Deserialisatie", "threat.ssrf": "SSRF",
      "threat.authz": "Autorisatie", "threat.crypto": "Cryptografie", "threat.resource_exhaustion": "Uitputting van middelen",
      "threat.concurrency": "Gelijktijdigheid", "threat.logging_pii": "Persoonsgegevens in logs", "threat.dependency_risk": "Afhankelijkheidsrisico"
    }
  };
  const LANG_NAMES = { python: "Python", javascript: "JavaScript", typescript: "TypeScript", go: "Go", java: "Java",
    csharp: "C#", ruby: "Ruby", php: "PHP", rust: "Rust", c: "C", cpp: "C++", kotlin: "Kotlin", swift: "Swift",
    shell: "Shell", sql: "SQL", unknown: "Unknown" };

  // ---------------------------------------------------------------------------------------
  // small helpers
  // ---------------------------------------------------------------------------------------
  const $ = (id) => doc.getElementById(id);
  const storage = (kind) => { try { return kind === "session" ? window.sessionStorage : window.localStorage; } catch (e) { return null; } };
  const load = (kind, key, fallback) => {
    try { const s = storage(kind); const v = s ? s.getItem(key) : null; return v === null ? fallback : v; } catch (e) { return fallback; }
  };
  const save = (kind, key, value) => {
    try { const s = storage(kind); if (!s) return false; if (value === null) s.removeItem(key); else s.setItem(key, value); return true; } catch (e) { return false; }
  };

  let lang = load("local", "saikou.lang", "") || ((navigator.language || "").toLowerCase().startsWith("nl") ? "nl" : "en");
  if (!STR[lang]) lang = "en";
  const has = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
  const t = (key, vars) => {
    // An empty string is a real translation ("say nothing here"), not a missing one.
    let s = has(STR[lang], key) ? STR[lang][key] : has(STR.en, key) ? STR.en[key] : key;
    if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
    return s;
  };
  const both = (obj) => (obj && (obj[lang] || obj.en)) || "";
  const plural = (n, one, many) => (n === 1 ? t(one) : t(many, { n }));
  const counts = (hard, warn) => [plural(hard, "count.hard1", "count.hardN"), plural(warn, "count.warn1", "count.warnN")];

  function h(tag, attrs, kids) {
    const el = doc.createElement(tag);
    if (attrs) {
      for (const k of Object.keys(attrs)) {
        const v = attrs[k];
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    add(el, kids);
    return el;
  }
  function add(el, kids) {
    if (kids === null || kids === undefined) return;
    (Array.isArray(kids) ? kids : [kids]).forEach((k) => {
      if (k === null || k === undefined || k === false) return;
      el.appendChild(typeof k === "string" || typeof k === "number" ? doc.createTextNode(String(k)) : k);
    });
  }
  function icon(name, cls) {
    const svg = doc.createElementNS(SVGNS, "svg");
    svg.setAttribute("class", "icon" + (cls ? " " + cls : ""));
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const use = doc.createElementNS(SVGNS, "use");
    use.setAttribute("href", "#i-" + name);
    svg.appendChild(use);
    return svg;
  }
  const live = (text) => { const el = $("live"); el.textContent = ""; setTimeout(() => { el.textContent = text; }, 60); };
  let toastTimer = 0;
  function toast(text) {
    const el = $("toast");
    el.textContent = text;
    el.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.hidden = true; }, 3500);
  }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: name });
    doc.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast(t("toast.saved", { name }));
  }

  // ---------------------------------------------------------------------------------------
  // talking to the server
  // ---------------------------------------------------------------------------------------
  let token = "";
  if (MODE === "local") {
    const m = /[#&]t=([A-Za-z0-9_-]+)/.exec(location.hash);
    if (m) {
      token = m[1];
      save("session", "saikou.key", token);
      // Keep the key out of the address bar, bookmarks and screenshots.
      history.replaceState(null, "", location.pathname + location.search);
    } else {
      token = load("session", "saikou.key", "");
    }
  } else {
    token = load("session", "saikou.apiToken", "");
  }

  class ApiError extends Error {
    constructor(message, code, status) { super(message); this.code = code; this.status = status; }
  }

  async function call(method, url, body) {
    const headers = { Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (MODE === "local") headers["X-Saikou-Token"] = token;
    else if (token) headers.Authorization = "Bearer " + token;
    let resp;
    try {
      resp = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
                                credentials: "omit", cache: "no-store" });
    } catch (e) {
      throw new ApiError(t("err.network"), "network", 0);
    }
    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = null; }
    if (!resp.ok) {
      const err = (data && data.error) || {};
      throw new ApiError(err.message || resp.statusText || "HTTP " + resp.status, err.code || "http_" + resp.status, resp.status);
    }
    return data;
  }

  function friendly(err) {
    if (err.code === "unauthorized") return MODE === "local" ? t("err.noToken") : t("err.hostedAuth");
    if (err.code === "not_configured") return t("err.notConfigured");
    if (err.code === "rate_limited") return t("err.rateLimited") + " (" + err.message + ")";
    return err.message || String(err);
  }

  // ---------------------------------------------------------------------------------------
  // shared views: states, verdicts, findings, reports
  // ---------------------------------------------------------------------------------------
  function stateEmpty(title, sub, iconName) {
    return h("div", { class: "state" }, [icon(iconName || "info"), h("h2", { text: title }), h("p", { text: sub })]);
  }
  function stateLoading(text) {
    return h("div", { class: "state" }, [h("div", { class: "spinner", "aria-hidden": "true" }), h("p", { text: text || t("state.checking") })]);
  }
  function stateError(err) {
    return h("div", { class: "state error", role: "alert" }, [
      icon("warn"),
      h("div", null, [h("h2", { text: t("err.title") }), h("p", { text: friendly(err) }),
                      err.code ? h("p", null, h("code", { text: err.code + (err.status ? " · HTTP " + err.status : "") })) : null])
    ]);
  }
  function verdict(blocked, title, sub, hard, warn) {
    const c = counts(hard, warn);
    return h("div", { class: "verdict " + (blocked ? "fail" : "pass") }, [
      icon(blocked ? "block" : "pass"),
      h("div", { class: "verdict-text" }, [h("h2", { text: title }), h("p", { text: sub })]),
      h("div", { class: "counts" }, [h("span", { class: "count" + (hard ? " hard" : ""), text: c[0] }),
                                     h("span", { class: "count" + (warn ? " warn" : ""), text: c[1] })])
    ]);
  }

  let catalog = null;
  let byId = {};
  let catalogPromise = null;
  function ensureCatalog() {
    if (!catalogPromise) {
      catalogPromise = call("GET", API.checks).then((data) => {
        catalog = data;
        byId = {};
        data.checks.forEach((c) => { byId[c.id] = c; });
        return data;
      }).catch((e) => { catalogPromise = null; throw e; });
    }
    return catalogPromise;
  }
  const provenanceOf = (f) => f.provenance || (byId[f.check] && byId[f.check].provenance) || "mechanical";
  const titleOf = (check) => (byId[check] ? both(byId[check].title) : check);

  function findingsList(findings, opts) {
    const sorted = findings.slice().sort((a, b) =>
      (a.severity === "hard_fail" ? 0 : 1) - (b.severity === "hard_fail" ? 0 : 1) || (a.line || 0) - (b.line || 0));
    const ul = h("ul", { class: "findings" });
    sorted.forEach((f) => {
      const hard = f.severity === "hard_fail";
      const prov = provenanceOf(f);
      const entry = byId[f.check];
      let where = null;
      if (f.line && opts && opts.onLine) {
        where = h("button", { type: "button", class: "line-btn", "aria-label": t("finding.lineAria", { n: f.line }),
                              onclick: () => opts.onLine(f.line) },
                  [icon("arrow"), t("finding.line", { n: f.line })]);
      } else if (f.line) {
        where = h("span", { class: "line-plain", text: t("finding.line", { n: f.line }) });
      }
      const li = h("li", { class: "finding" + (hard ? " hard" : "") }, [
        h("div", { class: "finding-head" }, [
          h("h3", { class: "finding-title", text: titleOf(f.check) }),
          h("span", { class: "sev " + (hard ? "hard" : "warn"), text: t(hard ? "pill.hard" : "pill.warn") }),
          h("span", { class: "prov", title: catalog ? both(catalog.provenance[prov]) : null, text: prov }),
          where
        ]),
        h("p", { class: "finding-detail", lang: "en" }, [
          t("report.detailLang") ? h("span", { class: "sr-only", lang, text: t("report.detailLang") + " " }) : null,
          f.detail
        ])
      ]);
      if (entry) {
        const ex = [];
        if (entry.example_bad) ex.push(h("div", null, [h("p", { class: "ex-label bad", text: t("finding.bad") }), h("pre", { class: "block", text: entry.example_bad })]));
        if (entry.example_good) ex.push(h("div", null, [h("p", { class: "ex-label good", text: t("finding.good") }), h("pre", { class: "block", text: entry.example_good })]));
        li.appendChild(h("details", null, [
          h("summary", null, [icon("chevron", "chev"), t("finding.explain")]),
          h("div", { class: "explain" }, [h("p", null, h("code", { class: "id", text: f.check })),
                                          h("p", { text: both(entry.description) }), ex.length ? h("div", { class: "examples" }, ex) : null])
        ]));
      }
      ul.appendChild(li);
    });
    return ul;
  }

  function fold(title, body, open) {
    return h("details", { class: "fold", open: !!open }, [
      h("summary", null, [icon("chevron", "chev"), h("span", { text: title })]),
      h("div", { class: "fold-body" }, body)
    ]);
  }

  function fileReport(r, opts) {
    const out = doc.createDocumentFragment();
    out.appendChild(h("div", { class: "meta-row" }, [
      r.path && r.path !== "input" ? h("span", { class: "tag", text: r.path }) : null,
      h("span", { class: "tag", text: LANG_NAMES[r.language] || r.language }),
      h("span", { class: "tag", text: r.verification_tier }),
      r.change && r.change !== "verify" ? h("span", { class: "tag", text: t("change." + r.change) }) : null
    ]));
    out.appendChild(h("h2", { class: "section-title", text: t("report.findings") }));
    out.appendChild(r.findings.length ? findingsList(r.findings, opts) : h("p", { class: "empty-line", text: t("report.noFindings") }));
    if (r.tier_meaning) {
      out.appendChild(h("div", { class: "tier" }, [h("b", { text: t("report.tier") + ": " + r.verification_tier + ". " }), both(r.tier_meaning)]));
    }
    const api = r.api_surface;
    if (api && ((api.removed || []).length || (api.changed_signature || []).length)) {
      const items = [];
      if ((api.removed || []).length) items.push(h("li", { text: t("report.apiRemoved", { names: api.removed.map((s) => s.name).join(", ") }) }));
      if ((api.changed_signature || []).length) items.push(h("li", { text: t("report.apiChanged", { names: api.changed_signature.map((s) => s.name).join(", ") }) }));
      out.appendChild(fold(t("report.api"), h("ul", null, items), true));
    }
    if (r.analyser) {
      out.appendChild(fold(t("report.analyser"), h("p", { text: t("report.analyserLine", {
        r: (r.analyser.removed || []).length, i: (r.analyser.introduced || []).length, s: (r.analyser.newly_suppressed || []).length }) })));
    }
    if (r.not_checked && r.not_checked.length) {
      out.appendChild(fold(t("report.notChecked", { lang: LANG_NAMES[r.language] || r.language, n: r.not_checked.length }),
                           h("ul", null, r.not_checked.map((c) => h("li", null, [both(c.title), " ", h("code", { text: c.id })])))));
    }
    return out;
  }

  function limitsFold(data) {
    if (!data.limits || !data.limits.length) return null;
    return fold(t("report.limits"), h("ul", null, data.limits.map((l) => h("li", { text: both(l) }))));
  }

  function toMarkdown(data) {
    const files = data.files || [];
    const blocked = files.filter((f) => f.blocked);
    const out = ["### Saikou: " + (blocked.length ? blocked.length + " file(s) blocked" : "no check blocked this change"), "",
                 "Checked " + files.length + " file(s) in `" + data.mode + "` mode. " + (data.reading_guide || ""), ""];
    const rows = [];
    files.forEach((f) => f.findings.forEach((x) => rows.push([f, x])));
    if (rows.length) {
      out.push("| Severity | File | Check | How established | Detail |", "|---|---|---|---|---|");
      rows.sort((a, b) => (a[1].severity === "hard_fail" ? 0 : 1) - (b[1].severity === "hard_fail" ? 0 : 1));
      rows.forEach(([f, x]) => {
        const loc = x.line ? f.path + ":" + x.line : f.path;
        const detail = String(x.detail).replace(/\|/g, "\\|").replace(/\n/g, " ").slice(0, 220);
        out.push("| " + (x.severity === "hard_fail" ? "**hard fail**" : "warning") + " | `" + loc + "` | `" + x.check +
                 "` | " + provenanceOf(x) + " | " + detail + " |");
      });
    }
    return out.join("\n") + "\n";
  }

  function exportBar(data, sarif) {
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    return h("div", { class: "export" }, [
      h("span", { class: "label", text: t("report.export") }),
      h("button", { type: "button", class: "btn", onclick: () => download("saikou-" + stamp + ".json", JSON.stringify(data, null, 2), "application/json") }, [icon("download"), "JSON"]),
      h("button", { type: "button", class: "btn", onclick: async (e) => {
        const btn = e.currentTarget;
        btn.disabled = true;
        try { download("saikou-" + stamp + ".sarif", JSON.stringify(await sarif(), null, 2), "application/sarif+json"); }
        catch (err) { toast(friendly(err)); }
        finally { btn.disabled = false; }
      } }, [icon("download"), "SARIF"]),
      h("button", { type: "button", class: "btn", onclick: () => download("saikou-" + stamp + ".md", toMarkdown(data), "text/markdown") }, [icon("download"), "Markdown"])
    ]);
  }

  // ---------------------------------------------------------------------------------------
  // history (localStorage, summaries only)
  // ---------------------------------------------------------------------------------------
  const HKEY = "saikou.history.v1";
  const historyOn = save("local", "saikou.probe", "1") && save("local", "saikou.probe", null);
  function historyLoad() {
    try { const arr = JSON.parse(load("local", HKEY, "[]")); return Array.isArray(arr) ? arr : []; } catch (e) { return []; }
  }
  function historyAdd(entry) {
    if (!historyOn) return;
    const arr = historyLoad();
    arr.unshift(Object.assign({ t: Date.now() }, entry));
    save("local", HKEY, JSON.stringify(arr.slice(0, 50)));
  }
  function renderHistory() {
    const box = $("hist-list");
    $("hist-clear").disabled = !historyOn || !historyLoad().length;
    if (!historyOn) { box.replaceChildren(stateEmpty(t("history.off"), "", "info")); return; }
    const arr = historyLoad();
    if (!arr.length) { box.replaceChildren(stateEmpty(t("history.empty"), t("history.emptySub"), "history")); return; }
    const fmt = new Intl.DateTimeFormat(lang === "nl" ? "nl-NL" : "en-GB", { dateStyle: "medium", timeStyle: "short" });
    const c = (e) => counts(e.hard || 0, e.warn || 0);
    box.replaceChildren(h("ul", { class: "hist" }, arr.map((e) => h("li", null, [
      icon(e.blocked ? "block" : "pass", e.blocked ? "fail" : "pass"),
      h("span", { class: "what", text: t("history." + e.kind) + " · " + (e.blocked ? t("result.blocked") : t("result.clear")) + (e.label ? " · " + e.label : "") }),
      h("span", { class: "when", text: fmt.format(new Date(e.t)) + (e.files ? " · " + e.files + " file(s)" : "") }),
      h("span", { class: "counts" }, [h("span", { class: "count" + (e.hard ? " hard" : ""), text: c(e)[0] }), h("span", { class: "count" + (e.warn ? " warn" : ""), text: c(e)[1] })])
    ]))));
  }

  // ---------------------------------------------------------------------------------------
  // dialogs
  // ---------------------------------------------------------------------------------------
  function confirmDialog(title, body, okLabel, danger) {
    const dlg = $("dlg");
    $("dlg-title").textContent = title;
    $("dlg-body").replaceChildren(...body);
    const ok = $("dlg-ok");
    ok.textContent = okLabel;
    ok.className = "btn " + (danger ? "danger" : "primary");
    return new Promise((resolve) => {
      const done = (value) => {
        ok.removeEventListener("click", yes);
        $("dlg-cancel").removeEventListener("click", no);
        dlg.removeEventListener("close", no);
        if (dlg.open) dlg.close();
        resolve(value);
      };
      const yes = () => done(true);
      const no = () => done(false);
      ok.addEventListener("click", yes);
      $("dlg-cancel").addEventListener("click", no);
      dlg.addEventListener("close", no);
      dlg.showModal();
      $("dlg-cancel").focus();
    });
  }

  // ---------------------------------------------------------------------------------------
  // code editor: textarea + line gutter + line jump
  // ---------------------------------------------------------------------------------------
  function Editor(box, onLoaded) {
    const ta = box.querySelector("textarea");
    const gutter = box.querySelector(".gutter-inner");
    const foot = box.querySelector("[data-foot]");
    const flash = box.querySelector(".line-flash");
    let marks = {};
    let shown = -1;
    let flashLine = 0;
    let flashTimer = 0;
    const lineHeight = () => parseFloat(getComputedStyle(ta).lineHeight) || 20;
    const padTop = () => parseFloat(getComputedStyle(ta).paddingTop) || 10;
    const lineCount = () => (ta.value ? ta.value.split("\n").length : 1);

    function paint(force) {
      const n = lineCount();
      if (n !== shown || force) {
        shown = n;
        const frag = doc.createDocumentFragment();
        for (let i = 1; i <= n; i++) {
          const s = doc.createElement("span");
          s.textContent = String(i);
          if (marks[i]) s.className = marks[i];
          frag.appendChild(s);
        }
        gutter.replaceChildren(frag);
      }
      foot.textContent = t("editor.count", { lines: n, chars: ta.value.length });
    }
    function sync() {
      gutter.style.transform = "translateY(" + -ta.scrollTop + "px)";
      if (flashLine) flash.style.transform = "translateY(" + (padTop() + (flashLine - 1) * lineHeight() - ta.scrollTop) + "px)";
    }
    ta.addEventListener("input", () => { if (Object.keys(marks).length) { marks = {}; paint(true); } else paint(); });
    ta.addEventListener("scroll", sync);

    function setValue(text) { ta.value = text; ta.scrollTop = 0; marks = {}; paint(true); sync(); ta.dispatchEvent(new Event("change")); }
    function loadFile(file) {
      if (file.size > 2000000) { toast(t("err.fileTooBig")); return; }
      file.text().then((text) => {
        if (text.indexOf("\u0000") >= 0) { toast(t("err.binary")); return; }
        setValue(text);
        if (onLoaded) onLoaded(file.name);
      });
    }
    box.addEventListener("dragover", (e) => { e.preventDefault(); box.classList.add("drag"); });
    box.addEventListener("dragleave", (e) => { if (!box.contains(e.relatedTarget)) box.classList.remove("drag"); });
    box.addEventListener("drop", (e) => {
      e.preventDefault();
      box.classList.remove("drag");
      const file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) loadFile(file);
    });
    paint(true);
    return {
      el: ta, box,
      value: () => ta.value,
      setValue, loadFile,
      repaint: () => paint(true),
      setMarks(findings) {
        marks = {};
        (findings || []).forEach((f) => {
          if (!f.line) return;
          if (f.severity === "hard_fail") marks[f.line] = "hard";
          else if (!marks[f.line]) marks[f.line] = "warn";
        });
        paint(true);
      },
      goTo(line) {
        const v = ta.value;
        let start = 0;
        for (let i = 1; i < line; i++) { const nx = v.indexOf("\n", start); if (nx < 0) break; start = nx + 1; }
        let end = v.indexOf("\n", start);
        if (end < 0) end = v.length;
        box.scrollIntoView({ block: "nearest", behavior: reducedMotion ? "auto" : "smooth" });
        ta.focus({ preventScroll: true });
        ta.setSelectionRange(start, end);
        ta.scrollTop = Math.max(0, (line - 1) * lineHeight() - ta.clientHeight / 3);
        flashLine = line;
        sync();
        flash.classList.add("on");
        clearTimeout(flashTimer);
        flashTimer = setTimeout(() => flash.classList.remove("on"), 1400);
      }
    };
  }

  function threatChips(box, selected) {
    box.replaceChildren();
    ((catalog && catalog.threat_classes) || []).forEach((id) => {
      const b = h("button", { type: "button", class: "chip-btn", "aria-pressed": selected.has(id) ? "true" : "false" },
                  [icon("check"), h("span", { text: t("threat." + id) })]);
      b.addEventListener("click", () => {
        if (selected.has(id)) selected.delete(id); else selected.add(id);
        b.setAttribute("aria-pressed", selected.has(id) ? "true" : "false");
      });
      box.appendChild(b);
    });
  }

  // ---------------------------------------------------------------------------------------
  // screen: Verify
  // ---------------------------------------------------------------------------------------
  const V = { policy: "verify", threats: new Set(), last: null, busy: false };
  const edBefore = Editor($("ed-before"), (name) => { if (!$("v-path").value.trim()) $("v-path").value = name; });
  const edAfter = Editor($("ed-after"), (name) => { if (!$("v-path").value.trim()) $("v-path").value = name; });

  // The example is a deliberately fake fix. It lives in assets/sample.json (data, like
  // tests/fixtures) so that Saikou's own change gate does not read it as code.
  async function loadSample() {
    const resp = await fetch("assets/sample.json", { credentials: "omit", cache: "no-store" });
    if (!resp.ok) throw new ApiError("HTTP " + resp.status, "http_" + resp.status, resp.status);
    return resp.json();
  }

  function verifyBody() {
    const body = { path: $("v-path").value.trim() || "input", before: edBefore.value(), after: edAfter.value(),
                   mode: V.policy, claimed_threats: Array.from(V.threats), strict_api: $("v-strict").checked };
    if ($("v-lang").value) body.language = $("v-lang").value;
    if (MODE === "local" && $("v-analyser").checked) body.analyser = true;
    return body;
  }

  function renderVerify() {
    const box = $("v-results");
    if (!V.last) { box.replaceChildren(stateEmpty(t("state.emptyVerify"), t("state.emptyVerifySub"), "verify")); return; }
    const data = V.last.data;
    const r = data.files[0];
    const frag = doc.createDocumentFragment();
    frag.appendChild(verdict(r.blocked, t(r.blocked ? "result.blocked" : "result.clear"),
                             t(r.blocked ? (data.mode === "gate" ? "result.blockedGateSub" : "result.blockedSub") : "result.clearSub"),
                             r.counts.hard_fail, r.counts.warn));
    frag.appendChild(fileReport(r, { onLine: (n) => edAfter.goTo(n) }));
    if (data.notes && data.notes.length) frag.appendChild(fold(t("report.notes"), h("ul", null, data.notes.map((n) => h("li", { text: n }))), true));
    const lim = limitsFold(data);
    if (lim) frag.appendChild(lim);
    const body = V.last.body;
    frag.appendChild(exportBar(data, () => call("POST", API.verify, Object.assign({}, body, { format: "sarif" }))));
    box.replaceChildren(frag);
  }

  async function runVerify() {
    if (V.busy) return;
    if (!edAfter.value().trim()) { toast(t("err.needAfter")); edAfter.el.focus(); return; }
    const box = $("v-results");
    const btn = $("v-run");
    V.busy = true;
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    box.setAttribute("aria-busy", "true");
    box.replaceChildren(stateLoading());
    const body = verifyBody();
    try {
      await ensureCatalog();
      const data = await call("POST", API.verify, body);
      V.last = { data, body };
      const r = data.files[0];
      edAfter.setMarks(r.findings);
      renderVerify();
      const c = counts(r.counts.hard_fail, r.counts.warn);
      live(t("live.done", { verdict: t(r.blocked ? "result.blocked" : "result.clear"), hard: c[0], warn: c[1] }));
      historyAdd({ kind: "verify", label: body.path !== "input" ? body.path : "", blocked: r.blocked,
                   hard: r.counts.hard_fail, warn: r.counts.warn });
    } catch (err) {
      box.replaceChildren(stateError(err));
      live(friendly(err));
      if (MODE === "hosted" && (err.code === "unauthorized" || err.code === "not_configured")) $("api-token").focus();
    } finally {
      V.busy = false;
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      box.setAttribute("aria-busy", "false");
    }
  }

  function setPolicy(p) {
    V.policy = p;
    $("v-policy").querySelectorAll("[data-policy]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.policy === p ? "true" : "false"));
  }

  // ---------------------------------------------------------------------------------------
  // screen: Gate (local only)
  // ---------------------------------------------------------------------------------------
  const G = { last: null, busy: false, open: {} };

  function renderGate() {
    const box = $("g-results");
    if (!G.last) { box.replaceChildren(stateEmpty(t("state.emptyGate"), t("state.emptyGateSub"), "gate")); return; }
    const { data, body } = G.last;
    const files = data.files || [];
    const frag = doc.createDocumentFragment();
    const skipped = data.skipped || [];
    if (!files.length && skipped.length) {
      frag.appendChild(stateEmpty(t("gate.noCheckable"), t("gate.noCheckableSub", { n: skipped.length }), "info"));
    } else if (!files.length) {
      frag.appendChild(stateEmpty(t("gate.noFiles"), t(body.staged ? "gate.noFilesStaged" : "gate.noFilesSub", { base: body.base }), "pass"));
    } else {
      const blocked = files.filter((f) => f.blocked).length;
      const hard = files.reduce((s, f) => s + f.counts.hard_fail, 0);
      const warn = files.reduce((s, f) => s + f.counts.warn, 0);
      frag.appendChild(verdict(blocked > 0, blocked ? t("gate.summaryBlocked", { b: blocked, n: files.length }) : t("gate.summaryClear"),
                               blocked ? t("gate.summaryBlockedSub") : t("gate.summaryClearSub", { n: files.length }), hard, warn));
    }
    frag.appendChild(h("div", { class: "meta-row" }, [
      h("span", { class: "tag", text: body.repo }),
      data.base ? h("span", { class: "tag", text: t("gate.base.tag", { sha: String(data.base).slice(0, 12) }) }) : null
    ]));
    if (files.length) {
      frag.appendChild(h("h2", { class: "section-title", text: t("gate.files") }));
      const ul = h("ul", { class: "file-list" });
      files.slice().sort((a, b) => (b.blocked - a.blocked) || a.path.localeCompare(b.path)).forEach((f, i) => {
        const id = "drill-" + i;
        const drill = h("div", { class: "drill", id, hidden: !G.open[f.path] });
        const row = h("button", { type: "button", class: "file-row", "aria-expanded": G.open[f.path] ? "true" : "false", "aria-controls": id }, [
          icon(f.blocked ? "block" : "pass", f.blocked ? "fail" : "pass"),
          h("span", { class: "file-path", text: f.path }),
          h("span", { class: "file-sub", text: [t(f.blocked ? "result.blocked" : "result.clear"), LANG_NAMES[f.language] || f.language, t("change." + f.change)].join(" · ") }),
          h("span", { class: "file-counts" }, [
            f.counts.hard_fail ? h("span", { class: "count hard", text: plural(f.counts.hard_fail, "count.hard1", "count.hardN") }) : null,
            f.counts.warn ? h("span", { class: "count warn", text: plural(f.counts.warn, "count.warn1", "count.warnN") }) : null
          ])
        ]);
        const fill = () => { drill.replaceChildren(fileReport(f, null)); };
        if (G.open[f.path]) fill();
        row.addEventListener("click", () => {
          const open = row.getAttribute("aria-expanded") !== "true";
          row.setAttribute("aria-expanded", open ? "true" : "false");
          G.open[f.path] = open;
          drill.hidden = !open;
          if (open) fill();
        });
        ul.appendChild(h("li", null, [row, drill]));
      });
      frag.appendChild(ul);
    }
    if (data.skipped && data.skipped.length) frag.appendChild(fold(t("gate.skipped", { n: data.skipped.length }), h("ul", null, data.skipped.map((s) => h("li", { text: s })))));
    const lim = limitsFold(data);
    if (lim) frag.appendChild(lim);
    if (files.length) frag.appendChild(exportBar(data, () => call("POST", API.git, Object.assign({}, body, { format: "sarif" }))));
    box.replaceChildren(frag);
  }

  async function runGate() {
    if (G.busy) return;
    const repo = $("g-repo").value.trim();
    if (!repo) { toast(t("err.needRepo")); $("g-repo").focus(); return; }
    const box = $("g-results");
    const btn = $("g-run");
    G.busy = true;
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    box.setAttribute("aria-busy", "true");
    box.replaceChildren(stateLoading());
    const body = { repo, base: $("g-base").value.trim() || "HEAD", staged: $("g-staged").checked, strict_api: $("g-strict").checked };
    try {
      await ensureCatalog();
      const data = await call("POST", API.git, body);
      G.last = { data, body };
      G.open = {};
      renderGate();
      const files = data.files || [];
      const hard = files.reduce((s, f) => s + f.counts.hard_fail, 0);
      const warn = files.reduce((s, f) => s + f.counts.warn, 0);
      const c = counts(hard, warn);
      live(t("live.done", { verdict: data.blocked ? t("result.blocked") : t("result.clear"), hard: c[0], warn: c[1] }));
      historyAdd({ kind: "gate", label: repo, blocked: !!data.blocked, hard, warn, files: files.length });
    } catch (err) {
      box.replaceChildren(stateError(err));
      live(friendly(err));
    } finally {
      G.busy = false;
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      box.setAttribute("aria-busy", "false");
    }
  }

  // ---------------------------------------------------------------------------------------
  // screen: Harden (local only)
  // ---------------------------------------------------------------------------------------
  const H = { threats: new Set(["injection"]), providers: null, loadedPath: "", loadedContent: null, last: null, busy: false };
  const edHarden = Editor($("ed-harden"), () => { H.loadedPath = ""; H.loadedContent = null; updateLoaded(); });

  function updateLoaded() {
    const el = $("h-loaded");
    if (H.loadedPath && edHarden.value() === H.loadedContent) el.textContent = t("harden.loaded", { path: H.loadedPath });
    else if (H.loadedPath) el.textContent = t("harden.edited");
    else el.textContent = edHarden.value().trim() ? t("harden.pasted") : "";
  }

  async function loadHardenFile() {
    const path = $("h-path").value.trim();
    if (!path) { toast(t("err.needPath")); $("h-path").focus(); return; }
    const btn = $("h-load");
    btn.disabled = true;
    try {
      const data = await call("POST", API.read, { path });
      edHarden.setValue(data.content);
      H.loadedPath = data.path;
      H.loadedContent = data.content;
      updateLoaded();
    } catch (err) {
      toast(friendly(err));
    } finally {
      btn.disabled = false;
    }
  }

  const usable = (p) => (p.id === "local" ? p.reachable && p.models.length > 0 : p.key_set);
  function selectedProvider() {
    const input = $("h-providers").querySelector("input[name=provider]:checked");
    return input && H.providers ? H.providers.providers.find((p) => p.id === input.value) : null;
  }
  function onProviderChange() {
    const p = selectedProvider();
    const list = $("h-models");
    list.replaceChildren();
    if (!p) { $("h-where").textContent = ""; return; }
    save("local", "saikou.provider", p.id);
    const models = p.id === "local" ? p.models : [p.default_model].filter(Boolean);
    models.forEach((m) => list.appendChild(h("option", { value: m })));
    $("h-model").placeholder = p.default_model || models[0] || "";
    $("h-where").textContent = p.id === "local" ? t("harden.whereLocal") : t("harden.whereRemote", { url: p.base_url });
  }
  function renderProviders() {
    const box = $("h-providers");
    if (!H.providers) return;
    const remembered = load("local", "saikou.provider", "");
    const current = selectedProvider();
    const want = current ? current.id : remembered;
    box.replaceChildren();
    let chosen = false;
    H.providers.providers.forEach((p) => {
      const ok = usable(p);
      let status;
      if (p.id === "local") status = p.not_local ? t("provider.localRemote") : !p.reachable ? t("provider.localDown") : p.models.length ? t("provider.localUp", { n: p.models.length }) : t("provider.localNone");
      else status = p.key_set ? t("provider.keySet", { env: p.key_env }) : t("provider.keyMissing", { env: p.key_env });
      const input = h("input", { type: "radio", name: "provider", value: p.id, disabled: !ok });
      if (ok && (p.id === want || (!want && !chosen))) { input.checked = true; chosen = true; }
      input.addEventListener("change", onProviderChange);
      box.appendChild(h("label", { class: "provider" }, [
        input,
        h("span", null, [h("b", { text: t("provider." + p.id) }), h("small", { text: p.base_url }),
                         h("span", { class: "status " + (ok ? "ok" : "missing") }, [icon(ok ? "pass" : "warn"), status])])
      ]));
    });
    if (!box.querySelector("input:checked")) {
      const first = box.querySelector("input:not(:disabled)");
      if (first) first.checked = true;
    }
    $("h-analyser-wrap").hidden = !H.providers.analyser_available;
    onProviderChange();
  }
  let providersPromise = null;
  function ensureProviders() {
    if (MODE !== "local") return Promise.resolve(null);
    if (!providersPromise) {
      providersPromise = call("GET", API.providers).then((data) => { H.providers = data; renderProviders(); return data; })
        .catch((err) => { providersPromise = null; $("h-providers").replaceChildren(stateError(err)); });
    }
    return providersPromise;
  }

  function diffView(text) {
    if (!text) return h("p", { class: "empty-line", text: t("harden.noDiff") });
    const tbody = h("tbody");
    let oldN = 0;
    let newN = 0;
    let inHunk = false;
    text.split("\n").forEach((line) => {
      const m = /^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      if (m) {
        inHunk = true;
        oldN = parseInt(m[1], 10);
        newN = parseInt(m[2], 10);
        tbody.appendChild(h("tr", { class: "hunk" }, [h("td", { colspan: "4", text: line })]));
        return;
      }
      if (!inHunk) return;                      // the ---/+++ file header
      const sign = line.charAt(0);
      const rest = line.slice(1);
      if (sign === "+") tbody.appendChild(h("tr", { class: "add" }, [h("td", { class: "ln" }), h("td", { class: "ln", text: newN++ }), h("td", { class: "sign", text: "+" }), h("td", { text: rest })]));
      else if (sign === "-") tbody.appendChild(h("tr", { class: "del" }, [h("td", { class: "ln", text: oldN++ }), h("td", { class: "ln" }), h("td", { class: "sign", text: "-" }), h("td", { text: rest })]));
      else if (sign !== "\\") tbody.appendChild(h("tr", null, [h("td", { class: "ln", text: oldN++ }), h("td", { class: "ln", text: newN++ }), h("td", { class: "sign", text: " " }), h("td", { text: rest })]));
    });
    return h("div", { class: "diff", tabindex: "0", role: "region", "aria-label": t("harden.diff") }, h("table", null, tbody));
  }

  function renderHarden() {
    const box = $("h-results");
    if (!H.last) { box.replaceChildren(stateEmpty(t("state.emptyHarden"), t("state.emptyHardenSub"), "harden")); return; }
    const r = H.last.data;
    const ok = r.status === "verified";
    const led = r.evidence_ledger || { findings: [], claims_by_provenance: {} };
    const hard = led.findings.filter((f) => f.severity === "hard_fail").length;
    const frag = doc.createDocumentFragment();
    frag.appendChild(verdict(!ok, t(ok ? "harden.verified" : "harden.rejected"), t(ok ? "harden.verifiedSub" : "harden.rejectedSub"),
                             hard, led.findings.length - hard));
    frag.appendChild(h("div", { class: "meta-row" }, [
      h("span", { class: "tag", text: t("provider." + r.provider) }), h("span", { class: "tag", text: r.model }),
      h("span", { class: "tag", text: LANG_NAMES[r.language] || r.language }), h("span", { class: "tag", text: r.verification_tier })
    ]));
    frag.appendChild(h("h2", { class: "section-title", text: t(ok ? "harden.diff" : "harden.diffRejected") }));
    frag.appendChild(diffView(r.diff));
    frag.appendChild(h("h2", { class: "section-title", text: t("harden.ledger") }));
    frag.appendChild(led.findings.length ? findingsList(led.findings, null) : h("p", { class: "empty-line", text: t("report.noFindings") }));
    const groups = led.claims_by_provenance || {};
    const claims = [];
    Object.keys(groups).forEach((prov) => groups[prov].forEach((c) => claims.push(h("li", null, [
      h("span", { class: "prov", text: prov }),
      h("span", { class: "text", lang: "en", text: c.statement + (c.detail ? " - " + c.detail : "") }),
      prov === "model" ? h("span", { class: "unverified", text: t("harden.unverified") }) : null
    ]))));
    if (claims.length) frag.appendChild(fold(t("harden.claims"), h("ul", { class: "claims" }, claims), true));
    if (r.assumptions && r.assumptions.length) frag.appendChild(fold(t("harden.assumptions"), h("ul", null, r.assumptions.map((a) => h("li", { lang: "en", text: a })))));
    frag.appendChild(h("p", { class: "hint", lang: "en", text: r.disclaimer || "" }));

    // Writing: only verified output, only to the loaded file, only if it was not edited.
    const sent = H.last.sent;
    let reason = "";
    if (!ok) reason = t("harden.writeOffRejected");
    else if (!sent.path) reason = t("harden.writeOffPasted");
    else if (!sent.unedited) reason = t("harden.writeOffEdited");
    else if (H.last.written) reason = t("harden.writtenNote");
    const can = ok && !reason && r.result_id;
    const writeBtn = h("button", { type: "button", class: "btn primary", disabled: !can }, [icon("write"), t("harden.write")]);
    writeBtn.addEventListener("click", () => writeHarden(writeBtn));
    frag.appendChild(h("div", { class: "write-bar" }, [writeBtn, h("p", { class: "hint", text: can ? t("harden.writeHint", { path: sent.path }) : reason })]));
    box.replaceChildren(frag);
  }

  async function writeHarden(btn) {
    const { data, sent } = H.last;
    const yes = await confirmDialog(t("dlg.writeTitle"), [h("p", { text: t("dlg.writeBody") }), h("p", null, h("code", { text: sent.path }))], t("dlg.writeOk"), false);
    if (!yes) { btn.focus(); return; }
    btn.disabled = true;
    try {
      await call("POST", API.write, { result_id: data.result_id, path: sent.path });
      H.last.written = true;
      edHarden.setValue(data.hardened_code);
      H.loadedPath = sent.path;
      H.loadedContent = data.hardened_code;
      updateLoaded();
      renderHarden();
      toast(t("harden.written", { path: sent.path }));
      live(t("harden.written", { path: sent.path }));
    } catch (err) {
      btn.disabled = false;
      toast(friendly(err));
      live(friendly(err));
    }
  }

  async function runHarden() {
    if (H.busy) return;
    const code = edHarden.value();
    if (!code.trim()) { toast(t("err.needCode")); edHarden.el.focus(); return; }
    await ensureProviders();
    const p = selectedProvider();
    if (!p || !usable(p)) { toast(t("err.needProvider")); return; }
    const model = $("h-model").value.trim() || p.default_model || (p.models && p.models[0]) || "";
    const unedited = !!H.loadedPath && code === H.loadedContent;
    const body = { code, path: H.loadedPath || "", provider: p.id, model, threats: Array.from(H.threats) };
    if (!$("h-analyser-wrap").hidden && $("h-analyser").checked) body.analyser = true;
    const box = $("h-results");
    const btn = $("h-run");
    H.busy = true;
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    box.setAttribute("aria-busy", "true");
    const started = Date.now();
    const waiting = h("p", { text: t("harden.waiting", { model, s: 0 }) });
    box.replaceChildren(h("div", { class: "state" }, [h("div", { class: "spinner", "aria-hidden": "true" }), waiting,
                                                      p.id === "local" ? h("p", { class: "hint", text: t("harden.slow") }) : null]));
    const timer = setInterval(() => { waiting.textContent = t("harden.waiting", { model, s: Math.round((Date.now() - started) / 1000) }); }, 1000);
    try {
      await ensureCatalog();
      const data = await call("POST", API.harden, body);
      H.last = { data, sent: { path: body.path, unedited }, written: false };
      renderHarden();
      const led = data.evidence_ledger || { findings: [] };
      const hard = led.findings.filter((f) => f.severity === "hard_fail").length;
      const c = counts(hard, led.findings.length - hard);
      live(t("live.done", { verdict: t(data.status === "verified" ? "harden.verified" : "harden.rejected"), hard: c[0], warn: c[1] }));
      historyAdd({ kind: "harden", label: (body.path || "") + " · " + model, blocked: data.status !== "verified",
                   hard, warn: led.findings.length - hard });
    } catch (err) {
      box.replaceChildren(stateError(err));
      live(friendly(err));
    } finally {
      clearInterval(timer);
      H.busy = false;
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      box.setAttribute("aria-busy", "false");
    }
  }

  // ---------------------------------------------------------------------------------------
  // screen: Checks
  // ---------------------------------------------------------------------------------------
  function fillSelect(sel, options) {
    const keep = sel.value;
    sel.replaceChildren(...options.map(([value, label]) => h("option", { value, text: label })));
    if (options.some(([v]) => v === keep)) sel.value = keep;
  }
  function checksFilters() {
    fillSelect($("c-prov"), [["", t("checks.any")], ["tool", "tool"], ["parser", "parser"], ["mechanical", "mechanical"]]);
    fillSelect($("c-sev"), [["", t("checks.any")], ["hard", t("sev.hard")], ["warn", t("sev.warn")], ["depends", t("sev.depends")]]);
    fillSelect($("c-applies"), [["", t("checks.any")]].concat(["python", "javascript", "config", "all", "harden"].map((a) => [a, t("applies." + a)])));
  }
  function renderLegend() {
    if (!catalog) return;
    const dl = (entries) => h("dl", null, entries.reduce((acc, [k, v]) => acc.concat([h("dt", { text: k }), h("dd", { text: both(v) })]), []));
    $("c-legend-body").replaceChildren(
      h("h2", { class: "section-title", text: t("legend.prov") }), dl(Object.entries(catalog.provenance)),
      h("h2", { class: "section-title", text: t("legend.tiers") }), dl(Object.entries(catalog.tiers)));
  }
  function renderChecks() {
    const list = $("c-list");
    if (!catalog) { list.replaceChildren(stateLoading(t("state.loading"))); return; }
    const q = $("c-q").value.trim().toLowerCase();
    const prov = $("c-prov").value;
    const sev = $("c-sev").value;
    const ap = $("c-applies").value;
    const hits = catalog.checks.filter((c) => (!prov || c.provenance === prov) && (!sev || c.severity === sev) && (!ap || c.applies === ap) &&
      (!q || [c.id, c.title.en, c.title.nl, c.description.en, c.description.nl, c.example_bad].join(" ").toLowerCase().includes(q)));
    $("c-count").textContent = t("checks.count", { n: hits.length, total: catalog.checks.length });
    if (!hits.length) {
      const reset = h("button", { type: "button", class: "btn", text: t("checks.reset") });
      reset.addEventListener("click", () => { $("c-q").value = ""; $("c-prov").value = ""; $("c-sev").value = ""; $("c-applies").value = ""; renderChecks(); $("c-q").focus(); });
      list.replaceChildren(h("div", { class: "state" }, [icon("search"), h("h2", { text: t("checks.none") }), reset]));
      return;
    }
    list.replaceChildren(...hits.map((c) => {
      const ex = [];
      if (c.example_bad) ex.push(h("div", null, [h("p", { class: "ex-label bad", text: t("finding.bad") }), h("pre", { class: "block", text: c.example_bad })]));
      if (c.example_good) ex.push(h("div", null, [h("p", { class: "ex-label good", text: t("finding.good") }), h("pre", { class: "block", text: c.example_good })]));
      return h("article", { class: "check-card" }, [
        h("h2", { text: both(c.title) }),
        h("code", { class: "id", text: c.id }),
        h("div", { class: "tags" }, [
          h("span", { class: "prov", text: c.provenance }),
          h("span", { class: "tag", text: t("sev." + c.severity) }),
          h("span", { class: "tag", text: t("applies." + c.applies) }),
          h("span", { class: "tag", text: t("modes." + c.modes) })
        ]),
        h("p", { text: both(c.description) }),
        ex.length ? h("details", null, [h("summary", null, [icon("chevron", "chev"), t("checks.example")]), h("div", { class: "examples" }, ex)]) : null
      ]);
    }));
  }

  // ---------------------------------------------------------------------------------------
  // shell: screens, theme, language, keyboard
  // ---------------------------------------------------------------------------------------
  let current = "verify";
  function show(name, focus) {
    if (!SCREENS.includes(name)) name = SCREENS[0];
    current = name;
    ALL_SCREENS.forEach((s) => { $("screen-" + s).hidden = s !== name; });
    doc.querySelectorAll(".rail-btn").forEach((b) => {
      if (b.dataset.screen === name) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    save("local", "saikou.screen", name);
    if (name === "checks") ensureCatalog().then(() => { renderLegend(); renderChecks(); }).catch((e) => $("c-list").replaceChildren(stateError(e)));
    if (name === "history") renderHistory();
    if (name === "harden") ensureProviders();
    if (focus) {
      const head = $("h-" + name);
      head.focus({ preventScroll: true });
      $("main").scrollTop = 0;
      window.scrollTo(0, 0);
    }
  }

  const THEMES = ["system", "light", "dark"];
  let theme = load("local", "saikou.theme", "system");
  if (!THEMES.includes(theme)) theme = "system";
  function applyTheme() {
    root.setAttribute("data-theme", theme);
    const btn = $("theme-btn");
    btn.querySelector("use").setAttribute("href", "#i-" + { system: "monitor", light: "sun", dark: "moon" }[theme]);
    $("theme-label").textContent = t("theme." + theme);
    btn.setAttribute("aria-label", t("theme.aria", { name: t("theme." + theme) }));
  }

  function applyLang() {
    root.lang = lang;
    doc.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.getAttribute("data-i18n")); });
    doc.querySelectorAll("[data-i18n-attr]").forEach((el) => {
      el.getAttribute("data-i18n-attr").split(";").forEach((pair) => {
        const [attr, key] = pair.split(":");
        if (attr && key) el.setAttribute(attr.trim(), t(key.trim()));
      });
    });
    doc.querySelectorAll("[data-lang]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.lang === lang ? "true" : "false"));
    $("mode-badge").textContent = t(MODE === "hosted" ? "badge.hosted" : "badge.local");
    applyTheme();
    langSelect();
    checksFilters();
    if (catalog) { threatChips($("v-threats"), V.threats); threatChips($("h-threats"), H.threats); }
    [edBefore, edAfter, edHarden].forEach((e) => e.repaint());
    updateLoaded();
    renderVerify();
    if (MODE === "local") { renderGate(); renderHarden(); renderProviders(); }
    if (current === "checks") { renderLegend(); renderChecks(); }
    if (current === "history") renderHistory();
  }

  function langSelect() {
    const langs = (catalog && catalog.languages) || Object.keys(LANG_NAMES).filter((k) => k !== "unknown");
    fillSelect($("v-lang"), [["", t("lang.auto")]].concat(langs.map((l) => [l, LANG_NAMES[l] || l])));
  }

  function runCurrent() {
    if (current === "verify") runVerify();
    else if (current === "gate") runGate();
    else if (current === "harden") runHarden();
    else if (current === "checks") $("c-q").focus();
  }

  function wire() {
    doc.querySelectorAll(".rail-btn").forEach((b) => {
      if (!SCREENS.includes(b.dataset.screen)) { b.hidden = true; return; }
      b.querySelector("kbd").textContent = String(SCREENS.indexOf(b.dataset.screen) + 1);
      b.addEventListener("click", () => show(b.dataset.screen, true));
    });
    $("theme-btn").addEventListener("click", () => {
      theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
      save("local", "saikou.theme", theme);
      applyTheme();
    });
    doc.querySelectorAll("[data-lang]").forEach((b) => b.addEventListener("click", () => {
      if (lang === b.dataset.lang) return;
      lang = b.dataset.lang;
      save("local", "saikou.lang", lang);
      applyLang();
    }));
    doc.querySelectorAll("[data-open]").forEach((b) => {
      const input = $(b.dataset.open);
      b.addEventListener("click", () => input.click());
      input.addEventListener("change", () => {
        const file = input.files && input.files[0];
        if (file) (input.id === "file-before" ? edBefore : edAfter).loadFile(file);
        input.value = "";
      });
    });
    const editors = { "ed-before": edBefore, "ed-after": edAfter, "ed-harden": edHarden };
    doc.querySelectorAll("[data-clear]").forEach((b) => b.addEventListener("click", () => {
      const ed = editors[b.dataset.clear];
      ed.setValue("");
      if (ed === edHarden) { H.loadedPath = ""; H.loadedContent = null; updateLoaded(); }
      ed.el.focus();
    }));
    edHarden.el.addEventListener("input", updateLoaded);
    edHarden.el.addEventListener("change", updateLoaded);
    $("v-policy").querySelectorAll("[data-policy]").forEach((b) => b.addEventListener("click", () => setPolicy(b.dataset.policy)));
    $("v-run").addEventListener("click", runVerify);
    $("v-sample").addEventListener("click", async () => {
      let sample;
      try { sample = await loadSample(); } catch (err) { toast(friendly(err)); return; }
      edBefore.setValue(sample.before);
      edAfter.setValue(sample.after);
      $("v-path").value = sample.path;
      $("v-lang").value = "";
      setPolicy("verify");
      V.threats.clear();
      sample.threats.forEach((x) => V.threats.add(x));
      threatChips($("v-threats"), V.threats);
      runVerify();
    });
    if (MODE === "local") {
      $("g-run").addEventListener("click", runGate);
      $("h-run").addEventListener("click", runHarden);
      $("h-load").addEventListener("click", loadHardenFile);
      $("h-path").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); loadHardenFile(); } });
    } else {
      $("token-panel").hidden = false;
      $("api-token").value = token;
      $("token-save").addEventListener("click", () => {
        token = $("api-token").value.trim();
        save("session", "saikou.apiToken", token || null);
        toast(t(token ? "token.saved" : "token.cleared"));
      });
      $("api-token").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); $("token-save").click(); } });
    }
    ["c-q", "c-prov", "c-sev", "c-applies"].forEach((id) => $(id).addEventListener("input", renderChecks));
    $("hist-clear").addEventListener("click", async () => {
      const yes = await confirmDialog(t("dlg.clearTitle"), [h("p", { text: t("dlg.clearBody") })], t("dlg.clearOk"), true);
      if (yes) { save("local", HKEY, null); renderHistory(); }
      $("hist-clear").focus();
    });
    doc.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); runCurrent(); return; }
      if (e.ctrlKey || e.metaKey || e.altKey || e.shiftKey) return;
      const el = e.target;
      const tag = el && el.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || (el && el.isContentEditable)) return;
      if (doc.querySelector("dialog[open]")) return;
      const n = parseInt(e.key, 10);
      if (n >= 1 && n <= SCREENS.length) { e.preventDefault(); show(SCREENS[n - 1], true); }
    });
  }

  async function boot() {
    wire();
    applyLang();
    show(load("local", "saikou.screen", "verify"), false);
    if (MODE === "local" && !token) {
      const err = $("boot-error");
      err.replaceChildren(icon("key"), h("div", null, [h("h2", { text: t("err.title") }), h("p", { text: t("err.noToken") })]));
      err.setAttribute("role", "alert");
      err.hidden = false;
      return;
    }
    try {
      await ensureCatalog();
      threatChips($("v-threats"), V.threats);
      threatChips($("h-threats"), H.threats);
      langSelect();
      if (current === "checks") { renderLegend(); renderChecks(); }
    } catch (err) {
      $("v-threats").replaceChildren(h("p", { class: "hint", text: friendly(err) }));
    }
    if (MODE === "local") {
      try {
        const meta = await call("GET", API.meta);
        if (meta.repo && !$("g-repo").value) $("g-repo").value = meta.repo;
        $("mode-badge").title = "saikou " + meta.version;
      } catch (err) { /* the screens report their own errors */ }
    }
  }

  boot();
})();
