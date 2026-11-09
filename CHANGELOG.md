# Changelog

## 1.2.1 - not released yet

### Security
- The sink checks follow rewritten forms, not only the literal one. These fake fixes used to come
  back `ok`: `shell=1`, `shell=bool(1)`, `shell=not False`, a module constant that is `True`,
  `**{'shell': True}`; `verify=bool(0)`; `s = requests.Session()` then `s.verify = False`;
  `_e = eval` then `_e(x)`; `cur.execute(sql, ())` with an empty parameter tuple; and
  `run = cur.execute` then `run(f"...")`. The checks read values the file itself fixes
  (constants, `not`, `and`/`or`, `bool(...)`, names assigned exactly once). Python only. Old and
  new engine compared on 18,713 Python files (CPython 3.11 `Lib`, a virtual environment's
  site-packages, one application): 0 false blocks in change gating with either. A local constant
  SQL string passed to `execute()` is no longer reported.
- Change gating reads the language of a script without an extension from its `#!` line (python,
  node, sh and the like). Such a script used to be skipped unless `--include-unknown` was given,
  so any change in it passed the gate.
- Python too deeply nested to parse is a `parse_failure` instead of a crash (`RecursionError`,
  `MemoryError`): the hosted API answered 500 and the CLI gate stopped with a traceback.
- The GitHub Action runs the installed engine even when the checked-out repository holds a
  `saikou/` or `pip/` folder or sets `PYTHONPATH`; a pull request could stand in for the engine.
- `saikou ui` keeps the session key off the command line: the browser gets a private temporary
  page that redirects, removed after 60 seconds, at shutdown or at exit.
- The hosted API's sessions are shared fairly: each token gets an equal share of `MAX_SESSIONS`
  (at least 1) and replaces only its own oldest intake. One token could push out everyone else's.
  The per-token rate limit is thread-safe; concurrent requests could pass it together.
- Every external GitHub Action is pinned to a commit SHA and moved to its current major version.

### Fixed
- The hosted API works on Python 3.9. Its session store made an `asyncio.Lock` at import, which on
  3.9 binds to the event loop current at that moment: importing could fail, and the lock belonged
  to the wrong loop once the server ran. The lock is now made when the store is first used.
- `saikou harden --write` and the local app refuse a file that is not UTF-8. They read such a
  file with replacement characters and then wrote U+FFFD over the real bytes.
- Writing a result is atomic (a temporary file in the same folder, then `os.replace`, with the
  file mode copied), so a full disk cannot leave an empty or half file. Hard links and ACLs are
  not kept. `--write` also refuses a file that changed while the model was working.
- In the local app, Harden accepted any `compat` value, and an unknown one silently switched off
  the `strict_api` gate. `compat`, `dependencies` and `error_policy` now take only the values the
  CLI and the hosted API take (422 otherwise), checked before the model is called.
- The hosted API answers every unexpected error in its documented JSON shape, with the traceback
  only in the server log. A non-ASCII `Authorization` header is a 401 and a non-ASCII token works;
  a non-string `before` or `after` in `/v1/verify/batch` is a 422. All three were text/plain 500s.
- `saikou ui --port 80` accepts the `Host` and `Origin` values browsers send for the default port.
- A provider that refuses structured output no longer costs an attempt, so with `retries=0` the
  request in plain JSON mode is still sent.
- A provider's default endpoint written in capitals in `.env` no longer stops the run.
- The suppression oracle's drift report prints plain version numbers.

### Changed
- `verify`, `verify_batch` and the local git gate check `format` and every option before any
  verification or git run.
- `qa/site` no longer uses Lighthouse CI, which brought all 17 npm audit findings of that folder.
- `fp_corpus.py` records the engine version, commit, date and Python version in its output, and
  the files in `docs/measurements/` carry them.
- SARIF upload: the README and the Action state GitHub's full requirements for a private
  repository (GitHub Code Security or Advanced Security, and `actions: read`).

## 1.2.0 - 2026-11-08

### Added
- Hosted API v1 (`saikou.api`, rebuilt on the shared `saikou.service`): `POST /v1/verify`,
  `POST /v1/verify/batch`, `GET /v1/checks` (public) and `GET /healthz`; `/harden/intake` and
  `/harden/apply` stay. One error shape, `{"error": {"code", "message"}}`. Bearer tokens from
  `API_TOKENS` fail closed unless `ENVIRONMENT=dev`; rate limit per token; request bodies are
  capped by `Content-Length` and by stream. `/harden/apply` answers 503 without a model key.
  The hosted service never touches the file system or git. (`e4e2120`)
- Playground at `/` of the hosted API: the web app with Verify and Checks only. (`e4e2120`)
- Local app, `saikou ui` (`saikou.server`, `saikou/web/`): standard library only, binds
  `127.0.0.1`, one-time key in the URL fragment, Host and Origin checks. Screens Verify, Gate,
  Harden, Checks and History; light and dark, English and Dutch; no third-party requests.
  Harden writes exactly the output that was reviewed, and its result includes a unified diff.
  Checked in a browser at desktop and 375 px width, in both themes and both languages, with
  the fixes from that pass. (`e4e2120`, `e51fd3a`)
- `Dockerfile` and `.dockerignore` for the hosted API: runs as non-root; no `.env`,
  `internal/` or `.git` in the image. (`e4e2120`)
- saikou.tech: canonical URLs, Open Graph and Twitter tags, hreflang pairs, JSON-LD
  `SoftwareApplication` (no ratings), `sitemap.xml` and `robots.txt`; `scripts/check_site.py`
  fails on a missing or broken one. (`38ad8f5`)
- README badge `site/assets/fixes-checked-with-saikou.svg`: says "checked", never "secure".
  (`38ad8f5`)
- JavaScript and TypeScript suppressions, found by `scripts/suppression_oracle_js.py` (761 pairs;
  ESLint 9 with eslint-plugin-security, the TypeScript compiler and semgrep, all executed). Pairs in
  which a tool honoured the marker and Saikou did not block went from 112 to 12, and those 12 are
  TypeScript directives that are a warning on purpose:
  - ESLint and TypeScript directives in block comments (`/* eslint-disable */`, `/* @ts-ignore */`)
    were not counted, nor `@ts-expect-error`, `/* nosemgrep */` or `/* NOSONAR */`;
  - an ESLint directive without a rule list silences every rule, the security ones included, and
    was only a warning: it now blocks where it covers a line that holds a risky call (`eval`,
    `new Function`, child_process, `fs`, `vm`, `innerHTML`, a non-literal `require`, ...);
  - a marker moved onto another line, count unchanged, is reported (per line, with the
    enclosing blocks as context).
- A suppression coverage statement that is generated, not written:
  - `scripts/suppression_oracle.py` generates 1,697 before/after pairs (spellings, positions,
    line endings and encodings, strings against comments, unreadable files, moved markers) and
    asks bandit, ruff, semgrep (executed), flake8 (pattern from its wheel), sonar-python and
    CodeQL (patterns from their sources) whether each honours the new marker;
  - `tests/test_suppression_oracle.py` runs Saikou on every pair and requires the verdict frozen
    in `tests/fixtures/suppression_oracle_golden.json`; a marker a tool honours and Saikou does
    not report fails it, and so does any unexpected change of verdict in either direction;
  - `docs/conformance/suppression-coverage.md` and `.nl.md` state the result with its scope and
    are generated from the golden file; the test fails when they are out of date;
  - `.github/workflows/oracle.yml` asks the executed tools again every week (Python and
    JavaScript/TypeScript) and fails when a new version reads a marker differently from the
    frozen answer;
  - `scripts/check_site.py` bans unscoped claims about what the checks catch ("never misses",
    "catches every", "guarantee", "volledige dekking", ...), except when they deny a promise;
    README and both home pages say how the check is verified and link to the statement.

### Fixed
- `suppression_introduced` no longer counts a Python comment marker (`# nosec`, `type: ignore`,
  `pylint: disable`, ...) that sits inside a string literal, such as fake-fix test data or help
  text: bandit 1.7.3+ reads `nosec` from comment tokens only. flake8 `noqa` and `nosemgrep`
  still count anywhere on the line, because those tools match the raw line. Python that does not
  tokenize, does not parse on the running interpreter, or uses lone CR line endings is counted as
  text, as before.
- `suppression_introduced` now recognises suppressions it missed: `# NOSONAR` and an upper-case
  `# NOSEC` (sonar-python), `# lgtm`, `lgtm[...]` and `codeql[...]` in any case (CodeQL), and
  bandit's marker glued to a test id (`# nosecB602`).
- The elision check no longer misses a real `... existing code ...` comment:
  - in Python after a line-separator character (form feed, U+2028, ...) earlier in the file;
  - in a Python 3.12+ f-string replacement field;
  - in JavaScript after an apostrophe in a comment, a quote inside a regex literal, or quotes
    in JSX text;
  - when the input could not be scanned.
- JavaScript guard checks now use a real left-to-right scanner instead of separate regexes.
  This fixes false blocks from `//` inside strings (`"http://x"`), JSX closing tags, `x! / y`,
  `i++ / y`, template substitutions and spreads (`...safe`), and an async class method no
  longer makes an unrelated bare call of the same name "async".
- The `keep the existing code/file/function/...` elision marker no longer fires on prose such
  as "keep the existing file on disk if it's newer" or "keep the existing code style". It counts
  when it ends the clause, or is followed by `here`, `below`, `above`, `unchanged`, `as is`,
  `intact` or `untouched`. Known limit: a placeholder that continues in prose ("keep the existing
  implementation from before") is not caught by this marker.
- JavaScript guard-name patterns matched `can`/`is`/`has`/`safe`/`user` followed by any letter,
  because `(?i)` also made the capital case-insensitive: `reader.cancel(e).catch(...)` was a
  floated authorisation guard, and `hash(...)`, `issue(...)` and `isolate(...)` were guards. Only
  camelCase names (`canWrite`, `isValid`) count now. Measured on 25,922 JS/TS files: 13 findings
  gone, all `.cancel().catch(...)`, none added.
- A pattern added in this cycle that was quadratic on very long lines (a 4.6 MB base64 line
  took 90 s) is now linear.
- Change gating no longer blocks a newly added empty file such as `tests/__init__.py`.
- Suppressions the real tools honour that `suppression_introduced` did not count, found by
  `scripts/suppression_oracle.py` (1,697 before/after pairs; bandit 1.9.4, ruff 0.17.1 and
  semgrep 1.181.0 executed, flake8 read from its wheel, sonar-python and CodeQL taken over from
  their sources). Pairs in which a tool honours the marker and Saikou said nothing went from 72 to 0:
  - a word glued to bandit's marker (`# nosecure`, `# nosec_lines`): bandit reads it as a bare
    marker that skips everything on the line. An earlier fix in this cycle excluded these on a
    wrong reading of bandit; checked by running bandit 1.9.4;
  - semgrep's marker in upper case and its short form (`# nosem`);
  - CodeQL's bare annotation after a semicolon followed by `(`, `=` or `.`;
  - flake8's marker in upper case or with a word glued to it (style suppressions, so a warning
    when gating);
  - `usedforsecurity` set to `(False)`, `0`, `None`, a name, or on the next line: bandit's
    weak-hash check only fires on the constant True (a warning when gating, as for `=False`);
  - a marker that only shows after decoding the declared source encoding (`# coding: utf-7`,
    where `+ACM-` is a hash sign).
  A second round of the oracle, with moved markers, wrapped lines and long lines added:
  - a marker moved onto code that had none, while the number of markers stays the same (from
    one sink to another, or to an identical statement in the same function), is reported. The
    check is per Python statement (enclosing names, syntax, number among identical ones), so
    re-wrapping a statement, reordering functions or fixing a sink and keeping its marker is not;
  - a bare `noqa` on a statement that makes a call bandit reports (subprocess, `os.system`,
    `eval`, `yaml.load`, md5/sha1, pickle, XML parsers, `random`, ..., import aliases
    resolved) blocks when gating: flake8, ruff and sonar-python honour it for the security
    finding. On an import line or with only style codes it stays a warning;
  - a `noqa: S602` behind a long line blocked nothing: the hit was classified on an excerpt cut
    at 120 characters;
  - `usedforsecurity=` other than True on password material (`hashlib.md5(password, ...)`)
    blocks when gating; on other data it stays a warning, being the documented remedy;
  - a ` nosemgrep` or ` nosem` anywhere on the line of a statement that makes a security call,
    a string included: semgrep ignores the finding (executed; its Python constants had no
    comment anchor, but nothing said so for the real matching). Elsewhere it is prose.

### Changed
- `hardcoded_secret_material` is a warning, not a block, when gating a change to a test file
  (`test/`, `tests/`, `testing/`, `test_*.py`, `*_test.py`, `conftest.py`, `tests.py`;
  repository-relative paths only). Recognisable provider keys (AWS, GitHub, Slack, Stripe live,
  Google, OpenAI, Anthropic) and private keys still block. Verifying a claimed fix always blocks.
- The `analyser` extra, the `dev` extra and the GitHub Action now require `bandit>=1.7.3`:
  1.7.0 to 1.7.2 also honoured `# nosec` inside string literals.

### Security
- Change gating no longer skips a changed file whose new version it cannot check. A file in
  a checked language, or an analyser configuration file, with a NUL byte in its first 8 KB,
  more than 1,000,000 bytes, unreadable in the work tree, or now a symbolic link or a
  submodule, used to be listed as skipped (or, for a symlink replaced by a file, not listed
  at all) while the gate passed, so one NUL byte in a comment let any change through. It now
  blocks with the new check `content_not_checked`, reported with the `asserted` tier because
  nothing was parsed, in `saikou diff`, the GitHub Action and the local app's Gate screen;
  with `--include-unknown` this holds for every file. UTF-16 and UTF-32 files with a
  byte-order mark are read as text. When only the old version is unreadable, the new one is
  checked as if the file were new. A file that is meant to be like this is left out with a
  pathspec (`-- . ':(exclude)vendor/bundle.js'`, Action input `paths`); the new Action input
  `warn-only` passes `--warn-only`, which demotes a check for every file. Files in languages
  Saikou does not check are still skipped and listed.
- `saikou harden` and `saikou ui` read only provider keys, model names, `LLM_TIMEOUT_S`,
  `LLM_MAX_OUTPUT_TOKENS` and the `--api-key-env` variable from `.env`. They used to set
  every name in the file, so a `.env` in someone else's repository could point
  `OLLAMA_BASE_URL` or `LLM_BASE_URL` at its own server and receive your key from your
  environment, choose another provider with `LLM_PROVIDER`, or set a proxy, a CA bundle,
  `PATH` or git settings. A run whose endpoint is set only in `.env`, to anything but the
  preset's default, now stops and says to use the environment or `--base-url`.
  `--api-key-env` naming an endpoint variable is refused. In `.env.example`, `LLM_BASE_URL` is
  now commented out (only the hosted API reads it from that file).
- Plain `http` is accepted only when the parsed host is `localhost` or a loopback address.
  The old prefix test also accepted `http://localhost.example.com`, so the key could go
  unencrypted to another domain. A base URL with a user name or password, a backslash, a
  space, a control character, a percent-encoded host, a query or a fragment is refused, and
  the request goes to the URL rebuilt from the checked parts. `saikou harden` checks the URL
  before it names it, and says "nothing leaves it" only for a loopback endpoint.
- The model call no longer follows a redirect. urllib followed a 301, 302 or 303 to any
  host, from https to plain http too, with the `Authorization` header and so the key, and
  used whatever came back as the model's answer. A redirect is now an error that says to set
  the base URL to the final address. Nothing that worked stops working: a followed POST
  became a GET without a body, and a 307 or 308 already failed.
- A model on this machine (`localhost` or a loopback address) is never reached through a
  proxy. With `HTTP_PROXY` in the environment, the request for a local model, key
  included, went in plain http to the proxy (and a proxy on another machine could not even
  reach the local server).
  Remote endpoints still use the environment's proxy.
- The hosted API's `model_error` no longer passes on the provider's own message (it could
  name part of the server's key or its provider account): it says only which HTTP status the
  provider returned. `saikou harden` and the local app still show the provider's reason, now
  without masked or partial forms of the key (`sk-proj-****abcd`, `sk-...abcd`, "ending in
  abcd", any four characters in a row of the key's secret part, glued to another word or
  not, any case; a placeholder key such as `ollama` is only removed as a whole), and read at
  most 64 KB of it. Its 503 `model_not_configured` no longer quotes the values of the
  server's settings.
- `--provider local` no longer sends the Ollama cloud key: it reads its own, normally unset,
  `OLLAMA_LOCAL_API_KEY`, so `OLLAMA_API_KEY` does not go in plain http to whatever listens
  on the local port. Looking up the installed local models (`/api/tags`) asks only this
  machine, after the URL is checked, without a proxy or a redirect. With `--model` (or the
  app's model field) there is no lookup; without one, a local URL that is not this machine
  is refused with a message to name the model, and the app shows "not on this machine".
- A malformed answer (a broken status line or header, an error body that breaks off, a
  deeply nested or non-text body, an answer over 8 MB) is reported as a provider error instead of escaping as a Python
  exception, whose text could hold the key.

## 1.1.0 - 2026-10-08

First packaged release (`pip install saikou`).

### Added
- `saikou` command line: `verify`, `diff` (git: work tree, `--staged`, or `--head`),
  `harden` (bring-your-own-key, writes only when verification passes), `selftest`.
- Output as text, JSON or SARIF 2.1.0; Markdown job summary (`--summary`).
- Two modes: fix verification (`verify`) and change gating (`diff`), with a
  measured policy for each.
- Analyser-config weakening detection for changed config files (bandit, ruff/flake8
  `S` rules, semgrep/gitleaks/trivy ignore files, ESLint security rules, Sonar, gosec).
- `saikou harden --provider openai|ollama|local`: Ollama cloud (`OLLAMA_API_KEY`, default
  model `gpt-oss:120b`) and local Ollama models without a key; dotenv loading (`.env`,
  `--env-file`); plain-JSON mode with the schema in the prompt where strict schemas are
  unavailable.
- GitHub Action (`action.yml`), pre-commit hook, Claude Code plugin and marketplace.
- `scripts/fp_corpus.py` and published measurements in `docs/measurements/`.

### Changed
- Engine moved into the `saikou` package; `saikou_harden.py` remains as a shim.
- Unparseable Python output is a hard fail in every entry point, not only the API.
- Elision and analyser-config checks are delta-aware (pre-existing text is not flagged);
  elision markers inside string literals are ignored for Python and JS/TS.
- Whole-file checks (unwired guards, shared-sink paths, JS guards) only block what the
  change introduced, unless a fix for that threat class was claimed.
- Language names and file extensions are normalised (`py`, `.ts`, `C#`, ...).
- Free-text threat labels ("command injection", "weak hash") map onto the threat enum,
  and the user's own threat model counts as claimed.
- Ledger claims list only the checks that actually ran for the language.
- API: refuses to serve without tokens unless `ENVIRONMENT=dev`; single-use sessions;
  rate limit; bounded model timeout and output tokens; truncated replies rejected;
  docs endpoints off in production; no httpx dependency.

### Fixed
- False positives measured on real code: `token_type = '...'`, registry paths,
  environment-variable names, dotted identifiers and namespace salts no longer read as
  hardcoded secrets; JS ternaries on a guard are not unused guards.

## 1.0.0 - 2026-09-03

Single-file engine `saikou_harden.py` with the evidence ledger, HTTP service and the
`code-hardener` Claude Code agent.
