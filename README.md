# Saikou

**Prove that a security fix is real, not just claimed.**

AI coding agents now open pull requests that "fix" vulnerabilities. Some of those
fixes only *look* fixed - and the usual check cannot tell the difference:

```python
subprocess.call(cmd, shell=True)  # nosec B602
```

`bandit` honours `# nosec`, so the scan after this "fix" comes back clean and a
before/after delta reports an improvement. The vulnerability is untouched.
Saikou is built around one rule:

> **Absence of a finding is never evidence of a fix.**

It compares the code before and after a change and blocks the transformations
that only look hardened. It gives **no score** - every finding says how it was
established (`tool`, `parser`, or `mechanical`), and anything it did not check is
not implied.

```text
$ saikou verify before.py after.py --claimed-threats injection
BLOCKED after.py  [python · ast_verified · verify]
  HARD FAIL [mechanical] suppression_introduced L14: A bandit analyser suppression appears ...
  HARD FAIL [parser] sink_shell_true L14: A fix for 'injection' was claimed but this sink survives unchanged ...
  HARD FAIL [parser] shared_sink_injection_path L11: run_query() forwards its argument into a raw sink ...
```

## What it catches

| Check | Catches | How established |
|---|---|---|
| `suppression_introduced` | New `nosec`, `nosemgrep`, `NOSONAR`, `lgtm`, `noqa: S…`, security `eslint-disable`, … (19 kinds, counted per kind so editing an already-suppressed line is not flagged) | mechanical |
| `analyser_config_weakened` | Suppression moved out of band: new `skips` in `[tool.bandit]`, `S` rules ignored in ruff/flake8, entries in `.semgrepignore`, security ESLint rules switched off, Sonar exclusions | mechanical |
| `guard_computed_but_unused` | `safe = sanitize(p)` (or `os.path.basename(p)`) computed, then `open(p)` used | parser |
| `shared_sink_injection_path` | One caller parameterised, but an interpolated string still reaches the raw sink through a wrapper | parser |
| `sink_*` | `shell=True`, `verify=False`, `debug=True`, interpolated SQL, `eval`/`exec` on non-literals, MD5/SHA1 over passwords, hardcoded key/salt/IV - **new** ones always block; pre-existing ones block only when a fix for that class was claimed | parser |
| `js_async_guard_in_boolean`, `js_floating_guard_promise`, `js_guard_computed_but_unused` | `if (!canAccess(x))` on an async guard (a Promise is always truthy), `assertAllowed(x).catch(log)`, unused sanitised values | mechanical (structural) |
| `elided_output`, `body_gutted` | `// ... existing code ...`, "rest unchanged", function bodies reduced to `...` | mechanical / parser |
| `cosmetic_only_change`, `no_change` | The "fix" only changed comments - the syntax tree is identical | parser |
| `parse_failure` | Output that no longer parses | parser |
| `api_break` (`--strict-api`) | Public symbols removed or signatures changed incompatibly (adding an optional parameter is compatible) | parser |
| `findings_suppressed_not_fixed` (`--analyser`) | bandit run twice, normally and with `--ignore-nosec`; findings hidden only by suppressions are never counted as fixed | tool |

Verification strength depends on the language, and every report says which tier ran:
**`ast_verified`** (Python: parsed, API and sinks computed), **`structural`**
(JavaScript/TypeScript guard checks, textual checks for Go, Java, C#, PHP, Ruby, Rust,
C/C++, Kotlin, Swift, shell, SQL), **`asserted`** (unrecognised: sanity checks only).

## Two modes

| | `saikou verify` - **fix verification** | `saikou diff` - **change gating** |
|---|---|---|
| Question | Is this claimed fix real? | Did this change introduce an evasion? |
| Unchanged / comment-only output | blocks (nothing was fixed) | fine |
| New `# type: ignore`, `@ts-ignore`, pylint/style suppressions | blocks (the red-team rule) | warning |
| New security-analyser suppression | blocks | blocks |
| "same as above", "for brevity" prose | blocks | warning (strong markers like `// ... existing code ...` still block) |
| Defects that were already there | warning, unless a fix for that class was claimed | warning |
| Changed file in a checked language whose new version cannot be checked (NUL byte in the first 8 KB, over 1,000,000 bytes, now a symlink or submodule) | - | blocks (`content_not_checked`; leave a vendored bundle out with a pathspec such as `-- . ':(exclude)vendor/bundle.js'`) |

## Install

```bash
pip install saikou            # engine + CLI, zero dependencies
pip install "saikou[analyser]"  # adds bandit for --analyser
```

Python 3.9+. The engine is standard-library only, so it embeds anywhere:

```python
from saikou import scan_transformation
findings = scan_transformation(before, after, language="python")
blocked = any(f.severity.value == "hard_fail" for f in findings)
```

## Use it

**Verify one claimed fix**

```bash
saikou verify before.py after.py --claimed-threats injection,path_traversal --strict-api
```

**Gate a pull request or local change** (exit 1 on introduced evasions)

```bash
saikou diff --base origin/main
```

**GitHub Action** - findings appear in code scanning and the job summary:

```yaml
name: saikou
on: pull_request
permissions:
  contents: read
  security-events: write   # upload to code scanning
  actions: read            # needed in private repositories only
jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0
      - uses: SuperfastSimon/saikou@v1
        with:
          only-agent-prs: "false"   # "true" = only check PRs opened by bots / AI agents
```

Code scanning takes the upload on every public repository. A private one needs GitHub Code
Security or GitHub Advanced Security, and its workflow needs `actions: read` as well as
`security-events: write`. Without code scanning, set `upload-sarif: "false"`: the job
summary still lists every finding.
A changed file the gate cannot read blocks (`content_not_checked`); leave one that is meant
to be like this (a vendored bundle over 1 MB, say) out with `paths: ". :(exclude)vendor/bundle.js"`.
`warn-only` turns the listed checks into warnings for every file, which also lets an
unreadable file with a real evasion through.

**pre-commit**

```yaml
repos:
  - repo: https://github.com/SuperfastSimon/saikou
    rev: v1.2.0
    hooks:
      - id: saikou
```

**Claude Code plugin** - the `code-hardener` agent interviews you for a threat model,
hardens, verifies its own output with `saikou verify`, and writes only after you
approve the diff:

```text
/plugin marketplace add SuperfastSimon/saikou
/plugin install saikou-harden@saikou
/harden src/upload.py injection,path_traversal
```

**Bring-your-own-key hardening** - your key, your provider (any OpenAI-compatible
endpoint, including a local gateway or Ollama). The result is verified before it can
be written, and never written when verification blocks:

```bash
export LLM_API_KEY=...            # read from the environment, never from argv
saikou harden app.py --threat injection --model gpt-4o            # dry run: ledger + diff
saikou harden app.py --threat injection --model gpt-4o --write    # writes only if verified
```

Keys are read from the environment, or from a git-ignored `.env` file in the current
directory (`--env-file` to point elsewhere; real environment variables win). That file
supplies only provider keys, model names, `LLM_TIMEOUT_S` and `LLM_MAX_OUTPUT_TOKENS` (plus
the variable named with `--api-key-env`), because the current directory may be someone
else's repository: an endpoint (`LLM_BASE_URL`, `OLLAMA_BASE_URL`, `OLLAMA_LOCAL_URL`),
`LLM_PROVIDER`, a proxy or anything else in it is ignored, and a run whose endpoint is set
only there (to anything but the default) stops with a message. Set the endpoint in your
environment or pass `--base-url`, and the provider with `--provider` or the environment.
Plain `http` is accepted only for `localhost` or a loopback address. Three providers are
built in:

| `--provider` | Where the model runs | Key |
|---|---|---|
| `openai` (default) | any OpenAI-compatible endpoint (`--base-url`) | `LLM_API_KEY` |
| `ollama` | [Ollama cloud](https://docs.ollama.com/cloud), default model `gpt-oss:120b` (`OLLAMA_MODEL` to change) | `OLLAMA_API_KEY` from [ollama.com/settings/keys](https://ollama.com/settings/keys) |
| `local` | a model on your own machine through Ollama; nothing leaves it | none (`OLLAMA_LOCAL_API_KEY` only if your local server needs one; `OLLAMA_API_KEY` is never sent to it) |

```bash
saikou harden app.py --provider ollama --threat injection
OLLAMA_LOCAL_MODEL=qwen2.5-coder:3b saikou harden app.py --provider local --threat injection
```

Ollama cloud does not currently offer strict JSON-schema output, so for `ollama` and
`local` Saikou asks for plain JSON, puts the schema in the prompt, and verifies the reply
itself. Small local models often produce a fix that fails verification on anything
non-trivial - then the ledger rejects it, which is the point. For longer files raise
Ollama's context first (`OLLAMA_CONTEXT_LENGTH=16384`), because its default window can
silently cut the input.

`--format json` and `--format sarif` work on `verify` and `diff`; `--summary FILE`
appends a Markdown report (e.g. `$GITHUB_STEP_SUMMARY`). Exit codes: `0` no hard fail,
`1` hard fail, `2` usage or runtime error. The same engine also runs as a
[local app](#local-app-saikou-ui) and as a [hosted API](#hosted-api).

## Local app (`saikou ui`)

```bash
saikou ui                                  # opens the app in your browser
saikou ui --no-browser                     # prints the link instead
saikou ui --repo ../project --port 8765    # Gate screen on another repository
```

The same engine behind a web app, for people who would rather not read terminal output.
It needs no extra package and no build step, and it makes no third-party requests.

- **Local only.** It listens on `127.0.0.1` (a free port unless `--port` is given). The link
  it prints holds a one-time session key in the URL fragment (`#t=...`); every call to the
  app's API must send it, and a request whose `Host` is not this server or whose `Origin` is
  another site is refused. Anyone who has the link can use the app on that machine, so do
  not share it. The browser is started on a private temporary page that redirects to the
  link (removed after a minute or when the app stops), so the key is never on a command
  line that other users of the machine can read.
- **Keys stay in the environment.** Harden reads provider keys from the environment or from
  `.env` (`--env-file`); the app shows only whether a key is set, never its value.

| Screen | Key | What it does |
|---|---|---|
| Verify | `1` | Before and after editors (paste, open or drop a file), claimed threats, strict-API switch. Verdict ("Blocked" or "Nothing blocked", never "safe"), findings with their provenance, an explanation per check, what was not checked; export as JSON, SARIF or Markdown |
| Gate | `2` | A repository and a base ref (or staged changes): one line per changed file, with drill-down |
| Harden | `3` | Provider and model, then the diff and the ledger. **Write** is enabled only for output that passed verification, asks for confirmation, and writes exactly the output you reviewed |
| Checks | `4` | Searchable catalogue of every check, filtered by provenance, severity or language |
| History | `5` | Summaries of earlier runs, kept in this browser only (`localStorage`) |

`Ctrl+Enter` runs the current screen. Light, dark and system themes; English and Dutch.

## Hosted API

```bash
pip install "saikou[api]"
API_TOKENS=choose-a-long-random-token uvicorn saikou.api:app --port 8080
```

| Endpoint | Auth | |
|---|---|---|
| `GET /healthz` | none | liveness |
| `GET /v1/checks` | none | the check catalogue, English and Dutch |
| `POST /v1/verify` | bearer | one before/after pair; `mode` is `verify` (default) or `gate` |
| `POST /v1/verify/batch` | bearer | many `{path, before, after}` pairs in one request; `mode` defaults to `gate` |
| `POST /harden/intake`, `POST /harden/apply` | bearer | the questions worth asking, then one model call whose output is verified; answers 503 unless a model key is set on the server |
| `GET /` | none | playground: the web app with Verify and Checks only (`PLAYGROUND=0` switches it off) |

```bash
curl -s http://127.0.0.1:8080/v1/verify \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"before": "...", "after": "...", "path": "app.py", "claimed_threats": ["injection"]}'
```

Every error is `{"error": {"code": "...", "message": "..."}}` with a matching HTTP status.

- **Fails closed.** Without `API_TOKENS` the API answers 503, unless `ENVIRONMENT=dev` is set
  explicitly. Tokens are comma-separated and sent as `Authorization: Bearer <token>`.
- **`ENVIRONMENT`** is `production` by default, which hides `/docs`, `/redoc` and
  `/openapi.json`; `dev` shows them.
- **No file system, no git.** The hosted service never reads or writes files, never runs git
  and never writes a hardened result anywhere. Those operations exist only in the local app.

Limits, as environment variables with their defaults (see `.env.example`):

| Variable | Default | Limit |
|---|---|---|
| `MAX_INPUT_CHARS` | `60000` | characters per file |
| `MAX_TOTAL_CHARS` | `400000` | characters per batch request |
| `MAX_BODY_BYTES` | `2000000` | bytes per request body |
| `RATE_LIMIT_PER_MINUTE` | `20` | requests per token |

`SESSION_TTL_S` (default `1800`) and `MAX_SESSIONS` (default `500`) bound the single-use
sessions between `/harden/intake` and `/harden/apply`. Each token gets an equal share
(`MAX_SESSIONS` divided by the number of tokens, at least 1): a token that fills its share
replaces its own oldest session, not another token's. Only with more tokens than
`MAX_SESSIONS` can a full store drop another token's session (the oldest of a token that
holds the most).

**Docker**

```bash
docker build -t saikou-api .
docker run -p 8080:8080 -e API_TOKENS=choose-a-long-random-token saikou-api
```

The image runs as a non-root user, listens on port 8080 and has a health check on
`/healthz`. `.dockerignore` keeps `.env`, `internal/` and `.git` out of it.

## Badge

If you run Saikou on fixes, you can say so. The badge says the fixes were *checked*, not
that the code is secure:

```markdown
[![fixes checked with Saikou](https://saikou.tech/assets/fixes-checked-with-saikou.svg)](https://saikou.tech)
```

## Measured on code nobody wrote for it

A check that wrongly blocks real code is also a defect, so every hard-fail rule is
measured on real libraries (`scripts/fp_corpus.py`, results in `docs/measurements/`):

| Corpus | Files | Harmless edit falsely blocked (gating mode) |
|---|---|---|
| CPython 3.11 standard library | 600 | **0.00%** |
| flask, fastapi, starlette, aiohttp, requests, pydantic, httpx, jinja2, werkzeug | 380 | **0.00%** |
| JavaScript (express and its dependencies) | 826 | **0.00%** |
| TypeScript declarations | 1,018 | **0.00%** |

The same files treated as **newly added** code are blocked in 5.5% (stdlib),
2.1% (web libraries), 0.24% (JS) and 0% (TS) of cases - every remaining case is a
real `eval`/`exec`/`shell=True` or a disabled `no-eval` rule, which new code should
have to justify. Each false positive found while measuring is locked in as a
regression test, in the engine self-test (`saikou selftest`: 123 checks, no network,
no key) or in the test suite (`tests/`).

## Suppression coverage

The check for added analyser suppressions (`nosec`, `noqa`, `nosemgrep`, `eslint-disable`,
`@ts-ignore`, ...) is tested against the real tools: generated before/after pairs go to bandit, ruff,
semgrep, ESLint and the TypeScript compiler, and Saikou is held to their answers: it blocks the
security markers they honour, and reports type-checker directives and `usedforsecurity` on
non-password data as warnings. The pairs, the frozen answers of the tools and the verdicts are in
`tests/`; the coverage statement,
with tool versions and what is not covered, is generated from them:
[docs/conformance/suppression-coverage.md](docs/conformance/suppression-coverage.md)
([nl](docs/conformance/suppression-coverage.nl.md)). It states a scope, not a guarantee.

## What it does not do

- **It certifies nothing.** It reports what it checked and how - not that code is secure.
- **It does not execute your code.** Behaviour is checked structurally (AST, API surface)
  for Python, and not at all for other languages.
- **It is not a vulnerability scanner.** It judges *changes*; run your SAST alongside it.
- **Analyser evidence is Python-only** (bandit). Other languages get structural checks,
  and the report says so.
- **One file at a time.** `diff` checks every changed file, but there is no cross-file
  dataflow analysis.

## License

Apache-2.0 for the engine, CLI, Action, pre-commit hook and Claude Code plugin.
Planned paid features (signed evidence export for audits, organisation policies) will
live outside this repository. See [saikou.tech](https://saikou.tech).
