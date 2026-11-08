"""Bring-your-own-key hardening: one model call, then mechanical verification.

Standard library only (urllib). Works with any OpenAI-compatible
`/chat/completions` endpoint: OpenAI, OpenRouter, LiteLLM, vLLM, a local
gateway, or Ollama's OpenAI-compatible API.

The model's answer is never trusted: it is checked by `assemble_ledger`, and a
blocked ledger means the hardened code is not handed back as if it were real.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .engine import (
    HARDEN_SCHEMA,
    HARDENER_SYSTEM,
    LANGUAGES,
    Contract,
    EvidenceLedger,
    Tier,
    assemble_ledger,
    build_user_messages,
    normalise_language,
    sha256,
)


class LLMError(RuntimeError):
    """Transport or format failure. Never a verdict about the code.

    `public` is the text safe to show someone who does not own the key (the hosted API):
    it leaves out the provider's own words, which can name parts of the key or the account.
    """

    def __init__(self, message: str, public: Optional[str] = None) -> None:
        super().__init__(message)
        self.public = public or message


# Provider presets. Both speak the OpenAI chat-completions format, so one client serves
# both; only the endpoint, key variable and structured-output support differ.
#
# Ollama cloud (https://docs.ollama.com/cloud): endpoint https://ollama.com/v1, key from
# https://ollama.com/settings/keys sent as `Authorization: Bearer`. Its structured-outputs
# page says cloud does not currently support strict JSON-schema output, so the "ollama"
# preset asks for plain JSON mode, puts the schema in the prompt, and validates locally.
# Default model gpt-oss:120b: an open-weight reasoning model with a 128K context, steady
# JSON discipline and low cost; set OLLAMA_MODEL to try e.g. kimi-k2.7-code or glm-5.3.
# Reasoning tokens count against the output limit, hence the larger default.
PROVIDERS: Dict[str, Dict[str, Any]] = {
    "openai": {"base_url": "https://api.openai.com/v1", "model": "gpt-4o",
               "key_env": "LLM_API_KEY", "url_env": "LLM_BASE_URL", "model_env": "LLM_MODEL",
               "structured": True, "max_output_tokens": 8000},
    "ollama": {"base_url": "https://ollama.com/v1", "model": "gpt-oss:120b",
               "key_env": "OLLAMA_API_KEY", "url_env": "OLLAMA_BASE_URL",
               "model_env": "OLLAMA_MODEL", "structured": False, "max_output_tokens": 16000},
    # A model running on this machine: no key, no data leaves it. Its own key variable
    # (normally unset): the cloud key in OLLAMA_API_KEY must not go to whatever listens on
    # this machine's port. Small models often fail
    # verification on non-trivial files - that is the ledger doing its job, not a bug. For
    # files beyond a few hundred lines raise Ollama's context first, e.g.
    # OLLAMA_CONTEXT_LENGTH=16384, because its default window can silently cut the input.
    "local": {"base_url": "http://localhost:11434/v1", "model": "",
              "key_env": "OLLAMA_LOCAL_API_KEY", "url_env": "OLLAMA_LOCAL_URL",
              "model_env": "OLLAMA_LOCAL_MODEL", "structured": False, "max_output_tokens": 8000,
              "timeout_s": 300, "retries": 0,      # a timeout on a slow local model will repeat
              # Greedy decoding (temperature 0) sends small models into repetition loops that
              # never finish (measured: qwen2.5-coder:3b repeating --exclude flags until the
              # token cap). A mild penalty breaks the loop; a wrong answer is then rejected
              # by verification instead of stalling the run.
              "extra": {"frequency_penalty": 0.3}},
}


def first_local_model(base_url: str) -> str:
    """Name of an installed (non-cloud) model on a local Ollama, to use when none is chosen.

    Asked only of this machine, after the URL is checked, without a proxy or a redirect.
    """
    url, loopback = checked_endpoint(base_url)
    if not loopback:
        raise LLMError("Name the model with --model or OLLAMA_LOCAL_MODEL: Saikou looks up "
                       "installed models only on this machine.")
    root = url.rsplit("/v1", 1)[0]
    try:
        with _DIRECT.open(f"{root}/api/tags", timeout=5) as resp:
            names = [m.get("name", "") for m in json.loads(resp.read(_MAX_BODY).decode("utf-8")).get("models", [])]
    except (urllib.error.URLError, OSError, ValueError, AttributeError, TypeError, RecursionError,
            http.client.HTTPException):
        raise LLMError(f"No Ollama answering at {root}. Start it (ollama serve) or point "
                       f"OLLAMA_LOCAL_URL at it.") from None
    local = [n for n in names if n and "cloud" not in n]
    if not local:
        raise LLMError("Ollama is running but has no local model installed; "
                       "run: ollama pull qwen2.5-coder:3b")
    return local[0]


# What a .env file may set. The default file is ./.env, and the current folder may be a
# repository someone else wrote, so the file only supplies keys, model names and the two
# model limits: never an endpoint, a provider choice, a proxy, a CA bundle, PATH, a git
# setting or anything else that decides where a request goes or what runs. Endpoints come
# from the real environment or --base-url, the provider from the environment or --provider.
_ENV_FILE_NAMES = frozenset(
    [p["key_env"] for p in PROVIDERS.values()] + [p["model_env"] for p in PROVIDERS.values()]
    + ["LLM_TIMEOUT_S", "LLM_MAX_OUTPUT_TOKENS"])
_ENDPOINT_DEFAULTS = {p["url_env"]: p["base_url"] for p in PROVIDERS.values()}

# Endpoint variables the last load_env_file call found in its file with a value other than
# the preset's own, and did not set, with that file's path. A provider whose endpoint was
# only given there refuses to run instead of silently sending its key to the default.
_ENDPOINTS_IN_FILE: Dict[str, str] = {}


def _is_endpoint_name(name: str) -> bool:
    return name.upper() in _ENDPOINT_DEFAULTS     # Windows environment names ignore case


def load_env_file(path: str = ".env", allow: Iterable[str] = ()) -> List[str]:
    """Load KEY=VALUE lines from a dotenv-style file into os.environ.

    Standard library only. Only the provider keys, model names and model limits Saikou
    reads are set, plus the names in `allow` (the variable given with --api-key-env) unless
    such a name is an endpoint variable; every other line is ignored. Values already in the
    environment win, so a real environment variable always overrides the file. Returns the
    NAMES that were set - never the values. A missing file is not an error.
    """
    _ENDPOINTS_IN_FILE.clear()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    names = _ENV_FILE_NAMES | {n for n in allow if not _is_endpoint_name(n)}
    loaded: List[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        name, _, value = line.partition("=")
        name, value = name.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if _is_endpoint_name(name) and value and name.upper() not in os.environ:
            if value.rstrip("/") != _ENDPOINT_DEFAULTS[name.upper()]:
                _ENDPOINTS_IN_FILE[name.upper()] = path
        if name in names and value and name not in os.environ:
            os.environ[name] = value
            loaded.append(name)
    return loaded


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def checked_endpoint(base_url: str) -> Tuple[str, bool]:
    """The URL to send to, rebuilt from its parsed parts, and whether it is this machine.

    https anywhere; plain http only to localhost or a loopback address, compared on the
    parsed host (a prefix test let http://localhost.example.com through). No user name or
    password, backslash, space, control character or percent-encoding in the host, so the
    host that is checked is the host urllib connects to.
    """
    if "\\" in base_url or any(ord(c) <= 32 or ord(c) == 127 for c in base_url):
        raise LLMError("LLM base URL must not contain a backslash, a space or a control character.")
    try:
        parts = urllib.parse.urlsplit(base_url)
        host, port = parts.hostname or "", parts.port
    except ValueError:
        raise LLMError("LLM base URL is not a valid URL.") from None
    if "@" in parts.netloc:
        raise LLMError("LLM base URL must not contain a user name or password.")
    if "%" in host:
        raise LLMError("LLM base URL must not percent-encode its host.")
    if not host or parts.query or parts.fragment:
        raise LLMError("LLM base URL needs a host and no query or fragment, e.g. https://host/v1.")
    loopback = _is_loopback(host)
    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise LLMError("LLM base URL must be https (plain http only for localhost).")
    netloc = (f"[{host}]" if ":" in host else host) + (f":{port}" if port is not None else "")
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", "")), loopback


@dataclass
class LLMConfig:
    base_url: str = "https://api.openai.com/v1"
    model: str = "gpt-4o"
    api_key: str = field(default="", repr=False)
    timeout_s: float = 90.0
    max_output_tokens: int = 8000
    retries: int = 2
    structured: bool = True        # False: plain JSON mode + schema in the prompt
    provider: str = "openai"
    extra: Dict[str, Any] = field(default_factory=dict)   # extra request parameters

    @classmethod
    def from_env(cls, api_key_env: Optional[str] = None, provider: str = "openai",
                 base_url: Optional[str] = None, model: Optional[str] = None) -> "LLMConfig":
        """Settings from the environment; `base_url` (from --base-url) beats the endpoint
        variable and `model` (from --model) the model variable."""
        if provider not in PROVIDERS:
            raise LLMError(f"Unknown provider {provider!r}; choose from {sorted(PROVIDERS)}.")
        preset = PROVIDERS[provider]
        url_env = preset["url_env"]
        if api_key_env and _is_endpoint_name(api_key_env):
            raise LLMError(f"--api-key-env must name the variable that holds your key, not "
                           f"the endpoint variable {api_key_env}.")
        if not base_url and url_env in _ENDPOINTS_IN_FILE and url_env not in os.environ:
            raise LLMError(f"{_ENDPOINTS_IN_FILE[url_env]} sets {url_env}, which Saikou does not "
                           f"read from a .env file because it decides where your key is sent. "
                           f"Set it in your environment (for saikou harden, --base-url works too).")

        def _int(name: str, default: int, minimum: int) -> int:
            raw = os.getenv(name, "")
            try:
                return max(minimum, int(raw)) if raw else default
            except ValueError:
                raise LLMError(f"{name} must be an integer, got {raw!r}")

        base_url = (base_url or os.getenv(url_env, preset["base_url"])).rstrip("/")
        model = model or os.getenv(preset["model_env"], preset["model"])
        if not model and provider == "local":
            model = first_local_model(base_url)
        return cls(
            base_url=base_url,
            model=model,
            api_key=os.getenv(api_key_env or preset["key_env"], ""),
            timeout_s=float(_int("LLM_TIMEOUT_S", preset.get("timeout_s", 90), 5)),
            max_output_tokens=_int("LLM_MAX_OUTPUT_TOKENS", preset["max_output_tokens"], 256),
            structured=bool(preset["structured"]),
            provider=provider,
            retries=int(preset.get("retries", 2)),
            extra=dict(preset.get("extra", {})),
        )

    @property
    def key_hint(self) -> str:
        return PROVIDERS.get(self.provider, PROVIDERS["openai"])["key_env"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect. urllib would follow a 301/302/303 to any host, from https to
    http too, and send the Authorization header along; refused, the 3xx surfaces as an
    HTTPError. (Following never produced an answer anyway: urllib turns the POST into a
    bodiless GET, and refuses 307/308 for a POST.)"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    # Refuse before urllib parses the Location, so a malformed one is still a redirect.
    def http_error_302(self, req, fp, code, msg, headers):
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


# Built once. A remote endpoint goes through the environment's proxy, as with urlopen (an
# https proxy only tunnels). This machine never does: the proxy would get the request, key
# included, in plain http (and a proxy elsewhere could not even reach this machine's server).
_OPENER = urllib.request.build_opener(_NoRedirect())
_DIRECT = urllib.request.build_opener(_NoRedirect(), urllib.request.ProxyHandler({}))
_MAX_BODY = 8_000_000      # a reply within the output-token limit is far smaller


def _post(url: str, payload: dict, api_key: str, timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    })
    opener = _DIRECT if _is_loopback(urllib.parse.urlsplit(url).hostname or "") else _OPENER
    with opener.open(req, timeout=timeout) as resp:  # checked endpoint, redirects refused
        raw = resp.read(_MAX_BODY + 1)
    if len(raw) > _MAX_BODY:
        raise LLMError("Provider answer is larger than 8 MB; nothing was read from it.")
    return json.loads(raw.decode("utf-8"))


# A word in a provider message: a run of characters a key or a masked key is made of.
_WORD = re.compile(r"[\w\-.*+/=•…]+")
_MASK = re.compile(r"\*{3,}|•{3,}|…|\.{3,}")
# Prefixes every key of a provider shares; they say which provider, not which key.
_PUBLIC_PREFIX = re.compile(r"(?:sk-(?:proj-|or-v1-|ant-api\d+-|svcacct-|admin-)?|gsk_)")


def _scrub(text: str, api_key: str) -> str:
    """Remove the key and anything that looks like part of it.

    Providers echo keys in their own formats ("sk-proj-****abcd", "sk-...abcd", "ending in
    abcd"), so besides the exact key this drops every word with a run of mask characters
    and every word that holds four characters in a row of the key's secret part (the key
    without its provider prefix, such as "sk-proj-"), glued to other text or not. Case is
    ignored. A random key rarely shares four characters with an ordinary word; when it
    does, that word is dropped too, which costs a word, not a secret.
    """
    if api_key:
        text = text.replace(api_key, "***")
    key = api_key.lower()
    prefix = _PUBLIC_PREFIX.match(key)
    secret = key[prefix.end():] if prefix else key
    if len(secret) < 16:     # a placeholder such as "ollama" or "EMPTY": only the exact key goes
        secret = ""

    def word(m: "re.Match[str]") -> str:
        w = m.group(0)
        core = w.strip(".,;:…")
        low = core.lower()
        if _MASK.search(core) and len(core) >= 6:
            return "***"
        if secret and any(low[i:i + 4] in secret for i in range(len(low) - 3)):
            return "***"
        return w

    return _WORD.sub(word, text)


def _provider_reason(exc: "urllib.error.HTTPError", api_key: str) -> str:
    """The provider's own explanation of an HTTP error, short and with the key scrubbed."""
    try:
        raw = exc.read(65536).decode("utf-8", "replace")
    except (OSError, ValueError, AttributeError, http.client.HTTPException):
        return "."                       # a body that breaks off (IncompleteRead, LineTooLong)
    try:
        data = json.loads(raw)
        err = data.get("error")
        raw = err.get("message", "") if isinstance(err, dict) else (err or raw)
    except (ValueError, AttributeError, RecursionError):
        pass
    text = _scrub(" ".join(str(raw).split()), api_key)
    return f": {text[:300]}" if text else "."


def call_llm(messages: List[dict], schema: dict, config: LLMConfig) -> Dict[str, Any]:
    """Typed JSON call with bounded time, bounded output and bounded retries.

    A parse failure is reported as a parse failure, never as a verdict about
    the code. A reply cut off at the token limit is reported as truncated
    rather than parsed into a partial (and therefore elided) artifact.
    """
    base_url, local = checked_endpoint(config.base_url)
    secret = config.api_key                                   # what error messages must not show
    api_key = config.api_key or ("ollama" if local else "")   # a local Ollama ignores the key
    if not api_key:
        raise LLMError(f"No API key: set {config.key_hint} in the environment or in a .env "
                       f"file (or name another variable with --api-key-env).")
    config = replace(config, api_key=api_key)
    url = f"{base_url}/chat/completions"
    schema_note = {"role": "system",
                   "content": "Reply with one JSON object that matches this JSON schema "
                              "exactly, and nothing else:\n" + json.dumps(schema)}
    payload: Dict[str, Any] = {
        "model": config.model, "temperature": 0, "max_tokens": config.max_output_tokens,
        **config.extra,
    }
    if config.structured:
        payload["messages"] = messages
        payload["response_format"] = {"type": "json_schema", "json_schema": {
            "name": "hardening_result", "schema": schema, "strict": True}}
    else:
        payload["messages"] = messages + [schema_note]
        payload["response_format"] = {"type": "json_object"}

    body: Optional[dict] = None
    for attempt in range(config.retries + 1):
        try:
            body = _post(url, payload, config.api_key, config.timeout_s)
            break
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                raise LLMError(f"Provider answered HTTP {exc.code}, a redirect. Saikou does not "
                               f"follow redirects, because the request carries your key; set "
                               f"the base URL to the final address.",
                               public=f"Provider answered HTTP {exc.code}, a redirect, which "
                                      f"Saikou does not follow.") from None
            if exc.code == 400 and payload["response_format"]["type"] == "json_schema":
                # Provider lacks structured outputs. JSON mode requires the word
                # "json" to appear in the messages, so say so explicitly.
                payload["response_format"] = {"type": "json_object"}
                payload["messages"] = messages + [schema_note]
                continue
            if exc.code in (429, 500, 502, 503, 504) and attempt < config.retries:
                time.sleep(2 ** attempt)
                continue
            raise LLMError(f"Provider returned HTTP {exc.code}"
                           + _provider_reason(exc, secret),
                           public=f"Provider returned HTTP {exc.code}.") from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            # A malformed status line or header: the type only, its text may hold anything.
            if attempt < config.retries:
                time.sleep(2 ** attempt)
                continue
            raise LLMError(f"Provider transport error: {type(exc).__name__}") from None
        except (ValueError, RecursionError):
            raise LLMError("Provider returned a non-JSON body.") from None
    if body is None:
        raise LLMError("Provider did not answer.")

    try:
        choice = body["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError, TypeError):
        raise LLMError("Provider response had no usable choice.") from None
    if choice.get("finish_reason") == "length":
        raise LLMError("Reply was cut off at the output-token limit; raise "
                       "LLM_MAX_OUTPUT_TOKENS or harden a smaller file. A truncated "
                       "artifact is never treated as a result.")
    if not isinstance(content, str) or not content.strip():
        raise LLMError("Provider returned empty or non-text content.")
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text)
    try:
        result = json.loads(text)
    except (ValueError, RecursionError):
        raise LLMError("Provider did not return valid JSON. This is a transport/format "
                       "failure, not a verdict about the code.") from None
    if not isinstance(result, dict):
        raise LLMError("Provider returned JSON that is not an object.")
    return result


@dataclass
class HardenResult:
    language: str
    tier: Tier
    original: str
    proposed: str
    ledger: EvidenceLedger
    assumptions: List[str]

    @property
    def blocked(self) -> bool:
        return self.ledger.blocked

    def as_dict(self) -> dict:
        return {
            "status": "rejected" if self.blocked else "verified",
            "language": self.language,
            "verification_tier": self.tier.value,
            "input_sha256": sha256(self.original),
            "output_sha256": sha256(self.proposed),
            "hardened_code": None if self.blocked else self.proposed,
            "rejected_output_preview": self.proposed[:2000] if self.blocked else None,
            "evidence_ledger": self.ledger.as_dict(),
            "assumptions": self.assumptions,
            "disclaimer": ("Reports what was checked and how. It does not certify that the "
                           "output is secure. Anything absent from the ledger was not "
                           "tested for."),
        }


def run_hardening(code: str, language: str, contract: Contract, config: LLMConfig,
                  *, run_tools: bool = True) -> HardenResult:
    """Ask the model for a hardened version, then verify it mechanically."""
    lang = normalise_language(language)
    _, tier = LANGUAGES[lang]
    result = call_llm([{"role": "system", "content": HARDENER_SYSTEM}]
                      + build_user_messages(code, contract, lang), HARDEN_SCHEMA, config)

    def _list(key: str) -> list:
        value = result.get(key)
        return value if isinstance(value, list) else []

    proposed = result.get("hardened_code")
    proposed = proposed if isinstance(proposed, str) else ""
    ledger = assemble_ledger(code, proposed, lang, tier, contract,
                             _list("changes"), _list("deferred_defects"), run_tools=run_tools)
    assumptions = [str(a) for a in _list("assumptions")]
    return HardenResult(lang, tier, code, proposed, ledger, assumptions)
