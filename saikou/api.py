"""Optional hosted HTTP service (`pip install saikou[api]`).

    uvicorn saikou.api:app --port 8080

    GET  /healthz            liveness (no auth)
    GET  /v1/checks          the check catalogue, English and Dutch (no auth)
    POST /v1/verify          one before/after pair
    POST /v1/verify/batch    many file pairs in one request (CI without installing anything)
    POST /harden/intake      contract + the questions worth asking
    POST /harden/apply       verified hardening + an evidence ledger (one model call)
    GET  /                   playground: the Saikou web app in hosted mode (Verify, Checks)

Every error is {"error": {"code": ..., "message": ...}} with a matching HTTP status.

Fails closed: without API_TOKENS it refuses to serve unless ENVIRONMENT=dev is set
explicitly. Requests are rate limited per token and bodies are capped (MAX_BODY_BYTES).
Hosted means hosted: this module never reads or writes the file system, never runs git
and never writes a hardened result anywhere. Those operations exist only in the local
app (saikou.server), which listens on 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException

from . import service, webassets
from .engine import (
    THREAT_CHOICES,
    TIER_MEANING,
    Contract,
    Session,
    SessionStore,
    __version__,
    build_questions,
    detect_language,
    normalise_language,
    normalise_threats,
    python_surface,
    sha256,
    utc_now,
)
from .llm import LLMConfig, LLMError, run_hardening
from .service import ServiceError


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except ValueError:
        return default


ENVIRONMENT = os.getenv("ENVIRONMENT", "production")
MAX_INPUT_CHARS = _int_env("MAX_INPUT_CHARS", 60000, 1000)
# The batch limit is 400k characters; JSON escaping and UTF-8 can double that.
MAX_BODY_BYTES = _int_env("MAX_BODY_BYTES", 2_000_000, 10_000)
API_TOKENS = frozenset(t.strip() for t in os.getenv("API_TOKENS", "").split(",") if t.strip())
RATE_LIMIT_PER_MINUTE = _int_env("RATE_LIMIT_PER_MINUTE", 20)
PLAYGROUND = os.getenv("PLAYGROUND", "1") != "0"

_sessions = SessionStore(_int_env("SESSION_TTL_S", 1800), _int_env("MAX_SESSIONS", 500))
_hits: Dict[str, Deque[float]] = defaultdict(deque)

_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
          405: "method_not_allowed", 413: "body_too_large", 415: "unsupported_media_type",
          422: "bad_request", 429: "rate_limited", 500: "internal_error",
          502: "model_error", 503: "unavailable"}


class IntakeBody(BaseModel):
    code: str = Field(..., min_length=1, max_length=MAX_INPUT_CHARS)
    language: Optional[str] = Field(None, max_length=40)
    notes: Optional[str] = Field(None, max_length=4000)


class ContractBody(BaseModel):
    language: Optional[str] = Field(None, max_length=40)
    target_runtime: str = Field("", max_length=80)
    threat_model: List[str] = Field(default_factory=list, max_length=len(THREAT_CHOICES))
    compat: str = Field("strict_api", pattern="^(strict_api|allow_signature_changes|rewrite_freely)$")
    dependencies: str = Field("stdlib_only", pattern="^(stdlib_only|existing_only|may_add)$")
    error_policy: str = Field("fail_closed", pattern="^(fail_closed|preserve_current)$")
    output_style: str = Field("full_module", pattern="^(full_module|changed_parts)$")
    must_preserve: List[str] = Field(default_factory=list, max_length=200)
    notes: str = Field("", max_length=4000)


class ApplyBody(BaseModel):
    session_id: str = Field(..., min_length=8, max_length=200)
    contract: ContractBody = Field(default_factory=ContractBody)


# ---------------------------------------------------------------------------------------
# auth, rate limit, body cap
# ---------------------------------------------------------------------------------------

def require_auth(authorization: str = Header(default="")) -> str:
    if not API_TOKENS:
        if ENVIRONMENT != "dev":
            raise ServiceError(503, "not_configured", "API_TOKENS is unset, so this instance "
                               "refuses to serve (set ENVIRONMENT=dev to run an open local "
                               "instance).")
        return "dev"
    token = authorization[7:] if authorization.startswith("Bearer ") else ""
    for t in API_TOKENS:
        if secrets.compare_digest(token, t):
            return sha256(t)[:16]
    raise ServiceError(401, "unauthorized", "Invalid or missing bearer token.",
                       headers={"WWW-Authenticate": "Bearer"})


def rate_limit(caller: str = Depends(require_auth)) -> str:
    now = time.monotonic()
    window = _hits[caller]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        wait = max(1, int(60 - (now - window[0])) + 1)
        raise ServiceError(429, "rate_limited", f"Rate limit of {RATE_LIMIT_PER_MINUTE} requests "
                           f"per minute exceeded; retry in {wait} s.",
                           headers={"Retry-After": str(wait)})
    window.append(now)
    return caller


def _too_large() -> HTTPException:
    return HTTPException(413, f"Request body exceeds {MAX_BODY_BYTES} bytes.")


class BodyLimit:
    """Reject bodies over MAX_BODY_BYTES: by Content-Length up front, and by counting the
    stream for chunked uploads that declare no length."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                over = int(declared) > MAX_BODY_BYTES
            except ValueError:
                over = True
            if over:
                await _error(413, "body_too_large", _too_large().detail)(scope, receive, send)
                return
        seen = 0

        async def capped() -> dict:
            nonlocal seen
            message = await receive()
            if message.get("type") == "http.request":
                seen += len(message.get("body", b""))
                if seen > MAX_BODY_BYTES:
                    # An HTTPException survives FastAPI's body parsing unchanged.
                    raise _too_large()
            return message

        await self.app(scope, capped, send)


async def _json(request: Request) -> Any:
    raw = await request.body()
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ServiceError(400, "bad_json", "Request body is not valid UTF-8 JSON.") from None


# ---------------------------------------------------------------------------------------
# app
# ---------------------------------------------------------------------------------------

_production = ENVIRONMENT == "production"
app = FastAPI(title="Saikou", version=__version__,
              docs_url=None if _production else "/docs",
              redoc_url=None if _production else "/redoc",
              openapi_url=None if _production else "/openapi.json")
app.add_middleware(BodyLimit)


def _error(status: int, code: str, message: str,
           headers: Optional[Dict[str, str]] = None) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message}}, status_code=status,
                        headers=headers)


@app.exception_handler(ServiceError)
async def _service_error(_request: Request, exc: ServiceError) -> JSONResponse:
    return _error(exc.status, exc.code, exc.message, exc.headers)


@app.exception_handler(HTTPException)
async def _http_error(_request: Request, exc: HTTPException) -> JSONResponse:
    return _error(exc.status_code, _CODES.get(exc.status_code, "error"), str(exc.detail),
                  getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    first = (exc.errors() or [{}])[0]
    where = ".".join(str(p) for p in first.get("loc", ()) if p != "body")
    message = first.get("msg", "Invalid request.")
    return _error(422, "bad_request", f"{where}: {message}" if where else message)


@app.middleware("http")
async def _headers(request: Request, call_next: Any) -> Response:
    request_id = secrets.token_hex(12)
    response = await call_next(request)
    response.headers.update({"X-Request-ID": request_id,
                             "X-Content-Type-Options": "nosniff",
                             "X-Frame-Options": "DENY",
                             "Referrer-Policy": "no-referrer"})
    response.headers.setdefault("Cache-Control", "no-store")
    return response


async def _run(fn: Any, *args: Any) -> Any:
    # The engine is synchronous and CPU-bound; keep it off the event loop.
    return await asyncio.to_thread(fn, *args)


@app.get("/healthz")
async def healthz() -> dict:
    return service.health()


@app.get("/v1/checks")
async def checks() -> dict:
    return service.checks()


@app.post("/v1/verify")
async def verify(request: Request, caller: str = Depends(rate_limit)) -> dict:
    return await _run(service.verify, await _json(request))


@app.post("/v1/verify/batch")
async def verify_batch(request: Request, caller: str = Depends(rate_limit)) -> dict:
    return await _run(service.verify_batch, await _json(request))


@app.post("/harden/intake")
async def intake(body: IntakeBody, caller: str = Depends(rate_limit)) -> dict:
    detection = detect_language(body.code, body.language)
    surface = python_surface(body.code) if detection.language == "python" else None
    session_id = await _sessions.put(Session(body.code, detection, time.time()))
    return {
        "session_id": session_id, "issued_at": utc_now(),
        "detected": {"language": detection.language, "display": detection.display,
                     "source": detection.source, "confident": detection.confident,
                     "verification_tier": detection.tier.value,
                     "tier_means": TIER_MEANING[detection.tier]},
        "input_sha256": sha256(body.code),
        "public_symbols": sorted(surface) if surface else [],
        "proposed_contract": Contract(notes=body.notes or "").as_dict(),
        "questions": build_questions(detection, surface),
        "next": "Answer the questions, then POST the contract to /harden/apply (single use).",
    }


@app.post("/harden/apply")
async def apply(body: ApplyBody, caller: str = Depends(rate_limit)) -> dict:
    try:
        config = LLMConfig.from_env()
    except LLMError:
        # The message can quote this server's settings; the caller gets none of them.
        raise ServiceError(503, "model_not_configured", "The model is not configured correctly "
                           "on this server, so hardening is unavailable here.") from None
    if not config.api_key:
        # Checked before the session is consumed, so the caller can retry later.
        raise ServiceError(503, "model_not_configured", f"{config.key_hint} is not set on this "
                           "server, so hardening is unavailable here.")
    session = await _sessions.take(body.session_id)
    if session is None:
        raise ServiceError(404, "session_not_found", "Unknown, expired or already-used "
                           "session. Start at /harden/intake.")
    c = body.contract
    language = normalise_language(c.language or session.detection.language)
    contract = Contract(target_runtime=c.target_runtime,
                        threat_model=normalise_threats(c.threat_model),
                        compat=c.compat, dependencies=c.dependencies,
                        error_policy=c.error_policy, output_style=c.output_style,
                        must_preserve=c.must_preserve, notes=c.notes)
    started = time.time()
    try:
        # The model call and bandit are blocking; keep them off the event loop.
        result = await asyncio.to_thread(run_hardening, session.code, language, contract, config)
    except LLMError as exc:
        # The caller does not own this server's key: never pass on the provider's own words.
        raise ServiceError(502, "model_error", exc.public) from None
    out = result.as_dict()
    out.update({"issued_at": utc_now(), "tier_means": TIER_MEANING[result.tier],
                "contract": contract.as_dict(),
                "processing_ms": int((time.time() - started) * 1000)})
    return out


# ---- playground ----------------------------------------------------------------------------

if PLAYGROUND:
    @app.get("/", include_in_schema=False)
    async def playground() -> Response:
        return Response(webassets.page("hosted"), media_type="text/html; charset=utf-8",
                        headers={"Content-Security-Policy": webassets.CSP})

    @app.get("/assets/{name}", include_in_schema=False)
    async def playground_asset(name: str) -> Response:
        found = webassets.asset(name)
        if found is None:
            raise HTTPException(404, "Not found.")
        content, ctype = found
        return Response(content, media_type=ctype, headers={"Cache-Control": "max-age=300"})
