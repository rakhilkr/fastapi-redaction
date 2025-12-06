# fastapi_redaction/redaction.py
import os
import json
import logging
from typing import Iterable, Optional, Set, Any
from starlette.types import ASGIApp
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, StreamingResponse

REDACTED_TOKEN = "***REDACTED***"

DEFAULT_KEY_KEYWORDS = [
    "key", "secret", "token", "password", "passwd", "credential", "cert", "client_secret", "private_key"
]

# ---------- utility functions ----------
def _collect_auto_env_keys(keywords: Iterable[str]) -> Set[str]:
    keys = set()
    lower_keywords = [k.lower() for k in keywords]
    for k in os.environ.keys():
        if any(kw in k.lower() for kw in lower_keywords):
            keys.add(k)
    return keys

def _gather_secret_values(env_keys: Iterable[str], extra_values: Iterable[str] = ()):
    vals = set()
    for k in env_keys:
        v = os.environ.get(k)
        if v and len(v) >= 4:
            vals.add(v)
    for v in extra_values:
        if v and len(v) >= 4:
            vals.add(str(v))
    return vals

def _redact_in_text(text: str, secrets: Iterable[str]):
    if not text or not secrets:
        return text
    out = text
    for s in secrets:
        if s and s in out:
            out = out.replace(s, REDACTED_TOKEN)
    return out

def _redact_json(obj: Any, sensitive_keys: Iterable[str], secrets_substrings: Iterable[str]):
    if isinstance(obj, dict):
        new = {}
        lower_sensitive = {k.lower() for k in sensitive_keys}
        for k, v in obj.items():
            if k.lower() in lower_sensitive:
                new[k] = REDACTED_TOKEN
            else:
                new[k] = _redact_json(v, sensitive_keys, secrets_substrings)
        return new
    elif isinstance(obj, list):
        return [_redact_json(x, sensitive_keys, secrets_substrings) for x in obj]
    elif isinstance(obj, str):
        return _redact_in_text(obj, secrets_substrings)
    else:
        return obj

# ---------- logging filter ----------
class RedactingFilter(logging.Filter):
    def __init__(self, secrets: Iterable[str]):
        super().__init__()
        self.secrets = list(secrets)

    def update_secrets(self, secrets: Iterable[str]):
        self.secrets = list(secrets)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
            masked = _redact_in_text(str(msg), self.secrets)
            record.msg = masked
            record.args = ()
        except Exception:
            pass
        return True

# ---------- ASGI Middleware ----------
class RedactMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        *,
        sensitive_header_names: Iterable[str] = ("authorization", "cookie", "set-cookie"),
        sensitive_json_keys: Iterable[str] = ("password", "token", "secret", "api_key"),
        secrets_substrings: Iterable[str] = (),
    ):
        super().__init__(app)
        self.sensitive_headers = {h.lower() for h in sensitive_header_names}
        self.sensitive_json_keys = set(sensitive_json_keys)
        self.secrets_substrings = list(secrets_substrings)

    async def dispatch(self, request: Request, call_next):
        # Redact request headers
        safe_headers = {
            name: (REDACTED_TOKEN if name.lower() in self.sensitive_headers
                else _redact_in_text(value, self.secrets_substrings))
            for name, value in request.headers.items()
        }
        request.state.redacted_headers = safe_headers

        # Get the original response
        response = await call_next(request)

        # Redact response headers
        for h in list(response.headers.keys()):
            if h.lower() in self.sensitive_headers:
                response.headers[h] = REDACTED_TOKEN
            else:
                response.headers[h] = _redact_in_text(response.headers[h], self.secrets_substrings)

        # Only handle JSON responses for body redaction
        content_type = response.headers.get("content-type", "")
        if response.status_code != 204 and "application/json" in content_type.lower():
            try:
                # Collect original body
                body_bytes = b""
                async for chunk in response.body_iterator:
                    body_bytes += chunk

                # If empty, just return original response
                if not body_bytes:
                    return response

                payload = json.loads(body_bytes)
                masked_payload = _redact_json(payload, self.sensitive_json_keys, self.secrets_substrings)
                masked_bytes = json.dumps(masked_payload).encode("utf-8")

                # Create new headers without Content-Length
                headers = dict(response.headers)
                headers.pop("content-length", None)

                # Return a new StreamingResponse with masked body
                return StreamingResponse(
                    content=iter([masked_bytes]),  # simple iterator yields entire masked body
                    status_code=response.status_code,
                    headers=headers,
                    media_type="application/json"
                )

            except Exception:
                # If any error occurs, fallback to original response
                return response

        # Non-JSON responses are returned as-is
        return response


# ---------- configuration dataclass ----------
class RedactionConfig:
    def __init__(
        self,
        *,
        explicit_env_keys: Optional[Iterable[str]] = None,
        extra_secret_values: Optional[Iterable[str]] = None,
        key_name_keywords: Optional[Iterable[str]] = None,
        sensitive_json_keys: Optional[Iterable[str]] = None,
        sensitive_header_names: Optional[Iterable[str]] = None,
    ):
        self.explicit_env_keys = set(explicit_env_keys or [])
        self.extra_secret_values = list(extra_secret_values or [])
        self.key_name_keywords = list(key_name_keywords or DEFAULT_KEY_KEYWORDS)
        self.sensitive_json_keys = list(sensitive_json_keys or ("password", "token", "secret", "api_key"))
        self.sensitive_header_names = list(sensitive_header_names or ("authorization", "cookie", "set-cookie"))

# ---------- Redaction extension ----------
class Redaction:
    def __init__(self, config: Optional[RedactionConfig] = None):
        self.config = config or RedactionConfig()
        self._secrets_substrings: Set[str] = set()
        self._env_keys_tracked: Set[str] = set()
        self._log_filter: Optional[RedactingFilter] = None
        self._middleware: Optional[RedactMiddleware] = None
        self._installed = False
        self._collect_secrets_initial()

    def attach_filter(self, logger=None):
        if self._log_filter is None:
            self._log_filter = RedactingFilter(self._secrets_substrings)
        if logger is None:
            logger = logging.getLogger()
        logger.addFilter(self._log_filter)

    def _collect_secrets_initial(self):
        auto = _collect_auto_env_keys(self.config.key_name_keywords)
        keys = set(auto) | set(self.config.explicit_env_keys)
        self._env_keys_tracked = keys
        vals = _gather_secret_values(keys, extra_values=self.config.extra_secret_values)
        self._secrets_substrings = set(vals)

    def update_secrets(self, extra_values: Optional[Iterable[str]] = None, refresh_env_keys: bool = False):
        if refresh_env_keys:
            auto = _collect_auto_env_keys(self.config.key_name_keywords)
            self._env_keys_tracked = set(auto) | set(self.config.explicit_env_keys)
        extra_values = extra_values or []
        vals = _gather_secret_values(self._env_keys_tracked, extra_values=extra_values)
        self._secrets_substrings = set(vals)
        if self._log_filter:
            self._log_filter.update_secrets(self._secrets_substrings)
        if self._middleware:
            self._middleware.secrets_substrings = list(self._secrets_substrings)

    def init_app(self, app, attach_to_root_logger: bool = True):
        if self._installed:
            return
        self._log_filter = RedactingFilter(self._secrets_substrings)
        if attach_to_root_logger:
            logging.getLogger().addFilter(self._log_filter)
        else:
            app.logger.addFilter(self._log_filter)

        self._middleware = RedactMiddleware(
            app,
            sensitive_header_names=self.config.sensitive_header_names,
            sensitive_json_keys=self.config.sensitive_json_keys,
            secrets_substrings=self._secrets_substrings,
        )
        app.add_middleware(type(self._middleware), **{
            "sensitive_header_names": self.config.sensitive_header_names,
            "sensitive_json_keys": self.config.sensitive_json_keys,
            "secrets_substrings": self._secrets_substrings,
        })
        self._installed = True

    # ---------- helper methods ----------
    def redact_text(self, text: str) -> str:
        """Redact a plain string."""
        return _redact_in_text(text, self._secrets_substrings)

    # Alias to match old testing code
    redact = redact_text
