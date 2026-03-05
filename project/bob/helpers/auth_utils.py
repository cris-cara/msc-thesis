import datetime
import json
import os
from typing import Optional

import jwt
from dotenv import load_dotenv
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# =================== CONFIG ===================
load_dotenv("bob/bob.env", override=True)

ALGORITHM = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET")
# ==============================================

class ProtectExtendedCardMiddleware(BaseHTTPMiddleware):
    """
    Protects specific JSON-RPC methods by enforcing Bearer token authentication.

    This middleware intercepts HTTP requests to JSON-RPC endpoints and applies
    access control based on provided configurations. It ensures that only requests
    to protected JSON-RPC methods on given paths require a valid Bearer token.

    Attributes:
        rpc_paths (set[str]): A set of endpoint paths where JSON-RPC methods may be
            protected. Each path is stripped of trailing slashes and normalized.
        protected_methods (set[str]): A set of JSON-RPC method names that are
            subject to access control via Bearer token validation.
    """
    def __init__(self, app, *, rpc_paths: set[str], protected_methods: set[str]):
        super().__init__(app)
        self.rpc_paths = {p.rstrip("/") or "/" for p in rpc_paths}
        self.protected_methods = protected_methods

    @staticmethod
    def _has_valid_bearer(request: Request) -> bool:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False
        token = auth_header.split(" ", 1)[1].strip()
        return bool(verify_token(token))

    @staticmethod
    def _replay_body(request: Request, body: bytes) -> Request:
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}
        return Request(request.scope, receive)

    async def dispatch(self, request: Request, call_next):
        path = (request.url.path.rstrip("/") or "/")

        # protect ONLY JSON-RPC calls on this path
        if path in self.rpc_paths and request.method.upper() == "POST":
            body = await request.body()

            # if not a valid JSON, not a JSON-RPC -> let go
            try:
                payload = json.loads(body.decode("utf-8") if body else "{}")
            except Exception:
                return await call_next(self._replay_body(request, body))

            methods = set()
            if isinstance(payload, dict) and isinstance(payload.get("method"), str):
                methods.add(payload["method"])
            elif isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict) and isinstance(item.get("method"), str):
                        methods.add(item["method"])

            # enforcement ONLY if method is among the ones protected
            if any(m in self.protected_methods for m in methods):
                if not self._has_valid_bearer(request):
                    return JSONResponse(
                        {"error": "Unauthorized", "details": "Missing/invalid Bearer token"},
                        status_code=401,
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            return await call_next(self._replay_body(request, body))

        # all the rest --> free
        return await call_next(request)



# ============================ CREATE AND VERIFY JWT ACCESS TOKEN ============================

def create_access_token(subject: str, expires_minutes: int = 60) -> str:
    """Generates a JWT access token with the specified subject and expiration time."""
    expiration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=expires_minutes)
    payload = {
        "sub": subject,
        "exp": expiration,
        "type": "access_token"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[dict]:
    """Verifies the JWT access token and returns its payload if valid."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def retrieve_sub_from_token(token: str) -> Optional[str]:
    """Extracts the subject (user ID) from a JWT access token."""
    payload = verify_token(token)
    return payload.get("sub") if payload else None