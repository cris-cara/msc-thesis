from .resolver import resolve
from .did_web_resolver import resolve_did_web
from .did_jwk_resolver import resolve_did_jwk

__all__ = ["resolve", "resolve_did_web", "resolve_did_jwk"]
