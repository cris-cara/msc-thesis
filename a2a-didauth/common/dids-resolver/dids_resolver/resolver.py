from __future__ import annotations

from .did_web_resolver import resolve_did_web
from .did_jwk_resolver import resolve_did_jwk

def resolve(did: str) -> dict:
    """
    Unified resolver:
    - if DID starts with 'did:web:' -> use did_web_resolver
    - if DID starts with 'did:jwk:' -> use did_jwk_resolver
    """
    if did.startswith("did:web:"):
        return resolve_did_web(did)

    if did.startswith("did:jwk:"):
        return resolve_did_jwk(did)

    # if you want you can support other methods here later
    raise ValueError(f"Unsupported DID method for DID: {did}")
