from __future__ import annotations

from typing import Any, Dict, Tuple
import base64, json

def _b64url_decode(data: str) -> bytes:
    """Base64url decode with proper padding handling."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _extract_did_and_jwk(input_obj: str) -> Tuple[str, dict[str, Any]] | None:
    """
    Extract (did, jwk) from: a 'did:jwk:...' string
    """
    if not isinstance(input_obj, str):
        return None
    else:
        input_obj = input_obj.strip()
        if not input_obj.startswith("did:jwk:"):
            raise ValueError(f"did must be did:jwk")

        b64 = input_obj[len("did:jwk:"):]
        jwk_json = _b64url_decode(b64).decode("utf-8")
        jwk = json.loads(jwk_json)
        return input_obj, jwk

def resolve_did_jwk(did: str, mode: str = "dict") -> dict[str, Any] | str:
    """
    Return a DID Document in the wallet-style (walt.id) standard format (py dict or json based on mode params):

    {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id": "did:jwk:...",
      "verificationMethod": [
        {
          "id": "did:jwk:...#0",
          "type": "JsonWebKey2020",
          "controller": "did:jwk:...",
          "publicKeyJwk": { ... }
        }
      ],
      "assertionMethod":      ["did:jwk:...#0"],
      "authentication":       ["did:jwk:...#0"],
      "capabilityInvocation": ["did:jwk:...#0"],
      "capabilityDelegation": ["did:jwk:...#0"],
      "keyAgreement":         ["did:jwk:...#0"]
    }
    """
    did, jwk = _extract_did_and_jwk(did)
    vm_id = f"{did}#0"

    doc: Dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": vm_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk,
            }
        ],
        "assertionMethod":      [vm_id],
        "authentication":       [vm_id],
        "capabilityInvocation": [vm_id],
        "capabilityDelegation": [vm_id],
        "keyAgreement":         [vm_id],
    }

    if mode == "json":
        # use dumps if a raw JSON string is needed (e.g., for printing)
        return json.dumps(doc, indent=2)

    # if mode not provided or "dict", stick to python object (e.g., to access fields like id)
    return doc
