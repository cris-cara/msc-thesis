from __future__ import annotations

import base64, json
from typing import Dict, List, Optional

from common.waltid_core.client import WaltIdClient
from common.waltid_core.session import WaltIdSession

from didcomm.common.types import DID_URL
from didcomm.secrets.secrets_resolver import SecretsResolver, Secret
from didcomm.secrets.secrets_util import jwk_to_secret

class SecretsResolver4JWK(SecretsResolver):
    """
    Class for resolving and managing secrets based on JSON Web Keys (JWKs) for DIDComm operations.

    This class provides functionality to interact with a wallet instance to retrieve and manage
    JSON Web Keys (JWKs) used for secure messaging in the DIDComm protocol. It supports caching
    of fetched keys for optimization and ensures strict compliance with DIDComm's key resolution
    requirements.

    Attributes:
        waltid (WaltIdClient): The Walt.id client instance for wallet interactions.
        session (WaltIdSession): The active session object associated with the wallet.
        cache_enabled (bool): Determines if caching is enabled for JWK resolution operations.
    """
    def __init__(self, waltid: type[WaltIdClient], session: "WaltIdSession", cache: bool = True):
        self._waltid = waltid
        self._session = session
        self._cache_enabled = cache

        self._base_private_jwk: Optional[dict] = None
        self._secret_cache: Dict[str, Secret] = {}

    @staticmethod
    def _split_fragment(did_url: str) -> tuple[str, Optional[str]]:
        """
        Splits a DID URL into base DID and fragment (if any).
        Example: "did:jwk:....#0" -> ("did:jwk:....", "0")
        """
        if not isinstance(did_url, str):
            return "", None
        if "#" in did_url:
            base, frag = did_url.split("#", 1)
            return base, (frag or None)
        return did_url, None

    @staticmethod
    def _parse_didjwk(did_or_kid: str) -> Optional[dict]:
        """
        Extracts the JWK embedded in 'did:jwk:<b64url>{#fragment}'.

        Note:
        - The fragment (e.g. "#0") is ignored when extracting the embedded JWK,
          because the JWK is encoded in the base DID part.
        """
        if not isinstance(did_or_kid, str) or not did_or_kid.startswith("did:jwk:"):
            return None

        did, _frag = SecretsResolver4JWK._split_fragment(did_or_kid)
        b64 = did[len("did:jwk:") :]
        # base64url padding
        b64 += "=" * (-len(b64) % 4)

        try:
            raw = base64.urlsafe_b64decode(b64.encode("utf-8"))
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    @staticmethod
    def _public_fingerprint(jwk: dict) -> Optional[tuple]:
        """
        Builds a comparable "public fingerprint" from a JWK.
        Only the public parameters are used, depending on kty.
        """
        if not jwk or not isinstance(jwk, dict):
            return None

        kty = jwk.get("kty")
        if kty == "EC":
            return ("EC", jwk.get("crv"), jwk.get("x"), jwk.get("y"))
        if kty == "OKP":
            return ("OKP", jwk.get("crv"), jwk.get("x"))
        if kty == "RSA":
            return ("RSA", jwk.get("n"), jwk.get("e"))

        # Fallback (best effort): include the most common public fields if present
        return (kty, jwk.get("crv"), jwk.get("x"), jwk.get("y"), jwk.get("n"), jwk.get("e"))

    @classmethod
    def _same_public_jwk(cls, a: dict, b: dict) -> bool:
        """
        Compare only the relevant public fields (kty-dependent).
        """
        fa = cls._public_fingerprint(a)
        fb = cls._public_fingerprint(b)
        return fa is not None and fa == fb

    async def _get_base_private_jwk(self) -> dict:
        """
        Retrieves the base private JSON Web Key (JWK).

        This asynchronous method fetches the private JWK from a given key export
        function, optionally using a cache to store the result. If caching is enabled
        and the base private JWK is already available, it is returned immediately. If
        not, the key is exported, validated, and optionally cached for future use.

        Raises:
            ValueError: If the exported JWK does not contain private key material ('d').

        Returns:
            dict: The private JWK in dictionary format.
        """
        if self._cache_enabled and self._base_private_jwk is not None:
            return self._base_private_jwk
        jwk = await self._waltid.export_key_jwk(
            session=self._session,
            key_id=None,        # => wallet "default" key (your convention)
            load_private=True,
        )

        if "d" not in jwk:
            raise ValueError("Exported JWK does not contain private key material ('d').")

        if self._cache_enabled:
            self._base_private_jwk = dict(jwk)

        return jwk

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        """
        Return the Secret matching the exact DID URL requested by DIDComm.
        The Secret id/kid MUST match the requested DID URL (including fragment, e.g. '#0'),
        otherwise DIDComm will treat it as "not found".
        """
        if not isinstance(kid, str) or not kid.startswith("did:jwk:"):
            return None

        if self._cache_enabled and kid in self._secret_cache:
            return self._secret_cache[kid]

        requested_pub = self._parse_didjwk(kid)
        if requested_pub is None:
            return None

        # call to the wallet waltid
        base_private = await self._get_base_private_jwk()

        # Reply only if the requested DID encodes the same public key as our wallet key
        if not self._same_public_jwk(requested_pub, base_private):
            return None

        jwk_for_didcomm = dict(base_private)
        # Critical: DIDComm indexes secrets by the exact DID URL it requests (often includes "#0")
        jwk_for_didcomm["kid"] = kid

        secret = jwk_to_secret(jwk_for_didcomm)

        # Defensive: ensure the produced Secret carries the exact DID URL identifier.
        # (Different didcomm implementations name this field differently.)
        if hasattr(secret, "id"):
            setattr(secret, "id", kid)
        elif hasattr(secret, "kid"):
            setattr(secret, "kid", kid)

        if self._cache_enabled:
            self._secret_cache[kid] = secret

        return secret

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        """
        Return only the DID URLs ('kids') that this resolver can satisfy.

        DIDComm calls this during unpack() to select which recipient keys are available.
        If this returns an empty list, unpack() will fail with DIDUrlNotFoundError.
        """
        if not kids:
            return []

        # call to the wallet waltid
        base_private = await self._get_base_private_jwk()

        out: List[DID_URL] = []

        for kid in kids:
            if not isinstance(kid, str) or not kid.startswith("did:jwk:"):
                continue

            requested_pub = self._parse_didjwk(kid)
            if requested_pub is None:
                continue

            if self._same_public_jwk(requested_pub, base_private):
                out.append(kid)

        return out