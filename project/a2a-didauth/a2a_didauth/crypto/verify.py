import json
from datetime import datetime, timezone

from jwcrypto import jws
from jwcrypto.common import JWException

from a2a_didauth.core.errors import (
    A2ADidAuthError,
    A2ADidAuthCryptoError,
    A2ADidAuthSignatureError
)
from a2a_didauth.dids import DIDResolverDemo, DIDDocUtils


def verify_jws(challenge_jws: str, expected_nonce: str, expected_aud: str = None) -> dict:
    """
    Verify and validate a JSON Web Signature (JWS) for authentication and integrity checks.

    This method performs several operations on the provided challenge JWS:
    1. Parses and deserializes the JWS.
    2. Retrieves and resolves the Decentralized Identifier (DID) from the "kid" field
       in the JWS header.
    3. Validates the "kid" against the DID Document's verification methods,
       authentication field, and key agreement field.
    4. Extracts the public key from the DID Document for signature verification.
    5. Verifies the authenticity of the JWS signature using the extracted public key.
    6. Extracts and parses the JWS payload.
    7. Validates the payload fields, including `iss`, `aud`, `nonce`, `exp`, and `iat`.

    Note that this method raises custom errors for any validation failure during the above checks.

    Args:
        challenge_jws: The JWS string that includes a signed challenge payload.
        expected_nonce: The expected nonce value, for validation against the payload.
        expected_aud: The expected audience field value in the payload.
                      This parameter is optional.

    Returns:
        A dictionary containing the parsed payload from the challenge JWS.

    Raises:
        A2ADidAuthError: If there is an issue during JWS parsing, resolution of the DID,
                         or validation of critical fields in the payload.
        A2ADidAuthCryptoError: If the "kid" in the JWS cannot be verified against the DID Document.
        A2ADidAuthSignatureError: If the JWS signature fails validation.
    """
    # parse JWS
    obj = jws.JWS()
    try:
        obj.deserialize(challenge_jws)
    except Exception as e:
        raise A2ADidAuthError(
            message=f"JWS not valid/parse failed: {e}"
        ) from e

    # retrieve kid and the DID from the header
    try:
        header = dict(obj.jose_header)
        kid = header.get("kid")
        iss_did = str(header.get("kid")).split("#")[0]

        # resolve the DID document
        did_doc = DIDResolverDemo.resolve(did=iss_did)
    except Exception as e:
        raise A2ADidAuthError(
            message=f"Error while resolving DID document: {e}"
        ) from e

    # ! checks on kid
    if not DIDDocUtils.kid_in_verification_method(did_document=did_doc, kid=kid):
        raise A2ADidAuthCryptoError(
            message=f"kid:'{kid}' listed in challenge JWS not found in DID document verification methods"
        )

    if not DIDDocUtils.kid_in_authentication(did_document=did_doc, kid=kid):
        raise A2ADidAuthCryptoError(
            message=f"kid:'{kid}' listed in challenge JWS not found in DID document authentication field"
        )

    if not DIDDocUtils.kid_in_key_agreement(did_document=did_doc, kid=kid):
        raise A2ADidAuthCryptoError(
            message=f"kid: '{kid}' is not referenced in keyAgreement or is missing in verificationMethod"
        )

    # ! retrieve public key
    public_key = DIDDocUtils.extract_public_key_from_did_doc_by_kid(did_document=did_doc, kid=kid)
    if not public_key:
        raise A2ADidAuthCryptoError(
            message=f"kid: '{kid}' does not reference any key in the DID document"
        )

    # verify JWS signature
    try:
        obj.verify(public_key)
    except JWException as e:
        raise A2ADidAuthSignatureError(
            message=f"JWS signature not valid: {e}",
            cause=e,
        ) from e

    # extract the payload
    payload = json.loads(obj.payload.decode("utf-8"))

    # ! check on payload
    if not payload["iss"] == iss_did:
        raise A2ADidAuthError(
            message=f"Mismatch between DID in header and iss in payload"
        )

    if not payload["aud"] == expected_aud:
        raise A2ADidAuthError(
            message=f"Mismatch between DID in header and aud in payload"
        )

    if not payload["nonce"] == expected_nonce:
        raise A2ADidAuthError(
            message=f"Mismatch between the two nonce"
        )

    if payload["exp"] < datetime.now(timezone.utc).timestamp():
        raise A2ADidAuthError(
            message=f"The challenge JWS has expired"
        )

    if payload["iat"] > datetime.now(timezone.utc).timestamp():
        raise A2ADidAuthError(
            message=f"The challenge JWS [iat field] is inconsistent"
        )

    return payload