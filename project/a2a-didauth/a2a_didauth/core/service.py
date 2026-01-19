import httpx
import uuid
from common.config import config
from datetime import datetime, timedelta, timezone
import json
from jwcrypto import jwk, jws
from jwcrypto.common import JWException

from typing import Optional
from a2a_didauth.core.models import BeginPayload, ResponsePayload, RejectionPayload
from a2a_didauth.core.session import DIDAuthSession
from a2a_didauth.core.errors import (
    A2ADidAuthError,
    A2ADidAuthPayloadError,
    A2ADidAuthTransportError,
    A2ADidAuthCryptoError,
    A2ADidAuthSignatureError
)

from a2a_didauth.dids import DIDResolverDemo, DIDDocUtils


from a2a_didauth.adapters.a2a import build_json_rpc_message

from pydantic import ValidationError
from a2a.types import (
    Message as A2AMessage,
    Part,
    DataPart,
    TextPart,
    Task,
    TaskStatus,
    TaskStatusUpdateEvent, TaskState, Role,
)

# =================== CONFIG ===================
cfg = config()

EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
# ==============================================

class A2ADidAuthService:
    _client: Optional[httpx.AsyncClient] = None

    @classmethod
    def set_client(cls, client: httpx.AsyncClient):
        cls._client = client

    @classmethod
    async def cleanup(cls):
        """
        Cleans up client resources by closing the connection if active.

        This method checks if the client resource is initialized and whether it is
        active (not closed). If these conditions are met, it asynchronously closes
        the client connection. This ensures proper release of resources and cleanup
        to prevent resource leaks.

        Returns:
            None: This method does not return a value.
        """
        if cls._client and not cls._client.is_closed:
            await cls._client.aclose()

    @classmethod
    async def send_did_auth_reject(cls):
        if cls._client is None:
            raise RuntimeError("Client not initialized")

        # construct and validate the payload
        try:
            didauth_begin_payload = RejectionPayload(
                op="reject",
            )
        except ValidationError as e:
            raise A2ADidAuthPayloadError(
                message=f"DIDAuth reject payload not valid: {e.errors()}",
                cause=e,
            ) from e

        # build the JSON-RPC request
        reject_req = build_json_rpc_message(payload=didauth_begin_payload)

        # send the request
        try:
            resp = await cls._client.post(
                url="/",
                json=reject_req
            )
        except httpx.RequestError as e:
            raise A2ADidAuthTransportError(
                message=f"Transport error while calling Bob: {type(e).__name__}: {e}",
                cause=e,
            ) from e

        return resp.json()

    @classmethod
    async def send_did_auth_request(cls, client_did: str, nonce: str):
        if cls._client is None:
            raise RuntimeError("Client not initialized")

        # construct and validate the payload
        try:
            didauth_begin_payload = BeginPayload(
                op="begin",
                client_did=client_did,
                nonce=nonce
            )
        except ValidationError as e:
            raise A2ADidAuthPayloadError(
                message=f"DIDAuth begin payload not valid: {e.errors()}",
                cause=e,
            ) from e

        # build the JSON-RPC request
        begin_req = build_json_rpc_message(payload=didauth_begin_payload)

        # send the request
        try:
            resp = await cls._client.post(
                url="/",
                json=begin_req
            )
        except httpx.RequestError as e:
            raise A2ADidAuthTransportError(
                message=f"Transport error while calling Bob: {type(e).__name__}: {e}",
                cause=e,
            ) from e

        return resp.json()

    @classmethod
    def build_did_auth_challenge_task(cls, iss_did: str, ext_uri: str, session: DIDAuthSession, signing_key_jwk: dict) -> Task:
        # craft the didauth_challenge
        header = {
            "typ": "JWT",
            "alg": "ES256",
            "kid": f"{iss_did}#0"
        }

        now = datetime.now(timezone.utc)
        payload = {
            "typ": "did_auth_challenge",
            "jti": str(uuid.uuid4()),
            "iss": iss_did,
            "aud": session.client_did,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=120)).timestamp()),
            "nonce": session.nonce
        }

        try:
            # JWS: header.payload.signature
            jws_obj = jws.JWS(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
            key = jwk.JWK.from_json(json.dumps(signing_key_jwk))
            jws_obj.add_signature(key, protected=json.dumps(header))

            jws_challenge = jws_obj.serialize(compact=True)

            task = Task(
                id=session.task_id,
                context_id=session.context_id,
                status=TaskStatus(
                    state=TaskState.input_required,
                    message=A2AMessage(
                        kind="message",
                        message_id=str(uuid.uuid4()),
                        role=Role.agent,
                        parts=[
                            Part(
                                root=DataPart(
                                    data={
                                        ext_uri: {
                                            "challenge_jws": jws_challenge,
                                        }
                                    }
                                )
                            )
                        ],
                    ),
                ),
                metadata={
                    ext_uri: {
                        "op": "challenge",
                    }
                },
            )
        except Exception as e:
            raise A2ADidAuthError(
                message=f"Error while building didauth challenge: {e}",
            ) from e
        return task

    @classmethod
    async def send_did_auth_response(cls, a2a_resp: dict, client_did: str, ext_uri: str, nonce: str, signing_key_jwk: dict):
        if cls._client is None:
            raise RuntimeError("Client not initialized")

        # retrieve taskId and contextId from the response
        task_id = a2a_resp['result']['id']
        context_id = a2a_resp['result']['contextId']

        # retrieve the challenge JWS from the response
        challenge_jws = a2a_resp['result']['status']['message']['parts'][0]['data'][ext_uri]['challenge_jws']

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
            server_did = str(header.get("kid")).split("#")[0]

            # resolve the DID document
            did_doc = DIDResolverDemo.resolve(did=server_did)
        except Exception as e:
            raise A2ADidAuthError(
                message=f"Error while resolving DID document: {e}"
            ) from e

        #! checks on kid
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

        #! retrieve public key
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

        #! check on payload
        if not payload["iss"] == server_did:
            raise A2ADidAuthError(
                message=f"Mismatch between DID in header and iss in payload"
            )

        if not payload["aud"] == client_did:
            raise A2ADidAuthError(
                message=f"Mismatch between DID in header and aud in payload"
            )

        if not payload["nonce"] == nonce:
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

        # - if all checks pass, then build the response to the challenge
        header = {
            "typ": "JWT",
            "alg": "ES256",
            "kid": f"{client_did}#0"
        }

        now = datetime.now(timezone.utc)
        payload = {
            "typ": "did_auth_challenge",
            "jti": str(uuid.uuid4()),
            "iss": client_did, # <-- alice DID
            "aud": server_did, # <-- bob DID
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=120)).timestamp()),
            "nonce": nonce
        }

        print(payload)

        try:
            # JWS: header.payload.signature
            jws_obj = jws.JWS(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
            key = jwk.JWK.from_json(json.dumps(signing_key_jwk))
            jws_obj.add_signature(key, protected=json.dumps(header))

            jws_response = jws_obj.serialize(compact=True)
        except Exception as e:
            raise A2ADidAuthError(
                message=f"Error while crafting JWS challenge response: {e}"
            )

        # construct and validate the payload
        try:
            did_auth_response_payload = ResponsePayload(
                op="response",
                response_jws=jws_response,
            )
        except ValidationError as e:
            raise A2ADidAuthPayloadError(
                message=f"DIDAuth response payload not valid: {e.errors()}",
                cause=e,
            ) from e

        # build the JSON-RPC request
        response_req = build_json_rpc_message(
            payload=did_auth_response_payload,
            task_id=task_id,
            context_id=context_id
        )

        # send the request
        try:
            resp = await cls._client.post(
                url="/",
                json=response_req
            )
        except httpx.RequestError as e:
            raise A2ADidAuthTransportError(
                message=f"Transport error while calling Bob: {type(e).__name__}: {e}",
                cause=e,
            ) from e

        return resp.json()

    @classmethod
    def build_did_auth_verify_task(cls, jws_response: str, ext_uri: str, session: DIDAuthSession, signing_key_jwk: dict) -> Task:
        # TODO: devi fare sempre quello che è stato fatto in send_did_auth_response
        # TODO: valuta già da ora di fare una funzione a parte per non ripetere sempre le stesse cose
        # TODO: valuta anche se spostare direttamente tutto in crypto anche la parte di JWS validation,
        #  oltre ad un sotterfugio per mettere anche il retrieve delle private key (sempre se necessario)



        # craft the didauth_challenge
        header = {
            "typ": "JWT",
            "alg": "ES256",
            "kid": f"{iss_did}#0"
        }

        now = datetime.now(timezone.utc)
        payload = {
            "typ": "did_auth_challenge",
            "jti": str(uuid.uuid4()),
            "iss": iss_did,
            "aud": session.client_did,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=120)).timestamp()),
            "nonce": session.nonce
        }

        try:
            # JWS: header.payload.signature
            jws_obj = jws.JWS(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
            key = jwk.JWK.from_json(json.dumps(signing_key_jwk))
            jws_obj.add_signature(key, protected=json.dumps(header))

            jws_challenge = jws_obj.serialize(compact=True)

            task = Task(
                id=session.task_id,
                context_id=session.context_id,
                status=TaskStatus(
                    state=TaskState.input_required,
                    message=A2AMessage(
                        kind="message",
                        message_id=str(uuid.uuid4()),
                        role=Role.agent,
                        parts=[
                            Part(
                                root=DataPart(
                                    data={
                                        ext_uri: {
                                            "challenge_jws": jws_challenge,
                                        }
                                    }
                                )
                            )
                        ],
                    ),
                ),
                metadata={
                    ext_uri: {
                        "op": "challenge",
                    }
                },
            )
        except Exception as e:
            raise A2ADidAuthError(
                message=f"Error while building didauth challenge: {e}",
            ) from e
        return task