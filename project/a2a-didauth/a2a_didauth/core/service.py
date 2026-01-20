import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from a2a.types import (
    Message as A2AMessage,
    Part,
    DataPart,
    Task,
    TaskStatus,
    TaskState, Role,
)
from jwcrypto import jwk, jws
from pydantic import ValidationError

from a2a_didauth.adapters.a2a import build_json_rpc_message
from a2a_didauth.adapters.a2a.jsonrpc_builders import build_json_rpc_task
from a2a_didauth.core.errors import (
    A2ADidAuthError,
    A2ADidAuthPayloadError,
    A2ADidAuthTransportError
)
from a2a_didauth.core.models import BeginPayload, ResponsePayload, RejectionPayload
from a2a_didauth.core.session import DIDAuthSession, NonceDIDAuthStatus, \
    DIDAuthSessionResolver
from a2a_didauth.crypto import verify_jws


class A2ADidAuthService:
    _client: Optional[httpx.AsyncClient] = None
    _ext_uri: str

    @classmethod
    def set_ext_uri(cls, ext_uri: str):
        cls._ext_uri = ext_uri

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
    async def send_did_auth_reject(
            cls,
            *,
            task_id: Optional[str] = None,
            context_id: Optional[str] = None,
            cause: Optional[str] = None
    ):
        """
        Asynchronously sends a DID authentication rejection message.

        This method constructs a rejection payload, validates it, builds a JSON-RPC
        request, and sends it to the designated endpoint. If the client is not
        initialized or if there are issues during the payload construction or
        message transmission, the appropriate errors are raised.

        Args:
            task_id (Optional[str]): An optional identifier for the task the rejection
                is related to.
            context_id (Optional[str]): An optional identifier for the context in which
                the rejection is being issued.
            cause (Optional[str]): An optional string describing the cause or reason
                for the rejection.

        Raises:
            RuntimeError: If the client is not initialized before calling this method.
            A2ADidAuthPayloadError: If the DID authentication rejection payload cannot
                be constructed or validated.
            A2ADidAuthTransportError: If there is a transport error while sending the
                rejection message.

        Returns:
            dict: The server's response, parsed as a JSON object.
        """
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
        reject_req = build_json_rpc_message(
            ext_uri=cls._ext_uri,
            payload=didauth_begin_payload,
            task_id=task_id,
            context_id=context_id,
            cause=cause
        )

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
        """
            Sends a DIDAuth request to a specified URI using the provided client DID and nonce.

            This method is responsible for constructing a valid JSON-RPC request with
            the provided parameters, validating the payload, and sending it to the
            external URI. It ensures communication compliance with Bob's request
            handling for DID authentication.

            Parameters:
            client_did: str
                The DID of the client initiating the request.
            nonce: str
                A unique nonce value used for the request to ensure integrity.

            Returns:
            dict
                The JSON response received from the external URI.

            Raises:
            RuntimeError
                If the client is not already initialized.
            A2ADidAuthPayloadError
                If the payload validation fails during request construction.
            A2ADidAuthTransportError
                If a transport error occurs while attempting to send the request.
        """
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
        begin_req = build_json_rpc_message(
            ext_uri=cls._ext_uri,
            payload=didauth_begin_payload,
        )

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
    def build_did_auth_challenge_task(cls, iss_did: str, session: DIDAuthSession, signing_key_jwk: dict) -> Task:
        """
        Builds and returns a DID authentication challenge task.

        This method creates a task containing a challenge for DID authentication.
        It generates a JSON Web Token (JWT) using the provided signing key, which includes
        the challenge details. The challenge is then serialized into a valid and compact
        JWT format. The challenge is embedded into a task structure that contains
        additional metadata and context information.

        Parameters:
            iss_did (str): The DID of the issuer.
            session (DIDAuthSession): The session containing authentication information.
            signing_key_jwk (dict): The signing key in JWK format.

        Returns:
            Task: An instance of the Task object containing the DID authentication
            challenge details.
        """
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
                                        cls._ext_uri: {
                                            "challenge_jws": jws_challenge,
                                        }
                                    }
                                )
                            )
                        ],
                    ),
                ),
                metadata={
                    cls._ext_uri: {
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
    async def send_did_auth_response(cls, a2a_resp: dict, client_did: str, nonce: str, signing_key_jwk: dict):
        """
        Provides functionality to send a DID authentication response securely via JSON-RPC.

        The method verifies the challenge JWS (JSON Web Signature) and prepares a response by
        building a new JWS that includes the necessary credentials and cryptographic elements.
        It sends the authentication response to a recipient using an HTTP client.

        Attributes:
            cls._client: The HTTP client instance used to send the request.

        Raises:
            RuntimeError: If the HTTP client is not initialized.
            A2ADidAuthError: If an error occurs during JWS verification or crafting the JWS challenge response.
            A2ADidAuthPayloadError: If the constructed payload for the authentication response is invalid.
            A2ADidAuthTransportError: If a transport-related error occurs during the request.

        Parameters:
            a2a_resp (dict): The response object containing details required to process the DID authentication.
            client_did (str): The decentralized identifier (DID) of the client initiating the authentication response.
            nonce (str): A unique value used for verifying the challenge JWS and preventing replay attacks.
            signing_key_jwk (dict): The signing key in JWK (JSON Web Key) format used to create the JWS for the response.

        Returns:
            dict: The JSON response from the recipient after sending the authentication response.
        """
        if cls._client is None:
            raise RuntimeError("Client not initialized")

        # retrieve taskId and contextId from the response
        task_id = a2a_resp['result']['id']
        context_id = a2a_resp['result']['contextId']

        # retrieve the challenge JWS from the response
        challenge_jws = a2a_resp['result']['status']['message']['parts'][0]['data'][cls._ext_uri]['challenge_jws']

        try:
            challenge_payload = verify_jws(challenge_jws=challenge_jws, expected_nonce=nonce, expected_aud=client_did)
        except A2ADidAuthError as e:
            raise A2ADidAuthError(
                message=f"Error while verifying challenge JWS: {e}"
            ) from e

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
            "aud": challenge_payload["iss"], # <-- bob DID
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=120)).timestamp()),
            "nonce": nonce
        }

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
            ext_uri=cls._ext_uri,
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
    def build_did_auth_verify_task(
            cls,
            jws_response: str,
            session: DIDAuthSession,
            session_resolver: DIDAuthSessionResolver,
            server_did: str,
        ) -> Task:
        """
        Builds a DID authentication verification task using the provided JWS response, session,
        session resolver, and server DID. Validates the JWS response, ensures that the nonce
        status in the session is pending, and constructs a JSON-RPC task upon successful verification.

        Parameters:
            jws_response (str): The JWS response to be verified.
            session (DIDAuthSession): The current DID authentication session containing necessary
                data for validation.
            session_resolver (DIDAuthSessionResolver): Responsible for resolving session-related
                states, such as nonce status.
            server_did (str): Represents the decentralized identifier (DID) of the server, used
                for audience validation.

        Returns:
            Task: A JSON-RPC task object representing the completion of the DID authentication
            verification process.

        Raises:
            RuntimeError: Raised if any validation check fails, including JWS verification or if
                the nonce status is not pending.
            A2ADidAuthError: Raised if an error occurs during the construction of the JSON-RPC task.
        """
        try:
            _ = verify_jws(
                challenge_jws=jws_response,
                expected_nonce=session.nonce,
                expected_aud=server_did)
        except A2ADidAuthError as e:
            raise RuntimeError(f"Error while verifying challenge JWS: {e}") from e

        #! check if the nonce status is pending
        nonce_status = session_resolver.get(task_id=session.task_id).nonce_status
        if not nonce_status == NonceDIDAuthStatus.PENDING:
            raise RuntimeError(f"Nonce status is not pending: {nonce_status}")

        # - if all checks pass, then build the Task.status = completed
        try:
            task = build_json_rpc_task(
                ext_uri=cls._ext_uri,
                op="complete",
                session=session
            )
        except Exception as e:
            raise A2ADidAuthError(
                message=f"Error while building didauth complete: {e}",
            ) from e

        return task