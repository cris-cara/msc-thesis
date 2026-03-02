import asyncio
import json
import re
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import jwt
import requests
from jwt.algorithms import ECAlgorithm
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import alice.helpers as helpers
from a2a_didauth.adapters.a2a import discover_agent_card, get_did_from_params, get_extension_uri
from a2a_didauth.core.service import A2ADidAuthService
from common import config, rehydrate_after_mcp_tool_call, get_logger
from common.a2a_helpers import build_a2a_send_request_from_didcomm
from common.agents import Agent
from common.waltid_core import WaltIdSession

# =================== CONFIG ===================
cfg = config()

BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
GREEN = cfg["colors"]["GREEN"]
BLUE = cfg["colors"]["BLUE"]
MAGENTA = cfg["colors"]["MAGENTA"]
YELLOW = cfg["colors"]["YELLOW"]
RESET = cfg["colors"]["RESET"]

logger = get_logger(__name__)  # Get a logger instance
# ==============================================

class Alice(Agent):
    def __init__(self):
        super().__init__(env_file_path="alice/alice.env")
        self.mcp_session: ClientSession | None = None

    async def mcp_connect(self, command: str, args: Optional[list[str]] = None) -> None:
        """
        Establishes a connection to an MCP server using provided command and arguments.

        This asynchronous method attempts to create a connection to an MCP server using
        a standard input-output (stdio) communication protocol. It initializes the server
        interaction session, configures the communication protocol, and completes the handshake
        process by invoking the session's initialization method.

        Parameters:
        command: str
            The command to be executed for initiating the MCP server process.

        args: list[str]
            A list of arguments accompanying the command for the MCP server process.

        Returns:
        None
        """
        logger.info(f"[{self.__class__.__name__}] Connecting to MCP server...")

        server_params = StdioServerParameters(
            command=command,
            args=args,
        )

        # start server process (stdio)
        read, write = await self._exit_stack.enter_async_context(
            stdio_client(server_params)
        )

        # set mcp_session
        self.mcp_session = await self._exit_stack.enter_async_context(
            ClientSession(read, write)
        )

        # initialize protocol
        init_result = await self.mcp_session.initialize()
        logger.info(f"{GREEN}[{self.__class__.__name__}] Connected to MCP server: {init_result.serverInfo}{RESET}")

    async def sign_in(self) -> None:
        """
        Logs the user into WaltID via an MCP session and retrieves the default DID.

        Raises
        ------
        RuntimeError
            If the MCP session is not initialized.

        ValueError
            If the DID cannot be retrieved from WaltID.

        Notes
        -----
        This method performs authentication using the `authenticate` tool provided
        by the MCP session. On successful authentication, it updates the
        `waltid_session` attribute with the session data returned from authentication.
        After the session is established, it retrieves and assigns the default DID
        to the `did` attribute by calling the `get_default_did` tool from the MCP session.
        """
        if not self.mcp_session:
            raise RuntimeError("MCP Session not initialized. Call mcp_connect() first.")

        logger.info(f"[{self.__class__.__name__}] Logging in to WaltID via MCP...")
        result = await self.mcp_session.call_tool(
            name="authenticate",
            arguments={"email": self.email, "password": self.password}
        )

        # set the waltid_session attribute
        self.waltid_session = rehydrate_after_mcp_tool_call(
            tool_result=result,
            target_class=WaltIdSession
        )

        # set the default DID
        did_result = await self.mcp_session.call_tool(
            name="get_default_did",
            arguments={"session": asdict(self.waltid_session)}
        )

        if did_result.content and hasattr(did_result.content[0], 'text'):
            self.did = rehydrate_after_mcp_tool_call(tool_result=did_result, target_class=str)
        else:
            raise ValueError("Impossible to retrieve DID from WaltID")

        logger.info(f"{GREEN}[{self.__class__.__name__}] Login successful. DID: {self.did}{RESET}")

    async def submit_verifiable_presentation(self, presentation_request: dict[str, Any]) -> int:
        """
        Submits a verifiable presentation (VP) to a verifier as per the provided presentation request.

        This method handles the entire process of consuming the presentation request, extracting and matching the
        required credentials, crafting the verifiable presentation, signing it, and submitting it to the verifier.

        Attributes not mentioned below are considered implementation details and are not described.

        Parameters:
            presentation_request (dict[str, Any]): A dictionary containing details about the presentation
            request, including `expiry`, `requestId`, and necessary URLs.

        Returns:
            int: The request ID extracted from the original presentation request.

        Raises:
            ValueError: Raised if the presentation request has expired, if the `request_uri` cannot be
            retrieved, or if the VP submission fails with an error response.

        """
        logger.info(f"[{self.__class__.__name__}] Starting VP submission")

        # expiry check
        if int(presentation_request["expiry"]) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Presentation request has expired")

        # extract request_id and request_uri from presentation_request
        request_id = presentation_request["requestId"]
        try:
            req_uri = re.search(r'request_uri=([^ ]+)', presentation_request["url"]).group(1)
        except AttributeError as e:
            raise ValueError("Unable to retrieve request_uri from response") from e
        except (KeyError, TypeError) as e:
            raise ValueError("Invalid presentation_request payload (missing/invalid 'url')") from e

        # consume the request_uri to get the presentation request object
        pres_req_obj_jwt = requests.get(url=req_uri, headers={"Accept": "application/jwt"}).text
        pres_req_obj = jwt.decode(pres_req_obj_jwt, options={"verify_signature": False})

        # extract the credential that matches the presentation definition
        data = pres_req_obj["claims"]["vp_token"]["presentation_definition"]
        presentation_def = {**data, "input_descriptors": [{k: v for k, v in d.items() if k != "schema"} for d in
                                                  data.get("input_descriptors", [])]}
        for item in presentation_def["input_descriptors"][0]["constraints"]["fields"]:
            if item["path"] == ['$.vc.credentialSubject.admin']:
                # substitute 'pattern': '/^true$/gi' with 'pattern': 'true' (respectively with 'false')
                m = re.search(r'^/\^(true|false)\$/gi$', item["filter"]["pattern"], flags=re.I)
                item["filter"]["pattern"] = m.group(1) if m else None

        tool_result = await self.mcp_session.call_tool(
            name="match_creds_for_pres_def",
            arguments={"session": self.waltid_session, "presentation_definition": presentation_def}
        )
        credential = rehydrate_after_mcp_tool_call(tool_result, dict)

        # retrieve useful fields for later
        credential_jwt = credential["document"]
        iss = credential["manifest"]["iss"]

        # retrieve the private key from the wallet associated with the provided session
        tool_result = await self.mcp_session.call_tool(
            name="export_key_jwk",
            arguments={"session": self.waltid_session, "load_private": True}
        )
        secret_key_jwk = rehydrate_after_mcp_tool_call(tool_result, dict)
        secret_key = ECAlgorithm.from_jwk(json.dumps(secret_key_jwk))

        # ===================================================================================================
        # craft and sign vp_token
        iat = pres_req_obj["iat"]
        exp = pres_req_obj["exp"]
        nonce = pres_req_obj["nonce"]
        iss = pres_req_obj["client_id"]

        vp_token = {
            "iss": self.did, # <-- agent's did
            "aud": iss,
            "nonce": nonce,
            "iat": iat,
            "exp": exp,
            "vp": {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                "type": ["VerifiablePresentation"],
                "verifiableCredential": [credential_jwt]
            }
        }

        vp_signed = jwt.encode(
            payload=vp_token,
            key=secret_key,
            algorithm="ES256",
            headers={"kid": self.did + "#0"}
        )

        # ===================================================================================================
        # craft and sign id_token
        definition_id = pres_req_obj["claims"]["vp_token"]["presentation_definition"]["id"]
        descriptor_id = pres_req_obj["claims"]["vp_token"]["presentation_definition"]["input_descriptors"][0]["id"]

        id_token = {
            "iss": "https://self-issued.me/v2/openid-vc",
            "sub": self.did,
            "aud": iss,
            "nonce": nonce,
            "iat": iat,
            "exp": exp,
            "_vp_token": {
                "presentation_submission": {
                    "id": definition_id,
                    "definition_id": definition_id,
                    "descriptor_map": [
                        {
                            "id": descriptor_id,
                            "format": "jwt_vp",
                            "path": "$",
                            "path_nested": {
                                "id": descriptor_id,
                                "format": "jwt_vc",
                                "path": "$.verifiableCredential[0]"
                            }
                        }
                    ]
                }
            }
        }

        id_token_signed = jwt.encode(
            id_token,
            key=secret_key,
            algorithm="ES256",
            headers={
                "kid": self.did + "#0"}
        )

        # ===================================================================================================
        # retrieve state from presentation request
        state = pres_req_obj["state"]

        # ===================================================================================================
        # present the VP to the Verifier MS Entra ID
        redirect_uri = pres_req_obj["redirect_uri"]

        data = {
            "vp_token": vp_signed,
            "id_token": id_token_signed,
            "state": state.strip(),
        }

        resp = requests.post(
            url=redirect_uri,
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"},
            data=data,
            timeout=15,

        )

        if resp.status_code == 200:
            logger.info(f"{GREEN}[{self.__class__.__name__}] VP submission completed. HTTP {resp.status_code}{RESET}")
            return request_id
        else:
            raise ValueError(f"Unable to submit VP: {resp.text}")

async def main(city: str):
    # initialize Alice
    alice = Alice()

    # initialize reusable httpx client
    bob_https = httpx.AsyncClient(
        base_url=BOB_BASE_URL,
        verify="bob/certs/bob-cert.pem",
        timeout=httpx.Timeout(10.0),
    )

    try:
        # connect to the MCP waltid server
        await alice.mcp_connect(
            command="uv",
            args=["run", "python", "-m", "alice.mcp.waltid_server"]
        )
        # authenticate to waltId wallet
        await alice.sign_in()
        # set the resolvers_config for DIDComm library
        alice.set_resolvers_config()

        # discovery Bob AgentCard
        agent_card = await discover_agent_card(url=BOB_BASE_URL)
        ext_uri = get_extension_uri(card=agent_card)
        BOB_DID = get_did_from_params(card=agent_card, ext_uri=ext_uri)

        # update and set the BOB client HTTPS
        bob_https.headers.update(
            {
                "A2A-Extensions": ext_uri,  # activates the extension for this request
                "X-A2A-Extensions": ext_uri,  # ! IMP for backward compatibility
                "A2A-Version": "0.3",  # optional but consistent with the spec examples
            }
        )


        #* ----------------------------------- START A2A-DIDAUTH FLOW -----------------------------------
        logger.info(f"{YELLOW}[{alice.__class__.__name__}] START A2A-didauth flow...{RESET}")

        A2ADidAuthService.set_ext_uri(ext_uri=ext_uri)
        A2ADidAuthService.set_client(client=bob_https)

        #* - A2ADIDAuth: PHASE 1
        try:
            #! IMP. choose a random nonce and memorize it also for later (/getAccessToken)
            nonce = str(uuid.uuid4())

            resp = await A2ADidAuthService.send_did_auth_request(
                client_did=alice.did,
                nonce=nonce
            )

            # retrieve taskId and contextId from the response
            task_id = resp['result']['id']
            context_id = resp['result']['contextId']
        except Exception as e:
            # send reject payload and abort operations
            await A2ADidAuthService.send_did_auth_reject(
                cause=str(e)
            )
            raise SystemExit(f"A2ADIDAuth operations aborted: {e}")

        #* - A2ADIDAuth: PHASE 3 and 4
        try:
            # retrieve the private key from waltid wallet
            result = await alice.mcp_session.call_tool(
                name="export_key_jwk",
                arguments={"session": alice.waltid_session, "load_private": True}
            )
            private_key = rehydrate_after_mcp_tool_call(result, dict)

            resp = await A2ADidAuthService.send_did_auth_response(
                a2a_resp=resp,
                client_did=alice.did,
                nonce=nonce,
                signing_key_jwk=private_key
            )
        except Exception as e:
            # send reject payload and abort operations
            await A2ADidAuthService.send_did_auth_reject(
                task_id=task_id,
                context_id=context_id,
                cause=str(e)
            )
            raise SystemExit(f"A2ADIDAuth operations aborted: {e}")

        logger.info(f"{YELLOW}[{alice.__class__.__name__}] END A2A-didauth flow. Mutual authentication "
                    f"successful!{RESET}")
        #* ----------------------------------- END A2A-DIDAUTH FLOW -----------------------------------

        #* ----------------------------------- START AUTHORIZATION VIA VP -----------------------------------
        # [sample] hardcoded logic
        if not agent_card.skills or agent_card.security_schemes['bearer_auth']:
            logger.info(f"{YELLOW}[{alice.__class__.__name__}] No skills found in AgentCard, I have to present a VP, "
                        f"get the access token and then retrieve the Authenticated Extended Card...{RESET}")

        # ask Bob to send a presentation request
        try:
            resp = await bob_https.post(
                url="/getPresentationRequest",
                json={"did_subject": alice.did},
            )
            resp.raise_for_status()
            pres_req = resp.json()
        except httpx.HTTPStatusError as e:
            raise SystemExit(f"Unable to retrieve a response from /getPresentationRequest: {e}")

        # submit the verifiable presentation to the Verifier MS Entra ID and retrieve the request ID
        request_id = await alice.submit_verifiable_presentation(presentation_request=pres_req)

        # ask Bob to send the access token after the VP submission
        try:
            jwe_request_json = await helpers.build_get_access_token_request(
                sender_did=alice.did,
                body={
                    "did_subject": alice.did,
                    "MS_request_id": request_id,
                    "didauth_task_id": task_id,
                    "didauth_nonce": nonce,
                },
                resolvers_cfg=alice.resolvers_config
            )

            resp = await bob_https.post(
                url="/getAccessToken",
                json=jwe_request_json,
            )
            resp.raise_for_status()
            access_token = resp.json().get("access_token")
            logger.info(f"{GREEN}[{alice.__class__.__name__}] Obtained access token! I can now ask fot the authenticated"
                        f" extended card...{RESET}")
        except httpx.HTTPStatusError as e:
            raise SystemExit(f"Unable to retrieve a response from /getAccessToken: {e}")

        # Now Alice has the access token, therefore, she can ask Bob the authenticated extended card
        # JSON-RPC call to agent/authenticatedExtendedCard
        payload = {"jsonrpc": "2.0", "id": "1", "method": "agent/getAuthenticatedExtendedCard", "params": {}}
        try:
            resp = await bob_https.post(
                url=BOB_BASE_URL,
                headers={"Authorization": f"Bearer {access_token}"},
                json=payload,
            )
            resp.raise_for_status()
            extended_agent_card = resp.json()
            logger.info(f"{GREEN}[{alice.__class__.__name__}] Obtained extended agent card!"
                        f"\n{extended_agent_card}{RESET}")

            # check if skills are present
            skills =  extended_agent_card.get("result", {}).get("skills", None)
            if not isinstance(skills, list) or not skills:
                raise ValueError("No skills found in the authenticated extended card")
        except httpx.HTTPStatusError as e:
            raise SystemExit(f"Unable to retrieve the extended agent card: {e}")

        #* ----------------------------------- END AUTHORIZATION VIA VP -----------------------------------


        #* -------------------------------- START DIDCOMM APPLICATION FLOW  -------------------------------
        # 1) Build DIDComm JWE to send to Bob
        jwe_request_json = await helpers.build_didcomm_weather_request(
            sender_did = alice.did,
            city=city,
            # ! attach the access_token in the DIDComm message body
            access_token=access_token,
            resolvers_cfg=alice.resolvers_config
        )

        # 2) Wrap DIDComm JWE in A2A JSON-RPC request
        """
        Correlation matching is done via `json_rpc_id`:
            - Alice (client): remember which `json_rpc_id` was sent
            - Bob (server): set automatically the `json_rpc_id` (SDK feature)
        """
        json_rpc_id = str(uuid.uuid4())
        jsonrpc_request = build_a2a_send_request_from_didcomm(
            json_rpc_id=json_rpc_id,
            didcomm_jwe_req=jwe_request_json,
        )

        logger.info(f"{BLUE}\n{'=' * 10} Sending A2A message/send request {'=' * 10}"
            f"\n{json.dumps(jsonrpc_request, indent=2)}\n{RESET}"
        )

        # 3) POST to A2A server root via HTTPS
        # NOTE: set a large timeout to give Bob's LLM model time to respond
        try:
            resp = await bob_https.post(
                url=BOB_BASE_URL,
                json=jsonrpc_request,
                timeout=httpx.Timeout(30.0)
            )
            resp.raise_for_status()
            jsonrpc_response = resp.json()
        except httpx.HTTPStatusError as e:
            raise SystemExit(f"Unable to retrieve a response from Bob: {e}")

        logger.info(f"{BLUE}\n{'=' * 10} Received JSON-RPC response from Bob {'=' * 10}"
            f"\n{json.dumps(jsonrpc_response, indent=2)}\n{RESET}"
        )

        # 4) Validate and unpack Bob's DIDComm reply
        jwe_reply_str = helpers.validate_and_get_jwe(
            target_json_rp_id=json_rpc_id,
            jsonrpc_response=jsonrpc_response
        )

        reply_msg = await helpers.unpack_bob_response(
            jwe_reply_str=jwe_reply_str,
            resolvers_cfg=alice.resolvers_config
        )
        body = reply_msg.body or {}

        logger.info(f"{MAGENTA}\n{'=' * 10} Unpacked DIDComm body from Bob {'=' * 10}"
            f"\n{json.dumps(body, ensure_ascii=False)}\n{RESET}"
        )

        #* -------------------------------- END DIDCOMM APPLICATION FLOW  -------------------------------

    except Exception as e:
        raise SystemExit(f"Error: {e}")
    finally:
        # cleanup and safe exit
        await alice.cleanup()
        await bob_https.aclose()
        await asyncio.sleep(1)

if __name__ == "__main__":
    input_city = "Torino"
    asyncio.run(main(city=input_city))
