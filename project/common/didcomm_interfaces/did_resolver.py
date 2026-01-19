import json
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.did_doc.did_doc import DIDDoc, VerificationMethod
from didcomm.common.types import DID, VerificationMethodType, VerificationMaterial, VerificationMaterialFormat
from dids_resolver import resolve as custom_did_resolver

class StaticDIDResolver(DIDResolver):
    """
    Provides functionality for resolving Decentralized Identifiers (DIDs) into
    corresponding DID Documents (DIDDoc) using a custom static resolution mechanism.

    This class extends the behavior of the base `DIDResolver` class by implementing
    a custom resolution strategy to convert DIDs into concrete DID Documents. The
    resolution process is synchronous and builds the DIDDoc manually based on the
    output of the custom DID resolution logic.

    Methods:
        resolve: Resolves a given Decentralized Identifier (DID) into a DID Document.
    """
    async def resolve(self, did: DID) -> DIDDoc:
        try:
            doc = custom_did_resolver(did)
        except ValueError as e:
            raise ValueError(f"Unable to resolve DID {did}") from e

        # manually build the DIDDoc
        vm = VerificationMethod(
            id=doc["verificationMethod"][0]["id"],
            type=VerificationMethodType(1),  # because in class VerificationMethodType --> JSON_WEB_KEY_2020=1
            controller=doc["verificationMethod"][0]["controller"],
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat(1), # because in class VerificationMaterialFormat --> JWK=1
                value=json.dumps(doc["verificationMethod"][0]["publicKeyJwk"])
            ),
        )

        return DIDDoc(
            did=doc["id"],
            key_agreement_kids=doc["keyAgreement"],
            authentication_kids=doc["authentication"],
            verification_methods=[vm],
            didcomm_services=[],
        )
