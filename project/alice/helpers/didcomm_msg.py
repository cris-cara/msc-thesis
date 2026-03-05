import json
import uuid

from didcomm.common.resolvers import ResolversConfig
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack

from common import config

# =================== CONFIG ===================
cfg = config()

BOB_DID = cfg["DIDs"]["bob"]
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BASE_URL = cfg["waltid"]["base_url"]
# ==============================================

def validate_and_get_jwe(target_json_rp_id: str, jsonrpc_response: dict) -> str:
    """
    Validates the consistency and structure of a JSON-RPC response and extracts the JWE
    (JSON Web Encryption) data field if it exists.

    This function ensures the provided JSON-RPC response matches the expected message ID, contains
    no errors, and adheres to the expected data format. If any of these conditions are unmet, a
    RuntimeError is raised.

    Parameters:
    target_json_rp_id: The ID of the originally sent JSON-RPC message, used to verify the response ID.
    jsonrpc_response: The JSON-RPC response dictionary received, expected to include artifacts and
                      DIDComm-related data.

    Raises:
    RuntimeError: Raised in the following cases:
        - The JSON-RPC response contains an "error" field.
        - The "id" field in the response does not match the expected target_json_rp_id.
        - The response does not include valid artifacts with parts.
        - The parts list in the response does not include an expected "data" kind.
        - The "data" in the part does not contain a "jwe" field.

    Returns:
    String containing the extracted JWE data encoded as JSON.
    """
    # handling JSON-RPC errors
    if "error" in jsonrpc_response:
        raise RuntimeError(f"A2A error from Bob: {jsonrpc_response['error']}")

    # check if the message IDs match
    resp_json_rpc_id = jsonrpc_response.get("id")
    if resp_json_rpc_id != target_json_rp_id:
        raise RuntimeError(f"ID mismatch! Expected {target_json_rp_id}, got {resp_json_rpc_id}")

    result = jsonrpc_response.get("result") or {}

    artifacts: list = result.get("artifacts") or result

    parts: list = artifacts[0].get("parts") or []
    if not parts:
        raise RuntimeError("A2A response has no parts")

    first_part = parts[0]
    if first_part.get("kind") != "data":
        raise RuntimeError(f"Unexpected part kind in response: {first_part.get('kind')}")

    data = first_part.get("data") or {}
    didcomm_container = data.get("didcomm") or {}
    jwe_reply_json = didcomm_container.get("jwe")
    if not jwe_reply_json:
        raise RuntimeError("No 'jwe' field in DIDComm container in response")

    return json.dumps(jwe_reply_json)

async def build_get_access_token_request(sender_did: str, body: dict, resolvers_cfg: ResolversConfig) -> dict:
    """
    Creates and returns an access token request message packed using DIDComm encryption.

    The function generates a DIDComm message with the specified sender DID, message
    body, and recipient DID. It then encrypts the message using the provided
    resolvers configuration and packing options. The encrypted message is returned
    as a dictionary after being converted from a JSON string.

    Parameters:
    sender_did: str
        The DID of the sender of the message.
    body: dict
        The body content of the message to be included in the DIDComm message.
    resolvers_cfg: ResolversConfig
        The configuration used for resolving cryptographic keys during packing.

    Returns:
    dict
        A dictionary representation of the encrypted and packed DIDComm message.
    """
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/access-token-request",
        body=body,
        frm=sender_did,
        to=[BOB_DID],
    )

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_cfg,
        message=didcomm_msg,
        frm=sender_did,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    # packed_msg is a JSON string; cast into dict
    return json.loads(pack_result.packed_msg)

async def build_didcomm_weather_request(sender_did: str, city: str, access_token: str, resolvers_cfg: ResolversConfig) -> dict:
    """
    Builds a DIDComm message for requesting weather information, encrypts it, and returns the packed
    message in dictionary format.

    The function generates a DIDComm message containing the weather request, encrypts it using
    `pack_encrypted` with specified configuration, and returns the packed message.

    Args:
        sender_did: The DID of the sender of the message.
        city (str): The name of the city for which weather information is requested.
        access_token (str): The access token used for authentication in the weather request.
        resolvers_cfg (ResolversConfig): The configuration for key/did resolvers used in the
            encryption process.

    Returns:
        dict: The packed encrypted DIDComm message in dictionary format.
    """
    # ! attach the access_token in the DIDComm message body
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0/weather-request",
        body={
            "message": f"Ciao Bob, quale è il meteo a {city}?",
            "access_token": access_token # ! here
        },
        frm=sender_did,
        to=[BOB_DID],
    )

    pack_result = await pack_encrypted(
        resolvers_config=resolvers_cfg,
        message=didcomm_msg,
        frm=sender_did,
        to=BOB_DID,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    # packed_msg is a JSON string; cast into dict
    return json.loads(pack_result.packed_msg)

async def unpack_bob_response(jwe_reply_str: str, resolvers_cfg: ResolversConfig) -> DidcommMessage:
    """
    Unpacks a Bob's JWE response string into a DidcommMessage instance.

    This function processes a JWE formatted string, uses the provided resolvers configuration
    to unpack the encrypted message, and retrieves the resulting message content as a
    DidcommMessage.

    Arguments:
        jwe_reply_str: str
            The JWE formatted response string to be unpacked.
        resolvers_cfg: ResolversConfig
            The resolvers configuration used for decryption and unpacking of the message.

    Returns:
        DidcommMessage
            The unpacked DIDComm message contained within the JWE response string.

    """
    unpack_result = await unpack(
        resolvers_config=resolvers_cfg,
        packed_msg=jwe_reply_str,
    )

    reply_msg = unpack_result.message
    return reply_msg