import json
import uuid
from traceback import print_tb

from didcomm.message import Message as DidcommMessage
from didcomm.common.resolvers import ResolversConfig
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack

from common import config

# =================== CONFIG ===================
cfg = config()

BOB_DID = cfg["DIDs"]["bob"]
BOB_BASE_URL = cfg["A2A"]["bob_base_url"]
BASE_URL = cfg["waltid"]["base_url"]
# ==============================================

def validate_and_get_jwe(target_id: str, jsonrpc_response: dict) -> str:
    """
    Validates the response from a JSON-RPC call and extracts the JSON Web Encryption (JWE) data.

    This function checks for potential errors in a JSON-RPC response, validates the
    message ID, and ensures that the response contains expected structure and data.
    It specifically focuses on extracting the JWE field from a DIDComm container
    within the response.

    Parameters:
    target_id: str
        The expected message ID to be matched against the response.
    jsonrpc_response: dict
        The JSON-RPC response object containing the data to validate and process.

    Returns:
    str
        A JSON-formatted string of the JWE data extracted from the response.

    Raises:
    RuntimeError
        If the response contains an error, has mismatched message ID, or lacks the
        expected structure or data required to extract the JWE.
    """
    # handling JSON-RPC errors
    if "error" in jsonrpc_response:
        raise RuntimeError(f"A2A error from Bob: {jsonrpc_response['error']}")

    result = jsonrpc_response.get("result") or {}

    # check if the message IDs match
    resp_id = jsonrpc_response.get("result").get("messageId")
    if resp_id != target_id:
        raise RuntimeError(f"ID mismatch! Expected {target_id}, got {resp_id}")

    message = result.get("message") or result

    parts = message.get("parts") or []
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