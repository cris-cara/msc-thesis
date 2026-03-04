# * Imagine that Eve has to send a message to Alice but a hypothetical MITM is able to poison Alice's DID Document
# * (i.e., by introducing a malignant DID Resolver)
# * MITM (poisons Alice's DID doc) --x Eve --> Alice

import json
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from didcomm.errors import MalformedMessageError, MalformedMessageCode
from didcomm.message import Message as DidcommMessage
from didcomm.pack_encrypted import pack_encrypted, PackEncryptedConfig
from didcomm.unpack import unpack

from alice.__main__ import Alice
from common.agents import Agent
from eve.__main__ import Eve

BOOT = Path(__file__).resolve().parent / "_run_waltid_server.py"

@pytest_asyncio.fixture
async def alice():
    """ Initialize Alice agent."""
    alice = Alice()
    await alice.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await alice.sign_in()
    alice.set_resolvers_config()

    yield alice

@pytest_asyncio.fixture
async def eve():
    """ Initialize Eve agent."""
    eve = Eve()
    await eve.mcp_connect(
        command=sys.executable,
        args=[str(BOOT)],
    )
    await eve.sign_in()
    eve.set_malignant_resolvers_config()

    yield eve

@pytest.mark.asyncio
async def test_wrong_key_recipient(alice: Agent, eve: Agent):
    #* packing DIDComm message (EVE side)
    didcomm_msg = DidcommMessage(
        id=str(uuid.uuid4()),
        type="example/1.0",
        body={"message": "Hi Alice! How are you?"},
        frm=eve.did,
        to=[alice.did],
    )

    jwe_request_json = await pack_encrypted(
        resolvers_config=eve.resolvers_config,
        message=didcomm_msg,
        frm=eve.did,
        to=alice.did,
        sign_frm=None,
        pack_config=PackEncryptedConfig(
            protect_sender_id=False,
            forward=False,
        ),
    )

    packed_msg = json.loads(jwe_request_json.packed_msg)

    #* unpack (ALICE side)
    #* here's where the exception error will be raised
    with pytest.raises(MalformedMessageError) as exif:
        unpack_result = await unpack(
            resolvers_config=alice.resolvers_config,
            packed_msg=packed_msg,
        )

    assert exif.value.code == MalformedMessageCode.CAN_NOT_DECRYPT

    kid = packed_msg["recipients"][0]["header"]["kid"]
    assert kid.endswith("#1")   #! assert that the poisoned keyAgreement was used
