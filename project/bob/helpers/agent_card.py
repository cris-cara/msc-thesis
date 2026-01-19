from a2a.types import(
    AgentCard,
    AgentCapabilities,
    AgentExtension,
    AgentSkill,
    HTTPAuthSecurityScheme,
    SecurityScheme
)
from common.config import config

# =================== CONFIG ===================
cfg = config()

EXT_URI = cfg["A2A"]["a2a_did_auth_uri"]
# ==============================================

AUTH_SCHEME = HTTPAuthSecurityScheme(
    scheme="bearer",
    bearer_format="JWT",
    description="Present a valid Verifiable Presentation (VP) to get the access token"
)
AUTH_NAME = "bearer_auth"

DIDCOMM_CAPS = {
    "formats": ["application/didcomm-encrypted+json"],
    "mode": ["authcrypt"],
    "alg": ["ECDH-1PU+A256KW"],
    "enc": ["A256CBC-HS512"],
    "curves": ["P-256"],
}

def create_agent_card(url: str, did: str, authenticated: bool = False) -> AgentCard:
    # Public skill: explains DIDAuth prerequisite and how to run it over message/send
    didauth_skill = AgentSkill(
        id="didauth",
        name="DID Authentication (DIDAuth)",
        description=(
            "Prerequisite step. Before requesting an access token via VP, the client MUST complete "
            "a DID-based mutual authentication handshake using the DIDAuth profile extension.\n\n"
            "Protocol (over JSON-RPC method `message/send`):\n"
            f"- begin: set 'op'='begin', include 'client_did' and 'nonce'\n"
            f"- challenge: server replies with 'op'='challenge' and 'jws' (JWS challenge)\n"
            f"- response: client sends 'op'='response' and 'jws' (JWS response)\n"
            f"- complete/reject: server replies 'op'='complete' or 'op'='reject'\n\n"
            "After 'complete', a DIDComm channel can be considered established and the client may "
            "proceed with VP-based authorization to obtain a JWT access token."
        ),
        tags=["didauth", "dids", "authentication", "a2a", "didcomm"],
        examples=[
            "start didauth",
            "didauth begin with my DID",
            "complete didauth and then request access token",
        ],
        security=None,  # public: no bearer required to start authentication
    )

    # weather skill: only in authenticated card
    weather_skill = AgentSkill(
        id="weather_didcomm",
        name="Weather over DIDComm",
        description="Given a prompt asking for the weather, returns the current answer",
        tags=["weather", "didcomm"],
        examples=["weather torino"],
        security=[{AUTH_NAME: []}] if authenticated else None,
    )

    # - Skills list:
    # - Public card: expose didauth skill only (so clients discover the prerequisite)
    # - Authenticated card: expose didauth + protected skills (optional to keep didauth visible too)
    # add weather skill to the authenticated card
    current_skills = [didauth_skill] if not authenticated else [didauth_skill, weather_skill]

    card = AgentCard(
        name="Bob Weather Agent",
        description="Agent Bob responding to the weather via DIDComm encapsulated in A2A",
        url=url,
        version="1.0.0",
        protocol_version="0.3.0",
        preferred_transport="JSONRPC",
        capabilities=AgentCapabilities(
            streaming=False,
            extensions=[
                AgentExtension(
                    uri=EXT_URI,
                    description=(
                        "DIDAuth profile extension (DID-based mutual authentication) executed over "
                        "`message/send` using namespaced metadata keys. This step MUST be completed "
                        "before the VP-based authorization flow."
                    ),
                    required=True,
                    params={
                        "dids": did,
                        "didcomm": DIDCOMM_CAPS,
                    }
                )
            ],
        ),
        default_input_modes=["text"],
        default_output_modes=["text"],
        skills=current_skills,
        supports_authenticated_extended_card=True,
    )

    # security capabilities declarations (ok in public card too)
    card.security_schemes = {AUTH_NAME: SecurityScheme(root=AUTH_SCHEME)}

    # - VERY IMPORTANT:
    # - do not set card.security in the public card
    # - if you want, you can set card.security ONLY in the authenticated card but it’s not necessary
    # if you already have skill.security
    if authenticated:
        card.security = [{AUTH_NAME: []}]  # optional

    return card