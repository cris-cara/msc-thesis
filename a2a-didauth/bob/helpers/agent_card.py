from a2a.types import AgentCapabilities, AgentCard, AgentSkill, HTTPAuthSecurityScheme, SecurityScheme

AUTH_SCHEME = HTTPAuthSecurityScheme(
    scheme="bearer",
    bearer_format="JWT",
    description="Present a valid Verifiable Presentation (VP) to get the access token"
)
AUTH_NAME = "bearer_auth"

def create_agent_card(url: str, authenticated: bool = False) -> AgentCard:
    """
    Creates an AgentCard instance with specific configurations for "Bob Weather Agent",
    optionally enabling authenticated mode with additional skills and security settings.

    This function generates an AgentCard object configured for the "Bob Weather Agent". In non-authenticated mode,
    the card is generated with minimal skills and no security settings. If authenticated mode is enabled,
    additional skills and security settings are included in the card configuration.

    Parameters:
    url: str
        The URL associated with the agent.
    authenticated: bool, optional
        Determines if the card should include authenticated settings such as additional skills
        and security configurations. Defaults to False.

    Returns:
    AgentCard
        The fully configured AgentCard instance for "Bob Weather Agent".
    """
    # weather skill: only in authenticated card
    weather_skill = AgentSkill(
        id="weather_didcomm",
        name="Weather over DIDComm",
        description="Given a prompt asking for the weather, returns the current answer",
        tags=["weather", "didcomm"],
        examples=["weather torino"],
        security=[{AUTH_NAME: []}] if authenticated else None,
    )

    # add weather skill to the authenticated card
    current_skills = [weather_skill] if authenticated else []

    card = AgentCard(
        name="Bob Weather Agent",
        description="Agent Bob responding to the weather via DIDComm encapsulated in A2A",
        url=url,
        version="1.0.0",
        protocol_version="0.3.0",
        preferred_transport="JSONRPC",
        capabilities=AgentCapabilities(streaming=False),
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