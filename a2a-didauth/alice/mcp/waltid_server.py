from mcp.server.fastmcp import FastMCP
from common.waltid_core import WaltIdClient as waltid
from common.waltid_core import WaltIdSession
from common import get_logger
from typing import Optional

mcp = FastMCP("Alice-waltid-wallet")
logger = get_logger(__name__)  # get a logger instance

@mcp.tool()
async def register(name: str, email: str, password: str) -> None:
    """
    Registers a user with the provided credentials.

    This function sends a request to register a user with the given name, email,
    and password using the WaltID system. Upon successful registration, a confirmation
    message is printed to the console.

    Args:
        name: The full name of the user to register.
        email: The email address of the user.
        password: The password for the user's account.

    Returns:
        None
    """
    await waltid.register(
        name=name,
        acc=email,
        pwd=password
    )
    logger.info("Registration successful!")
    return

@mcp.tool()
async def authenticate(email: str, password: str) -> WaltIdSession:
    """
    Asynchronously authenticates a user using email and password credentials, returning a session object upon
    successful authentication.

    Args:
        email (str): The email address of the user attempting to authenticate.
        password (str): The password associated with the provided email.

    Returns:
        WaltIdSession: An instance of the WaltIdSession class, representing the authenticated session.
    """
    return await waltid.authenticate(email, password)

@mcp.tool()
async def get_default_did(session:WaltIdSession) -> str:
    """
    Gets the default decentralized identifier (DID) for the given WaltId session.

    This method interacts asynchronously with the WaltId library to retrieve the
    default DID associated with the provided session object.

    Parameters:
    session (WaltIdSession): A WaltIdSession object required for authentication
    with the WaltId service to retrieve the default DID.

    Returns:
    str: The default DID associated with the provided session.
    """
    return await waltid.get_default_did(session)

@mcp.tool()
async def get_credentials_list(session: WaltIdSession) -> list:
    """
    Get a list of credentials asynchronously.

    This function interacts with the WaltIdSession to fetch a list of credentials
    available for the session. It communicates with the WaltId backend to retrieve
    the data. This functionality is intended for retrieving credentials for
    authentication or authorization purposes.

    Arguments:
        session (WaltIdSession): An active session object required to authenticate
                                 with the WaltId backend.

    Returns:
        list: A list containing the retrieved credentials.

    Raises:
        No explicit error handling is implemented within this function; however,
        exceptions might be raised from the underlying WaltId operations,
        connection issues, or session invalidations.
    """
    return await waltid.get_credentials_list(session=session)

@mcp.tool()
async def match_creds_for_pres_def(session: WaltIdSession, presentation_definition: dict) -> dict:
    """
    Matches credentials for a given presentation definition. This asynchronous method interacts
    with the walt.id wallet API to retrieve relevant credentials matching the provided
    presentation definition using the provided session.

    Arguments:
        session (WaltIdSession): The session object for interacting with the walt.id API.
        presentation_definition (dict): A dictionary representing the presentation definition
            for which matching credentials are being requested.

    Returns:
        dict: A dictionary containing the matched credentials that satisfy the given
        presentation definition.
    """
    return await waltid.match_creds_for_pres_def(
        session=session,
        presentation_definition=presentation_definition
    )

@mcp.tool()
async def get_credential_by_id(session: WaltIdSession, credential_id: str) -> dict:
    """
    Retrieve a specific credential's details by its unique identifier.

    This async function is used to fetch the details of a credential stored within a WaltID
    session. It requires a valid WaltIdSession and the unique credential identifier
    to retrieve the corresponding credential as a dictionary.

    Arguments:
        session (WaltIdSession): The session object representing an active WaltID session.
        credential_id (str): The unique identifier for the credential to be retrieved.

    Returns:
        dict: A dictionary containing the details of the credential associated
        with the given identifier.

    """
    return await waltid.get_credential_by_id(
        session=session,
        credential_id=credential_id
    )

@mcp.tool()
async def export_key_jwk(session: WaltIdSession, key_id: Optional[str] = None,
                         load_private: bool = True) -> dict:
    """
    Exports a key in JWK (JSON Web Key) format.

    This function uses the provided WaltIdSession to export a key in JWK format by its
    identifier, optionally including the private key information.

    The export process can be controlled to include only public information or to
    load private details depending on the `load_private` parameter.

    Arguments:
        session (WaltIdSession): The active session for interacting with WaltID services.
        key_id (Optional[str]): The identifier of the key to be exported. If not
            provided, a default behavior is determined by WaltID's API.
        load_private (bool): Specifies whether to include the private key. Defaults to True.

    Returns:
        dict: A dictionary representing the key in JWK format.

    Raises:
        Any relevant exception that occurs during interaction with WaltID services.
    """
    return await waltid.export_key_jwk(session=session, key_id=key_id, load_private=load_private)

def main() -> None:
    # transport MCP stdio
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()