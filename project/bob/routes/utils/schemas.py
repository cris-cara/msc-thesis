from pydantic import BaseModel, ConfigDict

class PresentationRequestIn(BaseModel):
    """
    Represents a presentation request input model.

    This class is used as a data structure to represent the input for a presentation
    request. It enforces specific configuration settings to ensure data validity
    and provides storage for the relevant attributes.

    Attributes:
        did_subject (str): The decentralized identifier (DID) of the subject
            associated with the presentation request.

    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    did_subject: str

class GetAccessTokenIn(BaseModel):
    """
    Represents an input model for obtaining an access token.

    This class serves as a data model used to carry the necessary information
    for obtaining an access token. The attributes define the essential details
    required by the related process, with additional configuration settings
    to enforce strict validation and formatting rules.

    Attributes:
        did_subject (str): The decentralized identifier (DID) subject associated
            with the access token request.
        MS_request_id (str): A unique identifier for the MS Entra ID request.
        didauth_task_id (str): The task ID associated with the a2a-didauth flow.
        didauth_nonce (str): A random string that comes from Phase 1 of a2a-didauth flow
    """
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    did_subject: str
    MS_request_id: str
    didauth_task_id: str
    didauth_nonce: str
