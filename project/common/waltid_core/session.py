from dataclasses import dataclass
from typing import Optional

@dataclass
class WaltIdSession:
    """
    Represents a session for WaltID interactions.

    This class is used to encapsulate session-related information
    including authentication token and associated wallet ID.

    Attributes:
        token: Authentication token used for session identification.
        wallet_id: Identifier of the wallet associated with the session.
    """
    token: Optional[str] = None
    wallet_id: Optional[str] = None