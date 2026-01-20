from __future__ import annotations

from typing import Optional


class A2ADidAuthError(Exception):
    """Base error for DID Auth over A2A."""
    def __init__(self, message: str):
        super().__init__(message)

class A2ADidAuthPayloadError(A2ADidAuthError):
    """Malformed/invalid payload, protocol-level issues."""
    def __init__(self, message: str, *, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.__cause__ = cause

class A2ADidAuthTransportError(A2ADidAuthError):
    """Errors related to transport layer (e.g., network issues)."""
    def __init__(self, message: str, *, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.__cause__ = cause

class A2ADidAuthCryptoError(A2ADidAuthError):
    """Errors related to cryptographic operations."""
    def __init__(self, message: str, *, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.__cause__ = cause

class A2ADidAuthSignatureError(A2ADidAuthError):
    """Errors related to signature verification."""
    def __init__(self, message: str, *, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.__cause__ = cause