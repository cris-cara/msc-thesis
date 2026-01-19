from __future__ import annotations

from abc import ABC, abstractmethod

class DIDResolver(ABC):
    @staticmethod
    @abstractmethod
    def resolve(did: str) -> dict:
        pass
