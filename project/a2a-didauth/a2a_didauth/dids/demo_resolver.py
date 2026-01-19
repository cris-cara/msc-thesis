from a2a_didauth.dids import DIDResolver
from dids_resolver import resolve

class DIDResolverDemo(DIDResolver):
    @staticmethod
    def resolve(did: str) -> dict:
        return resolve(did)