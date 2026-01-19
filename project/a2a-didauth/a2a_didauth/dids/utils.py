from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple
from jwcrypto import jwk

class DIDDocUtils:
    @staticmethod
    def kid_in_verification_method(did_document: Dict[str, Any], kid: str) -> bool:
        """
        Determines whether a `kid` is part of the `verificationMethod` within a DID document.

        This function searches the "verificationMethod" array in the provided DID document
        to determine if the specified key ID (`kid`) exists as an identifier. If the array is
        not present or not a list, the function returns `False`. If a dictionary within the
        array has a matching `id` field equal to `kid`, the function returns `True`.

        Args:
            did_document (Dict[str, Any]): The DID document containing the "verificationMethod"
                entry to search within.
            kid (str): The key identifier to locate within the verification methods.

        Returns:
            bool: `True` if the specified `kid` is found in the "verificationMethod" array;
                otherwise, `False`.
        """
        vmethods = did_document.get("verificationMethod", [])
        if not isinstance(vmethods, list):
            return False

        for vm in vmethods:
            if isinstance(vm, dict) and vm.get("id") == kid:
                return True

        return False

    @staticmethod
    def kid_in_authentication(did_document: Dict[str, Any], kid: str) -> bool:
        """
        Checks if a specific key identifier (kid) is present in the authentication
        section of the given DID document.

        This method verifies whether the provided `kid` is part of the list under
        the "authentication" key in the DID document. The "authentication" section
        should be an array; if it is not, the verification will return False.

        Args:
            did_document (Dict[str, Any]): The DID document to inspect. This should
                be a dictionary containing at least an "authentication" key which
                maps to a list.
            kid (str): The key identifier to check for in the "authentication"
                section of the DID document.

        Returns:
            bool: True if the `kid` is found in the "authentication" list of the DID
            document; False otherwise.
        """
        authentication = did_document.get("authentication", [])
        if not isinstance(authentication, list):
            return False

        for entry in authentication:
            if entry == kid:
                return True

        return False

    @staticmethod
    def kid_in_key_agreement(did_document: Dict[str, Any], kid: str) -> bool:
        """
        Determines whether a given key identifier (kid) exists in the `keyAgreement` section of a DID document
        and verifies its existence in the `verificationMethod`. This method evaluates if the `kid` is both
        present in the `keyAgreement` list and properly configured in the `verificationMethod`.

        Args:
            did_document (Dict[str, Any]): The DID document containing the key agreement and verification
                method details.
            kid (str): The key identifier to check for existence in the `keyAgreement` array.

        Returns:
            bool: True if the `kid` exists in the `keyAgreement` list and is validated against the
                `verificationMethod`. False otherwise.
        """
        key_agreement = did_document.get("keyAgreement", [])
        if not isinstance(key_agreement, list) or len(key_agreement) == 0:
            return False

        for entry in key_agreement:
            if entry == kid:
                return DIDDocUtils.kid_in_verification_method(did_document, kid)

        return False

    @staticmethod
    def extract_curve_for_kid(did_document: Dict[str, Any], kid: str) -> Optional[Tuple[str, str]]:
        """
        Extracts the key type and curve from a DID document for a specific key identifier (kid).

        The function searches through the 'verificationMethod' list in the provided DID document to
        find a specific verification method matching the given `kid`. Once found, it extracts the
        public key type (`kty`) and curve (`crv`) from the `publicKeyJwk` attribute.

        Args:
            did_document (Dict[str, Any]): The DID document containing verification methods and key
                information.
            kid (str): The key identifier to search for within the DID document's verification methods.

        Returns:
            Optional[Tuple[str, str]]: A tuple containing the key type (`kty`) and curve (`crv`), if
            successfully extracted. Returns `None` if the specified `kid` is not found or if the
            required attributes are missing/incompatible.
        """
        vmethods = did_document.get("verificationMethod", [])
        if not isinstance(vmethods, list):
            return None

        for vm in vmethods:
            if not isinstance(vm, dict):
                continue
            if vm.get("id") != kid:
                continue

            jwk = vm.get("publicKeyJwk")
            if not isinstance(jwk, dict):
                return None

            kty = jwk.get("kty")
            crv = jwk.get("crv")

            if isinstance(kty, str) and isinstance(crv, str):
                return kty, crv

            return None

        return None

    @staticmethod
    def extract_public_key_from_did_doc_by_kid(did_document: Dict[str, Any], kid: str) ->Optional[Dict[str, Any]]:
        """
        Extract the public key from a DID document by its key ID (kid).

        This function searches through the "verificationMethod" array within the provided
        DID document to find a matching "id" that corresponds to the specified kid. If a match
        is found, a corresponding JWK object of the public key is returned. If no match is
        found or the "verificationMethod" is not a valid list, None is returned.

        Args:
            did_document (Dict[str, Any]): A dictionary representing the DID document,
                which must include a "verificationMethod" key containing an array of
                verification methods.
            kid (str): A key ID (string) used to search for the matching verification method
                in the DID document.

        Returns:
            Optional[Dict[str, Any]]: A JWK object corresponding to the matched public key,
                or None if no matching "id" is found or the DID document is invalid.
        """
        vmethods = did_document.get("verificationMethod", [])
        if not isinstance(vmethods, list):
            return None

        for vm in vmethods:
            if kid == vm["id"]:
                return jwk.JWK.from_json(json.dumps(vm["publicKeyJwk"]))

        return None