#!/usr/bin/env python

"""
Abstraction of an openshift atomic signature, as defined in:

https://github.com/openshift/containers-image/blob/master/docs/atomic-signature.md
"""

import logging


from docker_registry_client_async import FormattedSHA256, ImageName, JsonBytes

LOGGER = logging.getLogger(__name__)


class AtomicSignature(JsonBytes):
    """
    OpenShift atomic signature.
    """

    TYPE = "atomic container signature"

    @staticmethod
    def minimal(
        *,
        docker_manifest_digest: FormattedSHA256,
        docker_reference: str,
        _type: str = TYPE,
    ) -> "AtomicSignature":
        """
        Creates a minimalistic atomic signature.

        Args:
            docker_manifest_digest: The docker manifest digest.
            docker_reference: The docker reference.
            _type: The signature type.

        Returns:
            The corresponding atomic signature.
        """
        atomic_signature = (
            f'{{"critical":{{"image":{{"docker-manifest-digest": "{docker_manifest_digest}"}},"type": "{_type}",'
            f'"identity": {{"docker-reference": "{docker_reference}"}}}}}}'.encode(
                encoding="utf-8"
            )
        )
        return AtomicSignature(atomic_signature)

    def get_docker_manifest_digest(self) -> FormattedSHA256:
        """
        Retrieves the docker manifest digest.

        Returns:
            The docker manifest digest.
        """
        return FormattedSHA256.parse(
            self.get_json()["critical"]["image"]["docker-manifest-digest"]
        )

    def get_docker_reference(self) -> ImageName:
        """
        Retrieves the docker reference.

        Returns:
            The docker reference.
        """
        return ImageName.parse(
            self.get_json()["critical"]["identity"]["docker-reference"]
        )

    def get_type(self) -> str:
        """
        Retrieves the signature type.

        Returns:
            The signature type.
        """
        return self.get_json()["critical"]["type"]
