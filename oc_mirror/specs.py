#!/usr/bin/env python

# pylint: disable=too-few-public-methods

"""Reusable string literals."""


class OpenShiftReleaseSpecs:
    """
    OpenShift string literals.
    """

    IMAGE_REFERENCES_NAME = "image-references"
    MANIFEST_PATH_PREFIX = "release-manifests/"
    RELEASE_ANNOTATION_CONFIG_MAP_VERIFIER = (
        "release.openshift.io/verification-config-map"
    )
    RELEASE_METADATA = "release-metadata"
