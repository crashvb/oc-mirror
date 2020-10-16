#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import certifi
import logging

import pytest

from docker_registry_client_async import DockerMediaTypes, ImageName, OCIMediaTypes
from docker_sign_verify import RegistryV2ImageSource
from pytest_docker_registry_fixtures import DockerRegistrySecure

from oc_mirror.ocrelease import get_release_metadata, put_release

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.fixture
async def registry_v2_image_source(docker_registry_secure: DockerRegistrySecure) -> RegistryV2ImageSource:
    """Provides a RegistryV2ImageSource instance."""
    # Do not use caching; get a new instance for each test
    ssl_context = docker_registry_secure.ssl_context
    ssl_context.load_verify_locations(cafile=certifi.where())
    async with RegistryV2ImageSource(ssl=ssl_context) as registry_v2_image_source:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        await registry_v2_image_source.docker_registry_client_async.add_credentials(
            docker_registry_secure.endpoint, credentials
        )

        yield registry_v2_image_source


@pytest.mark.online
@pytest.mark.parametrize(
    "release",
    [
        "quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64",
        # "s27lxlap.server27.info:5002/ocp4/openshift4:4.4.6-x86_64",
    ],
)
async def test_get_release_metadata(registry_v2_image_source: RegistryV2ImageSource, release: str):
    """Tests release metadata retrieval from a remote registry."""

    logging.getLogger("gnupg").setLevel(logging.FATAL)

    image_name = ImageName.parse(release)
    result = await get_release_metadata(registry_v2_image_source, image_name)
    assert all(
        x in result for x in ["blobs", "manifests", "signature_stores", "signing_keys"]
    )
    assert result["blobs"]
    assert result["manifests"]
    assert result["signature_stores"]
    assert result["signing_keys"]


@pytest.mark.online_modification
@pytest.mark.parametrize(
    "release",
    [
        "quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64",
        # "s27lxlap.server27.info:5002/ocp4/openshift4:4.4.6-x86_64",
    ],
)
async def test_put_release(
    docker_registry_secure: DockerRegistrySecure,
    registry_v2_image_source: RegistryV2ImageSource,
    release: str,
):
    """Tests release replication to a local registry."""

    image_name_src = ImageName.parse(release)
    image_name_dest = image_name_src.clone()
    image_name_dest.endpoint = docker_registry_secure.endpoint
    release_metadata = await get_release_metadata(registry_v2_image_source, image_name_src)

    result = await put_release(registry_v2_image_source, image_name_dest, release_metadata)
    assert result


# async def test_debug_rich(registry_v2_image_source: RegistryV2ImageSource):
#     """Tests release replication to a local registry."""
#
#     data = [
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", None),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", DockerMediaTypes.DISTRIBUTION_MANIFEST_LIST_V2),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", DockerMediaTypes.DISTRIBUTION_MANIFEST_V2),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", DockerMediaTypes.DISTRIBUTION_MANIFEST_V1),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", DockerMediaTypes.DISTRIBUTION_MANIFEST_V1_SIGNED),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", OCIMediaTypes.IMAGE_INDEX_V1),
#         ("quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64", OCIMediaTypes.IMAGE_MANIFEST_V1),
#         ("quay.io/openshift-release-dev/ocp-release@sha256:95d7b75cd8381a7e57cbb3d029b1b057a4a7808419bc84ae0f61175791331906", None)
#     ]
#     for _tuple in data:
#         image_name = ImageName.parse(_tuple[0])
#         manifest = await registry_v2_image_source.get_manifest(image_name, accept=_tuple[1])
#         assert manifest
#         logging.debug("%s", _tuple[1])
#         logging.debug("\tImage Name : %s", image_name)
#         logging.debug("\tDigest     : %s", manifest.get_digest())
#         logging.debug("\tMediaType  : %s", manifest.get_media_type())
