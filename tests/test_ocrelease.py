#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Manifest tests."""

import logging

from typing import Dict, Set

import certifi
import pytest

from _pytest.logging import LogCaptureFixture
from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import RegistryV2ImageSource
from pytest_docker_registry_fixtures import DockerRegistrySecure


from oc_mirror.ocrelease import get_release_metadata, put_release, translate_release

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


# TODO: What is the best way to code `DRCA_DEBUG=1 DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json` into
#       this fixture?


@pytest.fixture
async def registry_v2_image_source(
    docker_registry_secure: DockerRegistrySecure,
) -> RegistryV2ImageSource:
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
    "release,count_blobs,count_manifests,count_signature_stores,count_signing_keys,known_good_blobs,known_good_manifests",
    [
        (
            "quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64",
            227,
            109,
            2,
            1,
            {
                "sha256:06be4357dfb813c8d3d828b95661028d3d2a380ed8909b60c559770c0cd2f917": [
                    "quay.io/openshift-release-dev/ocp-release"
                ],
                "sha256:49be5ad10f908f0b5917ba11ab8529d432282fd6df7b8a443d60455619163b9c": [
                    "quay.io/openshift-release-dev/ocp-v4.0-art-dev"
                ],
            },
            {
                ImageName.parse(
                    "quay.io/openshift-release-dev/ocp-release@sha256:7613d8f7db639147b91b16b54b24cfa351c3cbde6aa7b7bf1b9c80c260efad06"
                ): "4.4.6-x86_64",
                ImageName.parse(
                    "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:ce1f23618369fc00eab1f9a9bb5f409ed6a3c2652770c8077a099a69064ee436"
                ): "4.4.6-aws-machine-controllers",
            },
        )
    ],
)
async def test_get_release_metadata(
    caplog: LogCaptureFixture,
    registry_v2_image_source: RegistryV2ImageSource,
    release: str,
    count_blobs: int,
    count_manifests: int,
    count_signature_stores: int,
    count_signing_keys: int,
    known_good_blobs: Dict[FormattedSHA256, Set[str]],
    known_good_manifests: Dict[ImageName, str],
):
    """Tests release metadata retrieval from a remote registry."""

    logging.getLogger("gnupg").setLevel(logging.FATAL)

    image_name = ImageName.parse(release)
    result = await get_release_metadata(registry_v2_image_source, image_name)

    assert result.blobs
    assert len(result.blobs) == count_blobs
    for digest in known_good_blobs.keys():
        assert digest in result.blobs.keys()
        for image_prefix in known_good_manifests[digest]:
            assert image_prefix in result.blobs[digest]

    assert result.manifests
    assert len(result.manifests) == count_manifests
    for image_name in known_good_manifests.keys():
        assert image_name in result.manifests.keys()
        assert result.manifests[image_name] == known_good_manifests[image_name]

    assert result.signature_stores
    assert len(result.signature_stores) == count_signature_stores

    assert result.signing_keys
    assert len(result.signing_keys) == count_signing_keys


@pytest.mark.online_modification
@pytest.mark.parametrize(
    "release", ["quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64"]
)
async def test_put_release(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    registry_v2_image_source: RegistryV2ImageSource,
    release: str,
):
    """Tests release replication to a local registry."""

    logging.getLogger("gnupg").setLevel(logging.FATAL)

    image_name_src = ImageName.parse(release)
    image_name_dest = image_name_src.clone()
    image_name_dest.endpoint = docker_registry_secure.endpoint
    release_metadata_src = await get_release_metadata(
        registry_v2_image_source, image_name_src
    )

    await put_release(registry_v2_image_source, image_name_dest, release_metadata_src)

    release_metadata_dest = await get_release_metadata(
        registry_v2_image_source, image_name_dest
    )

    assert (
        list(release_metadata_dest.blobs.keys()).sort()
        == list(release_metadata_src.blobs.keys()).sort()
    )
    for digest in release_metadata_src.blobs.keys():
        assert (
            list(release_metadata_dest.blobs[digest]).sort()
            == list(release_metadata_src.blobs[digest]).sort()
        )

    assert (
        list([str(x) for x in release_metadata_dest.manifests.keys()]).sort()
        == list([str(x) for x in release_metadata_src.manifests.keys()]).sort()
    )
    for image_name in release_metadata_src.manifests.keys():
        # Special Case: The release image in imposed in the metadata, not derived ...
        if image_name == image_name_src:
            assert (
                release_metadata_dest.manifests[image_name_dest]
                == release_metadata_src.manifests[image_name_src]
            )
            continue

        # Note we cannot attempt a direct lookup without a KeyError ...
        # assert release_metadata_dest.manifests[image_name] == release_metadata_src.manifests[image_name]
        tmp = {str(x): x for x in release_metadata_dest.manifests.keys()}
        assert (
            release_metadata_dest.manifests[tmp[str(image_name)]]
            == release_metadata_src.manifests[image_name]
        )

    assert (
        release_metadata_dest.signature_stores.sort()
        == release_metadata_src.signature_stores.sort()
    )

    assert (
        release_metadata_dest.signing_keys.sort()
        == release_metadata_src.signing_keys.sort()
    )


@pytest.mark.online_modification
@pytest.mark.parametrize(
    "release", ["quay.io/openshift-release-dev/ocp-release:4.4.6-x86_64"]
)
async def test_translate_release(
    caplog: LogCaptureFixture,
    docker_registry_secure: DockerRegistrySecure,
    registry_v2_image_source: RegistryV2ImageSource,
    release: str,
):
    """Tests release translation to a local registry."""

    logging.getLogger("gnupg").setLevel(logging.FATAL)

    image_name_src = ImageName.parse(release)
    image_name_dest = image_name_src.clone()
    image_name_dest.endpoint = docker_registry_secure.endpoint
    release_metadata_src = await get_release_metadata(
        registry_v2_image_source, image_name_src
    )

    await translate_release(
        registry_v2_image_source, image_name_dest, release_metadata_src
    )

    # TODO: ...


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
