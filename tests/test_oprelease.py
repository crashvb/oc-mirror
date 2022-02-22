#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Operator release tests."""

import logging

from typing import Dict, Generator, NamedTuple, Optional

import pytest

from docker_registry_client_async import ImageName
from docker_sign_verify import RegistryV2
from _pytest.logging import LogCaptureFixture
from pytest_docker_registry_fixtures import DockerRegistrySecure


from oc_mirror.oprelease import get_release_metadata, log_release_metadata, put_release

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


class TypingGetTestDataLocal(NamedTuple):
    # pylint: disable=missing-class-docstring
    index_name: ImageName
    package_channel: Dict[str, Optional[str]]


def get_test_data() -> Generator[TypingGetTestDataLocal, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    dataset = [
        TypingGetTestDataLocal(
            index_name=ImageName.parse(
                "registry.redhat.io/redhat/redhat-operator-index:v4.8"
            ),
            package_channel={"ocs-operator": None},
        ),
        # TypingGetTestDataLocal(
        #     index_name=ImageName.parse(
        #         "registry.redhat.io/redhat/redhat-operator-index:v4.8"
        #     ),
        #     package_channel={"ocs-operator": "eus-4.8"},
        # ),
    ]
    for data in dataset:
        yield data


@pytest.fixture(params=get_test_data())
def known_good_release(request) -> TypingGetTestDataLocal:
    """Provides 'known good' metadata for a local release that can be modified."""
    return request.param


@pytest.mark.online
async def test_get_release_metadata(
    known_good_release: TypingGetTestDataLocal,
    registry_v2: RegistryV2,
):
    """Tests release metadata retrieval from a remote registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata ...
    result = await get_release_metadata(
        registry_v2=registry_v2,
        index_name=known_good_release.index_name,
        package_channel=known_good_release.package_channel,
        verify=False,
    )

    assert result.index_database
    assert result.manifest_digest
    assert result.operators
    # assert result.signature_stores
    # assert result.signatures
    # assert result.signing_keys
    assert len(result.operators) == len(known_good_release.package_channel.keys())
    for package in known_good_release.package_channel.keys():
        operator = [
            operator for operator in result.operators if operator.package == package
        ][0]
        assert operator
        assert operator.bundle
        if known_good_release.package_channel[package] is None:
            assert operator.channel is not None
        else:
            assert operator.channel == known_good_release.package_channel[package]
        assert operator.images


@pytest.mark.online
@pytest.mark.parametrize(
    "release,package_channel,bundle_image,bundle_name,related_image",
    [
        (
            "registry.redhat.io/redhat/redhat-operator-index:v4.8",
            {"ocs-operator": "eus-4.8"},
            "registry.redhat.io/ocs4/ocs-operator-bundle@"
            "sha256:6b7a27b9f2c8ec7c1a32cffb1eaac452442b1874d0d8bacd242d8a6278337064",
            "ocs-operator.v4.8.7",
            "registry.redhat.io/rhceph/rhceph-4-rhel8@"
            "sha256:4b16d6f54a9ae1e43ab0f9b76f1b0860cc4feebfc7ee0e797937fc9445c5bb0a",
        ),
    ],
)
async def test_log_release_metadata(
    bundle_image: str,
    bundle_name: str,
    caplog: LogCaptureFixture,
    package_channel: Dict[str, str],
    registry_v2: RegistryV2,
    related_image: str,
    release: str,
):
    """Tests logging of release metadata."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    # Retrieve the release metadata ...
    image_name = ImageName.parse(release)
    result = await get_release_metadata(
        registry_v2=registry_v2,
        index_name=image_name,
        package_channel=package_channel,
        verify=False,
    )
    assert result

    await log_release_metadata(index_name=image_name, release_metadata=result)
    assert bundle_image in caplog.text
    assert bundle_name in caplog.text
    assert str(image_name) in caplog.text
    for key in package_channel.keys():
        assert key in caplog.text
    assert related_image in caplog.text


@pytest.mark.online_modification
async def test_put_release_from_internet(
    docker_registry_secure: DockerRegistrySecure,
    known_good_release: TypingGetTestDataLocal,
    registry_v2: RegistryV2,
):
    """Tests release replication to a local registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata ...
    release_metadata_src = await get_release_metadata(
        registry_v2=registry_v2,
        index_name=known_good_release.index_name,
        package_channel=known_good_release.package_channel,
        verify=False,
    )

    # Replicate the release ...
    image_name_dest = known_good_release.index_name.clone()
    image_name_dest.endpoint = docker_registry_secure.endpoint
    await put_release(
        index_name=image_name_dest,
        registry_v2=registry_v2,
        release_metadata=release_metadata_src,
        verify=False,
    )

    # Retrieve the release metadata (again) ...
    release_metadata_dest = await get_release_metadata(
        registry_v2=registry_v2,
        index_name=image_name_dest,
        package_channel=known_good_release.package_channel,
        verify=False,
    )

    # # Release metadata should have the same blob digests ...
    # assert (
    #         list(release_metadata_dest.blobs.keys()).sort()
    #         == list(release_metadata_src.blobs.keys()).sort()
    # )
    # # ... all blobs should correspond to the same namespaces ...
    # for digest in release_metadata_src.blobs.keys():
    #     assert (
    #             list(release_metadata_dest.blobs[digest]).sort()
    #             == list(release_metadata_src.blobs[digest]).sort()
    #     )
    #
    # # Release metadata digest should be the same ...
    # assert release_metadata_dest.manifest_digest == release_metadata_src.manifest_digest
    #
    # # Release metadata manifest digest should be the same ...
    # assert (
    #         list(release_metadata_dest.manifests.keys()).sort()
    #         == list(release_metadata_src.manifests.keys()).sort()
    # )
    #
    # # Translate the release image tags to a digest for comparison ...
    # image_name_dest_digest = image_name_dest.clone()
    # image_name_dest_digest.digest = release_metadata_dest.manifest_digest
    # image_name_dest_digest.tag = None
    # image_name_src_digest = image_name_src.clone()
    # image_name_src_digest.digest = release_metadata_src.manifest_digest
    # image_name_src_digest.tag = None
    #
    # # Release metadata manifest tags should be the same ...
    # for image_name in release_metadata_src.manifests.keys():
    #     # Special Case: The release image in imposed in the metadata, not derived ...
    #     if equal_if_unqualified(image_name, image_name_src_digest):
    #         assert (
    #                 release_metadata_dest.manifests[image_name_dest_digest]
    #                 == release_metadata_src.manifests[image_name_src_digest]
    #         )
    #     else:
    #         assert (
    #                 release_metadata_dest.manifests[image_name]
    #                 == release_metadata_src.manifests[image_name]
    #         )
    #
    # # The raw image references should be the same ...
    # assert (
    #         release_metadata_dest.raw_image_references.get_digest()
    #         == release_metadata_src.raw_image_references.get_digest()
    # )
    #
    # # The raw release metadata should be the same ...
    # assert (
    #         release_metadata_dest.raw_release_metadata
    #         == release_metadata_src.raw_release_metadata
    # )
    #
    # # TODO: Do we need to check signatures here?
    #
    # # The signature stores should be the same ...
    # assert (
    #         release_metadata_dest.signature_stores.sort()
    #         == release_metadata_src.signature_stores.sort()
    # )
    #
    # # The signing keys should be the same ...
    # assert (
    #         release_metadata_dest.signing_keys.sort()
    #         == release_metadata_src.signing_keys.sort()


async def test_foobar(registry_v2: RegistryV2):
    import logging

    logging.basicConfig(level=logging.DEBUG)
    image_name = ImageName.parse(
        "registry.redhat.io/ocs4/ocs-rhel8-operator@sha256:3642e698c38d4c54b35cd433d520ab3ecf46afab6863a4c07f4460bc33552f6a"
    )
    manifest = await registry_v2.get_manifest(image_name)
    LOGGER.fatal("MANIFEST: %s", manifest)
