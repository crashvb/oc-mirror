#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""Operator release tests."""

import asyncio
import logging

from typing import Dict, Generator, List, NamedTuple, Optional

import pytest

from docker_registry_client_async import FormattedSHA256, ImageName
from docker_sign_verify import NoSignatureError, RegistryV2
from _pytest.logging import LogCaptureFixture
from pytest_docker_registry_fixtures import DockerRegistrySecure

from oc_mirror.oprelease import (
    get_release_metadata,
    log_release_metadata,
    put_release,
    translate_release_metadata,
    TypingRegexSubstitution,
)

from .testutils import equal_if_unqualified, get_test_data, needs_credentials

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)

# Bug Fix: https://github.com/crashvb/docker-registry-client-async/issues/24
#
# Right now this is known to leave a nasty "Fatal error on SSL transport" error
# at the end of the test execution; however, without this we cannot test using
# a TLS-in-TLS proxy ...
setattr(asyncio.sslproto._SSLProtocolTransport, "_start_tls_compatible", True)


class TypingGetTestDataLocal(NamedTuple):
    # pylint: disable=missing-class-docstring
    index_name: ImageName
    package_channel: Dict[str, Optional[str]]
    signature_stores: List[str]
    signing_keys: List[str]


def get_release_data() -> Generator[TypingGetTestDataLocal, None, None]:
    """Dynamically initializes test data for a local mutable registry."""
    dataset = [
        TypingGetTestDataLocal(
            index_name=ImageName.parse(
                "registry.redhat.io/redhat/redhat-operator-index:v4.8"
            ),
            package_channel={"ocs-operator": None},
            signature_stores=[
                "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release"
            ],
            signing_keys=[],
        ),
        TypingGetTestDataLocal(
            index_name=ImageName.parse(
                "registry.redhat.io/redhat/redhat-operator-index:v4.8"
            ),
            package_channel={"ocs-operator": "eus-4.8"},
            signature_stores=[
                "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release"
            ],
            signing_keys=[],
        ),
    ]
    for data in dataset:
        yield data


@pytest.fixture(params=get_release_data())
def known_good_release(request) -> TypingGetTestDataLocal:
    """Provides 'known good' metadata for a local release that can be modified."""
    signing_key = get_test_data(
        request, __name__, "567e347ad0044ade55ba8a5f199e2f91fd431d51.gnupg"
    )
    return TypingGetTestDataLocal(
        index_name=request.param.index_name,
        package_channel=request.param.package_channel,
        signature_stores=request.param.signature_stores,
        signing_keys=[signing_key],
    )


@pytest.mark.online
@needs_credentials("registry.redhat.io")
async def test_get_release_metadata(
    known_good_release: TypingGetTestDataLocal,
    registry_v2_proxy: RegistryV2,
):
    """Tests release metadata retrieval from a remote registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # An exception should be raised if the image configuration is not signed
    with pytest.raises(NoSignatureError) as exception:
        await get_release_metadata(
            registry_v2=registry_v2_proxy,
            index_name=known_good_release.index_name,
            package_channel=known_good_release.package_channel,
            signature_stores=known_good_release.signature_stores,
            signing_keys=known_good_release.signing_keys,
        )
    assert str(exception.value) == "Unable to locate a valid signature!"

    # Retrieve the release metadata (which is unsigned from the vendor / community =/ ) ...
    result = await get_release_metadata(
        registry_v2=registry_v2_proxy,
        index_name=known_good_release.index_name,
        package_channel=known_good_release.package_channel,
        signature_stores=known_good_release.signature_stores,
        signing_keys=known_good_release.signing_keys,
        verify=False,
    )

    assert result.index_database is not None
    assert result.manifest_digest
    assert result.operators
    assert result.signature_stores
    assert not result.signatures
    assert result.signing_keys
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
            "registry.redhat.io/ocs4/ocs-operator-bundle@sha256:",
            "ocs-operator.v4.8.8",
            "registry.redhat.io/rhceph/rhceph-4-rhel8@sha256:",
        ),
    ],
)
@needs_credentials("registry.redhat.io")
async def test_log_release_metadata(
    bundle_image: str,
    bundle_name: str,
    caplog: LogCaptureFixture,
    package_channel: Dict[str, str],
    registry_v2_proxy: RegistryV2,
    related_image: str,
    release: str,
):
    # pylint: disable=too-many-arguments
    """Tests logging of release metadata."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata ...
    image_name = ImageName.parse(release)
    result = await get_release_metadata(
        registry_v2=registry_v2_proxy,
        index_name=image_name,
        package_channel=package_channel,
        verify=False,
    )
    assert result

    for sort_metadata in [True, False]:
        await log_release_metadata(
            index_name=image_name, release_metadata=result, sort_metadata=sort_metadata
        )
        assert bundle_image in caplog.text
        assert bundle_name in caplog.text
        assert str(image_name) in caplog.text
        for key in package_channel.keys():
            assert key in caplog.text
        assert related_image in caplog.text


@pytest.mark.online_modification
@needs_credentials("registry.redhat.io")
async def test_put_release_from_internet(
    docker_registry_secure: DockerRegistrySecure,
    known_good_release: TypingGetTestDataLocal,
    registry_v2_proxy: RegistryV2,
):
    """Tests release replication to a local registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata ...
    release_metadata_src = await get_release_metadata(
        registry_v2=registry_v2_proxy,
        index_name=known_good_release.index_name,
        package_channel=known_good_release.package_channel,
        verify=False,
    )

    # Replicate the release ...
    image_name_dest = known_good_release.index_name.clone()
    image_name_dest.endpoint = docker_registry_secure.endpoint_name
    await put_release(
        index_name=image_name_dest,
        registry_v2=registry_v2_proxy,
        release_metadata=release_metadata_src,
        verify=False,
    )

    # Retrieve the release metadata (again) ...
    release_metadata_dest = await get_release_metadata(
        registry_v2=registry_v2_proxy,
        index_name=image_name_dest,
        package_channel=known_good_release.package_channel,
        verify=False,
    )

    # Release metadata should have the index database ...
    assert FormattedSHA256.calculate(
        release_metadata_dest.index_database
    ) == FormattedSHA256.calculate(release_metadata_src.index_database)

    # Release metadata should have the same index name ...
    assert equal_if_unqualified(
        image_name0=release_metadata_src.index_name,
        image_name1=release_metadata_dest.index_name,
    )

    # Release metadata should have the same manifest digest ...
    assert release_metadata_dest.manifest_digest == release_metadata_src.manifest_digest

    # Release metadata should have the same operators listed ...
    assert sorted(
        release_metadata_dest.operators, key=lambda item: item.package
    ) == sorted(release_metadata_src.operators, key=lambda item: item.package)

    # The signature stores should be the same ...
    if release_metadata_src.signature_stores:
        assert (
            release_metadata_dest.signature_stores.sort()
            == release_metadata_src.signature_stores.sort()
        )
    else:
        assert not release_metadata_dest.signature_stores

    # TODO: Do we need to check signatures here?

    # The signing keys should be the same ...
    if release_metadata_src.signing_keys:
        assert (
            release_metadata_dest.signing_keys.sort()
            == release_metadata_src.signing_keys.sort()
        )
    else:
        assert not release_metadata_dest.signing_keys


@pytest.mark.online_modification
@needs_credentials("registry.redhat.io")
async def test_put_release_from_internal(
    docker_registry_secure_list: List[DockerRegistrySecure],
    known_good_release: TypingGetTestDataLocal,
    registry_v2_list_proxy: RegistryV2,
):
    # pylint: disable=too-many-locals
    """Tests release replication to a local registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata (hop 0)...
    image_name0 = known_good_release.index_name.clone()
    release_metadata0 = await get_release_metadata(
        index_name=image_name0,
        package_channel=known_good_release.package_channel,
        registry_v2=registry_v2_list_proxy,
        verify=False,
    )

    # Replicate the release (hop 1)...
    image_name1 = image_name0.clone()
    image_name1.endpoint = docker_registry_secure_list[0].endpoint_name
    await put_release(
        index_name=image_name1,
        registry_v2=registry_v2_list_proxy,
        release_metadata=release_metadata0,
        verify=False,
    )

    # Retrieve the release metadata (hop 1) ...
    release_metadata1 = await get_release_metadata(
        index_name=image_name1,
        package_channel=known_good_release.package_channel,
        registry_v2=registry_v2_list_proxy,
        verify=False,
    )

    # Translate to the second registry ...
    regex_substitutions = [
        TypingRegexSubstitution(
            pattern=r"quay\.io",
            replacement=docker_registry_secure_list[0].endpoint_name,
        ),
        TypingRegexSubstitution(
            pattern=r"registry\.redhat\.io",
            replacement=docker_registry_secure_list[0].endpoint_name,
        ),
    ]
    release_metadata1_translated = await translate_release_metadata(
        regex_substitutions=regex_substitutions, release_metadata=release_metadata1
    )

    # TODO: We need to implement "signing" here, and test with verify=True below ...

    # Replicate the release (hop 2) ...
    image_name2 = image_name0.clone()
    image_name2.endpoint = docker_registry_secure_list[1].endpoint_name
    await put_release(
        index_name=image_name2,
        registry_v2=registry_v2_list_proxy,
        release_metadata=release_metadata1_translated,
        verify=False,
    )

    # Retrieve the release metadata (hop 2) ...
    release_metadata2 = await get_release_metadata(
        index_name=image_name2,
        package_channel=known_good_release.package_channel,
        registry_v2=registry_v2_list_proxy,
        verify=False,
    )

    # Release metadata should have the index database ...
    assert FormattedSHA256.calculate(
        release_metadata2.index_database
    ) == FormattedSHA256.calculate(release_metadata0.index_database)

    # Release metadata should have the same index name ...
    assert equal_if_unqualified(
        image_name0=release_metadata0.index_name,
        image_name1=release_metadata2.index_name,
    )

    # Release metadata should have the same manifest digest ...
    assert release_metadata2.manifest_digest == release_metadata0.manifest_digest

    # Release metadata should have the same operators listed ...
    assert sorted(release_metadata2.operators, key=lambda item: item.package) == sorted(
        release_metadata0.operators, key=lambda item: item.package
    )

    # The signature stores should be the same ...
    if release_metadata0.signature_stores:
        assert (
            release_metadata2.signature_stores.sort()
            == release_metadata0.signature_stores.sort()
        )
    else:
        assert not release_metadata2.signature_stores

    # TODO: Do we need to check signatures here?

    # The signing keys should be the same ...
    if release_metadata0.signing_keys:
        assert (
            release_metadata2.signing_keys.sort()
            == release_metadata0.signing_keys.sort()
        )
    else:
        assert not release_metadata2.signing_keys
