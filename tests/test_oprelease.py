#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Operator release tests."""

import logging

from re import compile
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
    TypingOperatorMetadata,
    TypingRegexSubstitution,
)
from oc_mirror.utils import DEFAULT_TRANSLATION_PATTERNS

from .testutils import equal_if_unqualified, get_test_data, needs_credentials

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


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
    registry_v2: RegistryV2,
):
    """Tests release metadata retrieval from a remote registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # An exception should be raised if the image configuration is not signed
    with pytest.raises(NoSignatureError) as exception:
        await get_release_metadata(
            registry_v2=registry_v2,
            index_name=known_good_release.index_name,
            package_channel=known_good_release.package_channel,
            signature_stores=known_good_release.signature_stores,
            signing_keys=known_good_release.signing_keys,
        )
    assert str(exception.value) == "Unable to locate a valid signature!"

    # Retrieve the release metadata (which is unsigned from the vendor / community =/ ) ...
    result = await get_release_metadata(
        registry_v2=registry_v2,
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
@needs_credentials("registry.redhat.io")
async def test_log_release_metadata(
    known_good_release: TypingGetTestDataLocal,
    caplog: LogCaptureFixture,
    registry_v2: RegistryV2,
):
    """Tests logging of release metadata."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata ...
    result = await get_release_metadata(
        registry_v2=registry_v2,
        index_name=known_good_release.index_name,
        package_channel=known_good_release.package_channel,
        signature_stores=known_good_release.signature_stores,
        signing_keys=known_good_release.signing_keys,
        verify=False,
    )
    assert result

    for sort_metadata in [True, False]:
        await log_release_metadata(
            index_name=known_good_release.index_name,
            release_metadata=result,
            sort_metadata=sort_metadata,
        )
        assert str(result.index_name) in caplog.text
        for operator in result.operators:
            assert operator.bundle in caplog.text
            assert operator.channel in caplog.text
            for image in operator.images:
                assert str(image) in caplog.text
            assert operator.package in caplog.text


@pytest.mark.online_modification
@needs_credentials("registry.redhat.io")
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
    image_name_dest = known_good_release.index_name.clone().set_endpoint(
        docker_registry_secure.endpoint
    )
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
    registry_v2_list: RegistryV2,
):
    # pylint: disable=too-many-locals
    """Tests release replication to a local registry."""
    logging.getLogger("gnupg").setLevel(logging.FATAL)

    # Retrieve the release metadata (hop 0)...
    image_name0 = known_good_release.index_name.clone()
    release_metadata0 = await get_release_metadata(
        index_name=image_name0,
        package_channel=known_good_release.package_channel,
        registry_v2=registry_v2_list,
        verify=False,
    )

    # Replicate the release (hop 1)...
    image_name1 = image_name0.clone().set_endpoint(
        docker_registry_secure_list[0].endpoint
    )
    await put_release(
        index_name=image_name1,
        registry_v2=registry_v2_list,
        release_metadata=release_metadata0,
        verify=False,
    )

    # Retrieve the release metadata (hop 1), translate to the second registry ...
    regex_substitutions = [
        TypingRegexSubstitution(
            pattern=compile(pattern),
            replacement=docker_registry_secure_list[0].endpoint,
        )
        for pattern in DEFAULT_TRANSLATION_PATTERNS
    ]
    release_metadata1 = await get_release_metadata(
        index_name=image_name1,
        package_channel=known_good_release.package_channel,
        regex_substitutions=regex_substitutions,
        registry_v2=registry_v2_list,
        verify=False,
    )

    # TODO: We need to implement "signing" here, and test with verify=True below ...

    # Replicate the release (hop 2) ...
    image_name2 = image_name0.clone().set_endpoint(
        docker_registry_secure_list[1].endpoint
    )
    await put_release(
        index_name=image_name2,
        registry_v2=registry_v2_list,
        release_metadata=release_metadata1,
        verify=False,
    )

    # Retrieve the release metadata (hop 2), translate to the third registry ...
    regex_substitutions = [
        TypingRegexSubstitution(
            pattern=compile(
                docker_registry_secure_list[0].endpoint.replace(".", "\\.")
            ),
            replacement=docker_registry_secure_list[1].endpoint,
        )
    ]
    release_metadata2 = await get_release_metadata(
        index_name=image_name2,
        package_channel=known_good_release.package_channel,
        regex_substitutions=regex_substitutions,
        registry_v2=registry_v2_list,
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

    # Convert operators to use unqualified image names ...
    release_metadata0_operators = [
        TypingOperatorMetadata(
            bundle=o.bundle,
            channel=o.channel,
            images=[image_name.clone().set_endpoint() for image_name in o.images],
            package=o.package,
        )
        for o in release_metadata0.operators
    ]
    release_metadata2_operators = [
        TypingOperatorMetadata(
            bundle=o.bundle,
            channel=o.channel,
            images=[image_name.clone().set_endpoint() for image_name in o.images],
            package=o.package,
        )
        for o in release_metadata2.operators
    ]

    # Release metadata should have the same operators listed ...
    assert sorted(release_metadata2_operators, key=lambda item: item.package) == sorted(
        release_metadata0_operators, key=lambda item: item.package
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
