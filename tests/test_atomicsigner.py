#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""GPGSigner tests."""

import logging

from time import time
from typing import Generator

import pytest

from docker_registry_client_async import (
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
)
from docker_sign_verify import GPGTrust
from pytest_docker_apache_fixtures import ApacheSecure
from pytest_gnupg_fixtures import GnuPGKeypair

from oc_mirror import AtomicSigner

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)


@pytest.fixture
async def docker_registry_client_async(
    apache_secure: ApacheSecure,
) -> Generator[DockerRegistryClientAsync, None, None]:
    """Provides a DockerRegistryClientAsync instance."""
    # Do not use caching; get a new instance for each test
    async with DockerRegistryClientAsync(
        ssl=apache_secure.ssl_context
    ) as docker_registry_client_async:
        credentials = apache_secure.auth_header["Authorization"].split()[1]
        await docker_registry_client_async.add_credentials(
            f"https://{apache_secure.endpoint}", credentials
        )
        yield docker_registry_client_async


@pytest.fixture()
def signaturestore(apache_secure: ApacheSecure) -> str:
    """Provides a modifiable signature store location."""
    return f"https://{apache_secure.endpoint}"


@pytest.fixture()
def atomicsigner(
    docker_registry_client_async: DockerRegistryClientAsync,
    gnupg_keypair: GnuPGKeypair,
    signaturestore: str,
) -> AtomicSigner:
    """Provides AtomicSigner instances."""
    return AtomicSigner(
        docker_registry_client_async=docker_registry_client_async,
        homedir=gnupg_keypair.gnupg_home,
        keyid=gnupg_keypair.fingerprints[1],
        locations=[signaturestore],
        passphrase=gnupg_keypair.passphrase,
    )


# TODO: Add tests for protected methods ...


async def test_simple(atomicsigner: AtomicSigner, gnupg_keypair: GnuPGKeypair):
    """Test configuration signing and verification using GPG."""
    digest = FormattedSHA256.calculate(f"TEST DATA: {time()}".encode(encoding="utf-8"))
    image_name = ImageName.parse(f"foo/bar:{time()}")
    LOGGER.debug("Test Data:\n  digest     : %s\n  image name : %s", digest, image_name)

    # Generate a signature for the test data ...
    find_all_signatures = await atomicsigner.atomicsign(
        digest=digest, image_name=image_name
    )
    assert find_all_signatures
    assert find_all_signatures.index
    assert find_all_signatures.signature
    assert find_all_signatures.url
    assert all(
        (
            value in find_all_signatures.url
            for value in ["https", digest.replace(":", "="), "signature-"]
        )
    )

    # Verify the generated signature against the test data ...
    results = await atomicsigner.atomicverify(digest=digest, image_name=image_name)
    assert results
    for result in results:
        assert result.fingerprint == atomicsigner.keyid
        assert atomicsigner.keyid.endswith(result.key_id)
        assert "failed" not in result.signer_long
        assert "failed" not in result.signer_short
        assert result.status_atomic is None
        assert result.status_gpg == "signature valid"
        assert result.timestamp
        assert result.trust == GPGTrust.ULTIMATE.value
        assert result.type == "atomicsigner"
        assert result.username == gnupg_keypair.uids[0]
        assert result.valid


@pytest.mark.skip("Test scenario not defined.")
async def test_bad_data(atomicsigner: AtomicSigner, gnupg_keypair: GnuPGKeypair):
    """Test configuration signing and verification using GPG with bad data."""
    digest = FormattedSHA256.calculate(f"TEST DATA: {time()}".encode(encoding="utf-8"))
    image_name = ImageName.parse(f"foo/bar:{time()}")
    LOGGER.debug("Test Data:\n  digest     : %s\n  image name : %s", digest, image_name)

    # Generate a signature for the test data ...
    find_all_signatures = await atomicsigner.atomicsign(
        digest=digest, image_name=image_name
    )
    assert find_all_signatures
    assert find_all_signatures.index
    assert find_all_signatures.signature
    assert find_all_signatures.url
    assert all(
        (
            value in find_all_signatures.url
            for value in ["https", digest.replace(":", "="), "signature-"]
        )
    )

    # TODO: How to tamper with the data (e.g. produce and stage a signature with a mismatched digest)?

    # Verify the generated signature against the test data ...
    results = await atomicsigner.atomicverify(digest=digest, image_name=image_name)
    assert results
    for result in results:
        assert result.fingerprint is None
        assert atomicsigner.keyid.endswith(result.key_id)
        assert "failed" not in result.signer_long
        assert "failed" not in result.signer_short
        assert result.status_atomic is not None
        assert result.status_gpg != "signature valid"
        assert result.timestamp is None
        assert result.trust == GPGTrust.UNDEFINED.value
        assert result.type == "gpg"
        assert result.username == gnupg_keypair.uids[0]
        assert not result.valid
