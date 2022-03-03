#!/usr/bin/env python

# pylint: disable=protected-access,redefined-outer-name

"""GPGSigner tests."""

import asyncio
import logging

from ssl import create_default_context
from time import time
from typing import Generator

import pytest

from aiohttp.helpers import BasicAuth
from docker_registry_client_async import (
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
)
from docker_sign_verify import GPGTrust
from pytest_docker_apache_fixtures import ApacheSecure
from pytest_gnupg_fixtures import GnuPGKeypair
from pytest_docker_squid_fixtures import SquidSecure

from oc_mirror import AtomicSigner

pytestmark = [pytest.mark.asyncio]

LOGGER = logging.getLogger(__name__)

# Bug Fix: https://github.com/crashvb/docker-registry-client-async/issues/24
#
# Right now this is known to leave a nasty "Fatal error on SSL transport" error
# at the end of the test execution; however, without this we cannot test using
# a TLS-in-TLS proxy ...
setattr(asyncio.sslproto._SSLProtocolTransport, "_start_tls_compatible", True)


@pytest.fixture
async def docker_registry_client_async_proxy(
    apache_secure: ApacheSecure, squid_secure: SquidSecure
) -> Generator[DockerRegistryClientAsync, None, None]:
    """Provides a DockerRegistryClientAsync instance."""
    ssl_context = create_default_context(
        cadata=squid_secure.certs.ca_certificate.read_text("utf-8")
        + apache_secure.certs.ca_certificate.read_text("utf-8")
    )
    # Do not use caching; get a new instance for each test
    async with DockerRegistryClientAsync(
        ssl=ssl_context
    ) as docker_registry_client_async:
        credentials = apache_secure.auth_header["Authorization"].split()[1]
        for name in [
            apache_secure.endpoint,
            apache_secure.endpoint_name,
        ]:
            await docker_registry_client_async.add_credentials(name, credentials)
        docker_registry_client_async.proxies[
            "https"
        ] = f"https://{squid_secure.endpoint}/"
        docker_registry_client_async.proxy_auth = BasicAuth(
            login=squid_secure.username, password=squid_secure.password
        )

        yield docker_registry_client_async


@pytest.fixture()
def signaturestore_proxy(apache_secure: ApacheSecure) -> str:
    """Provides a modifiable signature store location."""
    return f"https://{apache_secure.endpoint_name}"


@pytest.fixture()
def atomicsigner_proxy(
    docker_registry_client_async_proxy: DockerRegistryClientAsync,
    gnupg_keypair: GnuPGKeypair,
    signaturestore_proxy: str,
) -> AtomicSigner:
    """Provides AtomicSigner instances."""
    return AtomicSigner(
        docker_registry_client_async=docker_registry_client_async_proxy,
        homedir=gnupg_keypair.gnupg_home,
        keyid=gnupg_keypair.fingerprints[1],
        locations=[signaturestore_proxy],
        passphrase=gnupg_keypair.passphrase,
    )


# TODO: Add tests for protected methods ...


async def test_simple(atomicsigner_proxy: AtomicSigner, gnupg_keypair: GnuPGKeypair):
    """Test configuration signing and verification using GPG."""
    digest = FormattedSHA256.calculate(f"TEST DATA: {time()}".encode(encoding="utf-8"))
    image_name = ImageName.parse(f"foo/bar:{time()}")
    LOGGER.debug("Test Data:\n  digest     : %s\n  image name : %s", digest, image_name)

    # Generate a signature for the test data ...
    find_all_signatures = await atomicsigner_proxy.atomicsign(
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
    results = await atomicsigner_proxy.atomicverify(
        digest=digest, image_name=image_name
    )
    assert results
    for result in results:
        assert result.fingerprint == atomicsigner_proxy.keyid
        assert atomicsigner_proxy.keyid.endswith(result.key_id)
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
async def test_bad_data(atomicsigner_proxy: AtomicSigner, gnupg_keypair: GnuPGKeypair):
    """Test configuration signing and verification using GPG with bad data."""
    digest = FormattedSHA256.calculate(f"TEST DATA: {time()}".encode(encoding="utf-8"))
    image_name = ImageName.parse(f"foo/bar:{time()}")
    LOGGER.debug("Test Data:\n  digest     : %s\n  image name : %s", digest, image_name)

    # Generate a signature for the test data ...
    find_all_signatures = await atomicsigner_proxy.atomicsign(
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
    results = await atomicsigner_proxy.atomicverify(
        digest=digest, image_name=image_name
    )
    assert results
    for result in results:
        assert result.fingerprint is None
        assert atomicsigner_proxy.keyid.endswith(result.key_id)
        assert "failed" not in result.signer_long
        assert "failed" not in result.signer_short
        assert result.status_atomic is not None
        assert result.status_gpg != "signature valid"
        assert result.timestamp is None
        assert result.trust == GPGTrust.UNDEFINED.value
        assert result.type == "gpg"
        assert result.username == gnupg_keypair.uids[0]
        assert not result.valid
