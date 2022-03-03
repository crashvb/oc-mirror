#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""Configures execution of pytest."""

from ssl import create_default_context
from typing import Generator, List

import certifi
import pytest

from aiohttp.helpers import BasicAuth
from click.testing import CliRunner
from docker_sign_verify import RegistryV2
from pytest_asyncio.plugin import Mode
from pytest_docker_registry_fixtures import DockerRegistrySecure
from pytest_docker_squid_fixtures import SquidSecure

from .testutils import OCMCliRunner


def pytest_addoption(parser):
    """pytest add option."""
    parser.addoption(
        "--allow-online",
        action="store_true",
        default=False,
        help="Allow execution of online tests.",
    )
    parser.addoption(
        "--allow-online-modification",
        action="store_true",
        default=False,
        help="Allow modification of online content (implies --allow-online).",
    )


def pytest_collection_modifyitems(config, items):
    """pytest collection modifier."""

    skip_online = pytest.mark.skip(
        reason="Execution of online tests requires --allow-online option."
    )
    skip_online_modification = pytest.mark.skip(
        reason="Modification of online content requires --allow-online-modification option."
    )
    for item in items:
        if "online_modification" in item.keywords and not config.getoption(
            "--allow-online-modification"
        ):
            item.add_marker(skip_online_modification)
        elif (
            "online" in item.keywords
            and not config.getoption("--allow-online")
            and not config.getoption("--allow-online-modification")
        ):
            item.add_marker(skip_online)


def pytest_configure(config):
    """pytest configuration hook."""
    config.addinivalue_line("markers", "online: allow execution of online tests.")
    config.addinivalue_line(
        "markers", "online_modification: allow modification of online content."
    )

    config.option.asyncio_mode = Mode.AUTO


@pytest.fixture(scope="session")
def pdrf_scale_factor() -> int:
    """Scale PDRF to 2."""
    return 2


@pytest.fixture(scope="session")
def pdsf_scale_factor() -> int:
    """Scale PDSF to 2."""
    return 2


@pytest.fixture
def clirunner() -> Generator[CliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = CliRunner()
    with runner.isolated_filesystem():
        yield runner


# TODO: What is the best way to code `DRCA_DEBUG=1 DRCA_CREDENTIALS_STORE=~/.docker/quay.io-pull-secret.json` into
#       this fixture?
@pytest.fixture
async def registry_v2(
    docker_registry_secure: DockerRegistrySecure,
) -> RegistryV2:
    """Provides a RegistryV2 instance."""
    # Do not use caching; get a new instance for each test
    ssl_context = docker_registry_secure.ssl_context
    ssl_context.load_verify_locations(cafile=certifi.where())
    async with RegistryV2(ssl=ssl_context) as registry_v2:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        await registry_v2.docker_registry_client_async.add_credentials(
            docker_registry_secure.endpoint, credentials
        )

        yield registry_v2


@pytest.fixture
async def registry_v2_proxy(
    docker_registry_secure: DockerRegistrySecure, squid_secure: SquidSecure
) -> RegistryV2:
    """Provides a RegistryV2 instance."""
    ssl_context = create_default_context(
        cadata=squid_secure.certs.ca_certificate.read_text("utf-8")
        + docker_registry_secure.certs.ca_certificate.read_text("utf-8")
    )
    ssl_context.load_verify_locations(cafile=certifi.where())
    # Do not use caching; get a new instance for each test
    async with RegistryV2(ssl=ssl_context) as registry_v2_proxy:
        credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
        for name in [
            docker_registry_secure.endpoint,
            docker_registry_secure.endpoint_name,
        ]:
            await registry_v2_proxy.docker_registry_client_async.add_credentials(
                name, credentials
            )
        registry_v2_proxy.docker_registry_client_async.proxies[
            "https"
        ] = f"https://{squid_secure.endpoint}/"
        registry_v2_proxy.docker_registry_client_async.proxy_auth = BasicAuth(
            login=squid_secure.username, password=squid_secure.password
        )

        yield registry_v2_proxy


@pytest.fixture
async def registry_v2_list(
    docker_registry_secure_list: List[DockerRegistrySecure],
) -> RegistryV2:
    """Provides a RegistryV2 instance."""
    # Do not use caching; get a new instance for each test
    ssl_context = create_default_context(cafile=certifi.where())
    for docker_registry_secure in docker_registry_secure_list:
        ssl_context.load_verify_locations(cafile=str(docker_registry_secure.cacerts))
    async with RegistryV2(ssl=ssl_context) as registry_v2:
        for docker_registry_secure in docker_registry_secure_list:
            credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
            await registry_v2.docker_registry_client_async.add_credentials(
                docker_registry_secure.endpoint, credentials
            )

        yield registry_v2


@pytest.fixture
async def registry_v2_list_proxy(
    docker_registry_secure_list: List[DockerRegistrySecure],
    squid_secure_list: List[SquidSecure],
) -> RegistryV2:
    """Provides a RegistryV2 instance."""
    ssl_context = create_default_context(cafile=certifi.where())
    for docker_registry_secure in docker_registry_secure_list:
        ssl_context.load_verify_locations(cafile=str(docker_registry_secure.cacerts))
    for squid_secure in squid_secure_list:
        ssl_context.load_verify_locations(cafile=str(squid_secure.cacerts))
    # Do not use caching; get a new instance for each test
    async with RegistryV2(ssl=ssl_context) as registry_v2_proxy:
        for docker_registry_secure in docker_registry_secure_list:
            credentials = docker_registry_secure.auth_header["Authorization"].split()[1]
            for name in [
                docker_registry_secure.endpoint,
                docker_registry_secure.endpoint_name,
            ]:
                await registry_v2_proxy.docker_registry_client_async.add_credentials(
                    name, credentials
                )
        for squid_secure in squid_secure_list:
            registry_v2_proxy.docker_registry_client_async.proxies[
                "https"
            ] = f"https://{squid_secure.endpoint}/"
            registry_v2_proxy.docker_registry_client_async.proxy_auth = BasicAuth(
                login=squid_secure.username, password=squid_secure.password
            )

        yield registry_v2_proxy


@pytest.fixture
def runner() -> Generator[OCMCliRunner, None, None]:
    """Provides a runner for testing click command line interfaces."""
    runner = OCMCliRunner()
    with runner.isolated_filesystem():
        yield runner
