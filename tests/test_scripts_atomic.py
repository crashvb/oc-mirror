#!/usr/bin/env python

# pylint: disable=redefined-outer-name,too-many-arguments,unused-import

"""CLI tests."""

import logging
import json
import os

from contextlib import contextmanager
from pathlib import Path
from time import time
from tempfile import NamedTemporaryFile

import certifi
import pytest

from docker_registry_client_async import DockerRegistryClientAsync, ImageName
from docker_sign_verify import FormattedSHA256
from pytest_docker_apache_fixtures import ApacheSecure
from pytest_gnupg_fixtures import GnuPGKeypair
from _pytest.logging import LogCaptureFixture
from _pytest.tmpdir import TempPathFactory

from oc_mirror.scripts.atomic import cli

LOGGER = logging.getLogger(__name__)


@contextmanager
def drca_cacerts(path: Path):
    """Context manager to globally define the DRCA CA trust store."""
    key = "DRCA_CACERTS"
    old = os.environ.get(key, None)

    tmpfile = NamedTemporaryFile()
    tmpfile.write(path.read_bytes())
    tmpfile.write(Path(certifi.where()).read_bytes())
    tmpfile.flush()

    os.environ[key] = tmpfile.name
    yield None
    if old is not None:
        os.environ[key] = old
    else:
        del os.environ[key]

    tmpfile.close()


@contextmanager
def drca_credentials_store(apache_secure: ApacheSecure):
    """
    Context manager to globally define the DRCA credentials store.

    Args:
        apache_secure: The secure apache from which to retrieve the credentials.

    Yields:
        The path to the DRCA credentials store.
    """
    key = "DRCA_CREDENTIALS_STORE"
    old = os.environ.get(key, None)

    auth = apache_secure.auth_header["Authorization"].split()[1]
    credentials = {"auths": {f"https://{apache_secure.endpoint}": {"auth": auth}}}
    tmpfile = NamedTemporaryFile()
    tmpfile.write(json.dumps(credentials).encode("utf-8"))
    tmpfile.flush()

    os.environ[key] = str(tmpfile.name)
    yield None
    if old is not None:
        os.environ[key] = old
    else:
        del os.environ[key]
    tmpfile.close()


@contextmanager
def gnupghome(path: Path):
    """Context manager to globally define the GnuPG home directory."""
    key = "GNUPGHOME"
    old = os.environ.get(key, None)
    os.environ[key] = str(path)
    yield None
    if old is not None:
        os.environ[key] = old
    else:
        del os.environ[key]


def test_empty_args(clirunner):
    """Test atomic CLI can be invoked."""
    for command in ["sign", "verify"]:
        result = clirunner.invoke(cli, [command], catch_exceptions=False)
        assert "Usage:" in result.stdout
        assert result.exit_code != 0


@pytest.mark.online
def test_sign_bad_keyid(
    caplog: LogCaptureFixture,
    gnupg_keypair: GnuPGKeypair,
    runner,
    tmp_path_factory: TempPathFactory,
):
    """Test atomic can handle invalid keyids."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image_name = ImageName.parse(f"foo/bar:{__name__}")
    image_name.digest = FormattedSHA256.calculate(
        f"random_value: {time()}".encode(encoding="utf-8")
    )
    gnupg_home = tmp_path_factory.mktemp(__name__)
    with gnupghome(gnupg_home):
        result = runner.invoke(
            cli,
            args=[
                "sign",
                "--keyid",
                "invalidkeyid",
                "--keypass",
                gnupg_keypair.passphrase,
                str(image_name),
            ],
        )
        assert isinstance(result.exception, SystemExit)
        assert (
            f"Unable to create new signature for digest: {image_name.digest}"
            in caplog.text
        )
        assert "Signature stored." not in caplog.text
        assert f"/sha256={image_name.digest.sha256}/signature-" not in caplog.text


@pytest.mark.online
def test_verify_no_signatures(
    apache_secure: ApacheSecure,
    caplog: LogCaptureFixture,
    runner,
):
    """Test atomic can operate on images without existing signatures."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image_name = ImageName.parse(f"foo/bar:{__name__}")
    image_name.digest = FormattedSHA256.calculate(
        f"random_value: {time()}".encode(encoding="utf-8")
    )
    with drca_credentials_store(apache_secure), drca_cacerts(apache_secure.cacerts):
        result = runner.invoke(
            cli,
            args=[
                f"--signature-store=https://{apache_secure.endpoint}",
                "verify",
                str(image_name),
            ],
        )
    assert isinstance(result.exception, SystemExit)
    assert "Unable to locate a valid signature" in caplog.text
    assert "Verified" not in caplog.text
    assert str(image_name) in caplog.text


@pytest.mark.online_modification
def test_verify_not_found(
    apache_secure: ApacheSecure,
    caplog: LogCaptureFixture,
    runner,
):
    """Test atomic can handle incorrect image names."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image_name = ImageName.parse(f"{apache_secure.endpoint}/foo/bar:{__name__}")
    with drca_credentials_store(apache_secure), drca_cacerts(apache_secure.cacerts):
        result = runner.invoke(
            cli,
            args=[
                f"--signature-store=https://{apache_secure.endpoint}",
                "verify",
                str(image_name),
            ],
        )
        assert isinstance(result.exception, SystemExit)
        assert "404" in caplog.text
        assert "Not Found" in caplog.text
        assert str(image_name) in caplog.text


@pytest.mark.online
def test_verify_signed(
    apache_secure: ApacheSecure,
    caplog: LogCaptureFixture,
    gnupg_keypair: GnuPGKeypair,
    runner,
):
    """Test atomic can handle signed images."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image_name = ImageName.parse(f"foo/bar:{__name__}")
    image_name.digest = FormattedSHA256.calculate(
        f"random_value: {time()}".encode(encoding="utf-8")
    )
    for signature_type in ["image-config", "manifest"]:
        with drca_credentials_store(apache_secure), drca_cacerts(
            apache_secure.cacerts
        ), gnupghome(gnupg_keypair.gnupg_home):
            result = runner.invoke(
                cli,
                args=[
                    f"--signature-store=https://{apache_secure.endpoint}",
                    f"--signature-type={signature_type}",
                    "sign",
                    "--keyid",
                    str(gnupg_keypair.keyid),
                    "--keypass",
                    gnupg_keypair.passphrase,
                    str(image_name),
                ],
            )
            assert not result.exception
            assert "Signature stored." in caplog.text
            assert (
                f"https://{apache_secure.endpoint}/sha256={image_name.digest.sha256}/signature-"
                in caplog.text
            )

            caplog.clear()

            result = runner.invoke(
                cli,
                args=[
                    f"--signature-store=https://{apache_secure.endpoint}",
                    f"--signature-type={signature_type}",
                    "verify",
                    str(image_name),
                ],
            )
            assert not result.exception
            assert (
                f"https://{apache_secure.endpoint}/sha256={image_name.digest.sha256}/signature-"
                in caplog.text
            )
            assert "Signature matches:" in caplog.text
            assert "Signature is compliant:" in caplog.text


@pytest.mark.online
def test_verify_unauthorized(
    apache_secure: ApacheSecure,
    caplog: LogCaptureFixture,
    runner,
):
    """Test atomic can handle incorrect credentials."""
    caplog.clear()
    caplog.set_level(logging.DEBUG)

    image_name = ImageName.parse(f"foo/bar:{__name__}")
    image_name.digest = FormattedSHA256.calculate(
        f"random_value: {time()}".encode(encoding="utf-8")
    )

    # Note: Not using apache_secure_credentials().
    with drca_cacerts(apache_secure.cacerts):
        result = runner.invoke(
            cli,
            args=[
                f"--signature-store=https://{apache_secure.endpoint}",
                "verify",
                str(image_name),
            ],
        )
        assert isinstance(result.exception, SystemExit)
        assert "Unable to locate a valid signature!" in caplog.text
        assert str(image_name) in caplog.text
