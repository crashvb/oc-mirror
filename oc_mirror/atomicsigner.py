#!/usr/bin/env python

"""Classes that provide signature functionality."""

import logging

from pathlib import Path
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse

import aiofiles

from aiohttp.client import _RequestContextManager
from aiohttp.typedefs import LooseHeaders
from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import (
    DockerRegistryClientAsync,
    FormattedSHA256,
    ImageName,
)
from docker_sign_verify import (
    DigestMismatchError,
    GPGSigner,
    GPGStatus,
    GPGTrust,
    SignatureMismatchError,
)

from .atomicsignature import AtomicSignature

LOGGER = logging.getLogger(__name__)


class AtomicSignerVerify(NamedTuple):
    # pylint: disable=missing-class-docstring
    atomic_signature: AtomicSignature
    fingerprint: str
    key_id: str
    signer_long: Optional[str]
    signer_short: Optional[str]
    status_atomic: Optional[ValueError]
    status_gpg: str
    timestamp: str
    trust: str
    type: str
    username: str
    valid: bool


class FindAllSignatures(NamedTuple):
    # pylint: disable=missing-class-docstring
    index: int
    signature: bytes
    url: str


async def get_request_headers(*, headers: LooseHeaders = None) -> LooseHeaders:
    """
    Generates request headers that contain the user agent identifier.

    Args:
        headers: Optional supplemental request headers to be returned.

    Returns:
        The generated request headers.
    """
    if not headers:
        headers = {}

    if "User-Agent" not in headers:
        # Note: This cannot be imported above, as it causes a circular import!
        from . import __version__  # pylint: disable=import-outside-toplevel

        headers["User-Agent"] = f"oc-mirror/{__version__}"

    return headers


class AtomicSigner(GPGSigner):
    """Creates and verifies atomic signatures using GnuPG."""

    def __init__(
        self,
        *,
        docker_registry_client_async: DockerRegistryClientAsync,
        homedir: Path = None,
        keyid: str = None,
        locations: List[str] = None,
        passphrase: str = None,
    ):
        """
        Args:
            docker_registry_client_async: The underlying DockerRegistryClientAsync object.
            homedir: The GPG home directory (default: ~/.gnupg).
            keyid: The GPG key identifier, only required for signing.
            passphrase: The passphrase used to unlock the GPG key.
            locations: The signature store locations used to retrieve signatures.
        """
        super().__init__(homedir=homedir, keyid=keyid, passphrase=passphrase)

        self.docker_registry_client_async = docker_registry_client_async
        self.locations = locations if locations is not None else []

        LOGGER.debug("Using signature stores:")
        for location in locations:
            LOGGER.debug("  %s", location)

    async def _find_all_signatures(
        self, *, digest: FormattedSHA256, location: str
    ) -> List[FindAllSignatures]:
        # pylint: disable=protected-access
        """Retrieves the all signatures corresponding to a given digest from a signature store."""
        result = []
        client_session = await self.docker_registry_client_async._get_client_session()
        headers = await self._get_headers(endpoint=location)
        proxy = await self._get_proxy(location=location)
        index = 0
        while True:
            index = index + 1
            url = f"{location}/sha256={digest.sha256}/signature-{index}"
            LOGGER.debug("Retrieving signature: %s ...", url)
            response = await client_session.get(
                headers=headers,
                proxy=proxy,
                proxy_auth=self.docker_registry_client_async.proxy_auth,
                ssl=self.docker_registry_client_async.ssl,
                url=url,
            )
            if response.status > 400:
                break
            LOGGER.debug("Signature retrieved.")
            result.append(
                FindAllSignatures(index=index, signature=await response.read(), url=url)
            )
        return result

    async def _get_headers(self, *, endpoint: str) -> LooseHeaders:
        # pylint: disable=protected-access
        """Retrieves headers for remote requests."""
        url_segments = urlparse(endpoint)
        for i in [
            url_segments.netloc,
            f"{url_segments.scheme}://{url_segments.netloc}",
            f"{url_segments.scheme}://{url_segments.netloc}/",
            f"{url_segments.netloc}:{url_segments.port}",
            f"{url_segments.scheme}://{url_segments.netloc}:{url_segments.port}",
            f"{url_segments.scheme}://{url_segments.netloc}:{url_segments.port}/",
        ]:
            credentials = await self.docker_registry_client_async._get_credentials(
                endpoint=i
            )
            if credentials:
                break
        headers = await get_request_headers()
        if credentials:
            headers["Authorization"] = f"Basic {credentials}"
        return headers

    async def _get_proxy(self, *, location: str) -> Optional[str]:
        # pylint: disable=protected-access
        """
        Retrieves the proxy configuration for a given location.

        Args:
            location: The location for which to retrieve the proxy configuration.
        """
        url_segments = urlparse(location)
        proxy = await self.docker_registry_client_async._get_proxy(
            endpoint=url_segments.netloc, protocol=url_segments.scheme.lower()
        )
        return proxy

    async def _make_collection(self, *, digest: FormattedSHA256, location: str):
        # pylint: disable=protected-access
        """Creates a remote collection (directory), if needed, for a given digest."""
        client_session = await self.docker_registry_client_async._get_client_session()
        headers = await self._get_headers(endpoint=location)
        proxy = await self._get_proxy(location=location)
        url = f"{location}/sha256={digest.sha256}"
        response = await client_session.get(
            headers=headers,
            proxy=proxy,
            proxy_auth=self.docker_registry_client_async.proxy_auth,
            ssl=self.docker_registry_client_async.ssl,
            url=url,
        )
        if response.status < 400:
            return
        LOGGER.debug("Creating collection: %s ...", url)
        await _RequestContextManager(
            client_session._request(
                allow_redirects=True,
                headers=headers,
                method="MKCOL",
                proxy=proxy,
                proxy_auth=self.docker_registry_client_async.proxy_auth,
                raise_for_status=True,
                ssl=self.docker_registry_client_async.ssl,
                str_or_url=url,
            )
        )
        LOGGER.debug("Collection created.")

    async def _store_signature(
        self, *, digest: FormattedSHA256, location: str = None, signature: bytes
    ) -> FindAllSignatures:
        # pylint: disable=protected-access
        """Replicates a given signature to a remote signature store."""
        if location is None:
            location = self.locations[0]

        signatures = await self._find_all_signatures(digest=digest, location=location)
        index = signatures[-1].index + 1 if signatures else 1
        url = f"{location}/sha256={digest.sha256}/signature-{index}"

        await self._make_collection(digest=digest, location=location)

        LOGGER.debug("Storing signature: %s ...", url)
        client_session = await self.docker_registry_client_async._get_client_session()
        headers = await self._get_headers(endpoint=location)
        proxy = await self._get_proxy(location=location)
        await client_session.put(
            data=signature,
            headers=headers,
            proxy=proxy,
            proxy_auth=self.docker_registry_client_async.proxy_auth,
            raise_for_status=True,
            ssl=self.docker_registry_client_async.ssl,
            url=url,
        )
        LOGGER.debug("Signature stored.")
        return FindAllSignatures(index=index, signature=signature, url=url)

    @staticmethod
    async def _verify_atomic_signature(
        *,
        atomic_signature: AtomicSignature,
        digest: FormattedSHA256,
        image_name: ImageName,
    ) -> Optional[ValueError]:
        """
        Verifies an atomic signature against a given digest and image name.
        pkg/verify/verify.go:382: - verifyAtomicContainerSignature()
        """
        if atomic_signature.get_type() != AtomicSignature.TYPE:
            return SignatureMismatchError("Signature is not the correct type!")
        # TODO: Actually make use of the provided image_name ...
        if len(atomic_signature.get_docker_reference().image) < 1:
            return SignatureMismatchError("Signature must have an identity!")
        if atomic_signature.get_docker_manifest_digest() != digest:
            return DigestMismatchError("Signature digest does not match!")
        return None

    async def atomicsign(
        self, *, digest: FormattedSHA256, image_name: ImageName
    ) -> Optional[FindAllSignatures]:
        """Creates an atomic signature."""
        atomic_signature = AtomicSignature.minimal(
            docker_manifest_digest=digest, docker_reference=str(image_name)
        )

        if not self.keyid:
            raise RuntimeError("Cannot sign without keyid!")
        if not self.passphrase or len(self.passphrase) < 1:
            raise RuntimeError("Refusing to use an unprotected key!")

        # Write the data to a temporary file and invoke GnuPG to create a detached signature ...
        async with aiotempfile(mode="w+b") as datafile:
            signaturefile = Path(f"{datafile.name}.gpg")

            # Write the data to a temporary file ...
            await datafile.write(atomic_signature.get_bytes())
            await datafile.flush()

            # Note: These options deviate from GPGSigner.sign()
            args = [
                "gpg",
                "--batch",
                "--default-key",
                str(self.keyid),
                "--digest-algo",
                "SHA512",
                "--homedir",
                str(self.homedir),
                "--no-options",
                "--no-emit-version",
                "--no-tty",
                "--passphrase-fd",
                "0",
                "--pinentry-mode",
                "loopback",
                "--sign",
                "--status-fd",
                "2",
                datafile.name,
            ]

            execute_command = await self._exeute_command(
                args=args, stdin=self.passphrase.encode("utf-8")
            )
            if execute_command.returncode:
                return None

        # Retrieve the signature and cleanup ...
        try:
            async with aiofiles.open(signaturefile, "rb") as tmpfile:
                data = await tmpfile.read()
                find_all_signatures = await self._store_signature(
                    digest=digest, signature=data
                )
                return find_all_signatures
        finally:
            signaturefile.unlink(missing_ok=True)

    async def atomicverify(
        self, *, digest: FormattedSHA256, image_name: ImageName
    ) -> List[AtomicSignerVerify]:
        # pylint: disable=too-many-locals
        """Verifies atomic signatures."""
        result = []

        # Retrieve all corresponding signatures from all trust store locations ...
        signatures_all = []
        for location in self.locations:
            signatures = await self._find_all_signatures(
                digest=digest, location=location
            )
            signatures_all.extend(signatures)

        # Write the data and signature to temporary files and invoke GnuPG to verify they match ...
        for signature in signatures_all:
            async with aiotempfile(mode="w+b") as signaturefile:
                datafile = Path(f"{signaturefile.name}.atomic_signature")

                # Write the signature to a temporary file ...
                await signaturefile.write(signature.signature)
                await signaturefile.flush()

                # Note: These options deviate from GPGSigner.verify()
                args = [
                    "gpg",
                    "--batch",
                    "--decrypt",
                    "--homedir",
                    str(self.homedir),
                    "--no-options",
                    "--no-emit-version",
                    "--no-tty",
                    "--output",
                    str(datafile),
                    "--status-fd",
                    "2",
                    signaturefile.name,
                ]

                execute_command = await self._exeute_command(args=args)

                # Retrieve the data file and cleanup ...
                try:
                    async with aiofiles.open(datafile, "rb") as tmpfile:
                        data = await tmpfile.read()
                        atomic_signature = AtomicSignature(data)
                finally:
                    datafile.unlink(missing_ok=True)

                # Verify both types of signatures ...
                status_atomic = await self._verify_atomic_signature(
                    atomic_signature=atomic_signature,
                    digest=digest,
                    image_name=image_name,
                )
                status_gpg = await GPGSigner._parse_output(
                    output=execute_command.stderr
                )

                # Assign metadata ...
                signer_long = signer_short = "Signature parsing failed!"
                try:
                    signer_short = (
                        f"keyid={status_gpg.key_id} status={status_gpg.status.value}"
                    )
                    signer_long = "\n".join(
                        [
                            f"{''.ljust(8)}Signature made {status_gpg.timestamp} using key ID {status_gpg.key_id}",
                            "".ljust(12) + status_gpg.username,
                        ]
                    )
                except:  # pylint: disable=bare-except
                    ...

                result.append(
                    AtomicSignerVerify(
                        atomic_signature=atomic_signature,
                        fingerprint=status_gpg.fingerprint,
                        key_id=status_gpg.key_id,
                        signer_long=signer_long,
                        signer_short=signer_short,
                        status_atomic=status_atomic,
                        status_gpg=status_gpg.status.value,
                        timestamp=status_gpg.timestamp,
                        trust=status_gpg.trust.value,
                        type="atomicsigner",
                        username=status_gpg.username,
                        valid=(
                            status_atomic is None
                            and status_gpg.status == GPGStatus.VALIDSIG
                            and status_gpg.trust in [GPGTrust.FULLY, GPGTrust.ULTIMATE]
                        ),
                    )
                )

        return result
