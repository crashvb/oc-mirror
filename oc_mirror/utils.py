#!/usr/bin/env python

"""Utility classes."""

import logging
import tarfile

from io import BytesIO
from tempfile import TemporaryDirectory
from typing import List, NamedTuple

from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import FormattedSHA256, ImageName, Manifest
from docker_registry_client_async.utils import must_be_equal
from docker_sign_verify import (
    NoSignatureError,
    RegistryV2ManifestList,
    RegistryV2,
    SignatureMismatchError,
)
from docker_sign_verify.exceptions import DigestMismatchError
from docker_sign_verify.utils import be_kind_rewind, chunk_file
from pretty_bad_protocol import GPG
from pretty_bad_protocol._parsers import Verify
from pretty_bad_protocol._util import _make_binary_stream

from .atomicsignature import AtomicSignature
from .atomicsigner import AtomicSigner, AtomicSignerVerify

LOGGER = logging.getLogger(__name__)


class TypingDetachedSignature(NamedTuple):
    # pylint: disable=missing-class-docstring
    atomic_signature: AtomicSignature
    key: str
    raw_signature: bytes
    timestamp: str
    verify: Verify
    url: str
    username: str


class TypingRegexSubstitution(NamedTuple):
    # pylint: disable=missing-class-docstring
    pattern: str
    replacement: str


class TypingRetrieveAndVerifyReleaseMetadata(NamedTuple):
    # pylint: disable=missing-class-docstring
    signatures: List[TypingDetachedSignature]


class TypingVerifyDetachedSignature(NamedTuple):
    # pylint: disable=missing-class-docstring
    atomic_signature: AtomicSignature
    crypt: Verify
    result: bool


async def copy_blob(
    *,
    digest: FormattedSHA256,
    image_name_dest: ImageName,
    image_name_src: ImageName,
    registry_v2: RegistryV2,
):
    """
    Replicates a blob between two docker registry images.

    Args:
        digest: The digest of the blob to be replicated.
        image_name_dest: The destination registry image.
        image_name_src:  The source registry image.
        registry_v2: The underlying registry v2 image source to use to replicate.
    """
    docker_registry_client_async = registry_v2.docker_registry_client_async

    LOGGER.debug("Copying blob %s ...", digest)
    response = await docker_registry_client_async.head_blob(
        image_name=image_name_dest, digest=digest
    )
    if response.result:
        return

    async with aiotempfile(mode="w+b") as file:
        await docker_registry_client_async.get_blob_to_disk(
            digest=digest, file=file, image_name=image_name_src
        )
        await be_kind_rewind(file)
        await registry_v2.put_image_layer_from_disk(
            file=file, digest_expected=digest, image_name=image_name_dest
        )


async def copy_image(
    *,
    image_name_dest: ImageName,
    image_name_src: ImageName,
    registry_v2: RegistryV2,
):
    """
    Replicates an image between two docker registries.

    Args:
        image_name_dest: The destination registry image.
        image_name_src:  The source registry image.
        registry_v2: The underlying registry v2 image source to use to replicate.
    """
    docker_registry_client_async = registry_v2.docker_registry_client_async

    LOGGER.debug("Copying image: %s ...", image_name_src)

    manifest = await registry_v2.get_manifest(image_name=image_name_src)
    if isinstance(manifest, RegistryV2ManifestList):
        LOGGER.debug("Processing manifest list: %s ...", image_name_src)
        for digest in manifest.get_manifests():
            img_name_dest = image_name_dest.clone()
            img_name_dest.digest = digest
            img_name_dest.tag = None
            img_name_src = image_name_src.clone()
            img_name_src.digest = digest
            img_name_src.tag = None
            await copy_image(
                image_name_dest=img_name_dest,
                image_name_src=img_name_src,
                registry_v2=registry_v2,
            )
    else:
        for layer in manifest.get_layers():
            await copy_blob(
                digest=layer,
                image_name_dest=image_name_dest,
                image_name_src=image_name_src,
                registry_v2=registry_v2,
            )
        await copy_blob(
            digest=manifest.get_config_digest(),
            image_name_dest=image_name_dest,
            image_name_src=image_name_src,
            registry_v2=registry_v2,
        )

    await docker_registry_client_async.put_manifest(
        image_name=image_name_dest, manifest=manifest
    )


async def copy_manifest(
    *,
    image_name_dest: ImageName,
    image_name_src: ImageName,
    registry_v2: RegistryV2,
):
    """
    Replicates a manifest between two docker registry images.

    Args:
        image_name_dest: The destination registry image.
        image_name_src:  The source registry image.
        registry_v2: The underlying registry v2 image source to use to replicate.
    """
    docker_registry_client_async = registry_v2.docker_registry_client_async

    LOGGER.debug("Copying manifest: %s ...", image_name_src)
    response = await docker_registry_client_async.head_manifest(
        image_name=image_name_dest
    )
    if response.result:
        return

    async with aiotempfile(mode="w+b") as file:
        await docker_registry_client_async.get_manifest_to_disk(
            file=file, image_name=image_name_src
        )
        await be_kind_rewind(file)

        # Note: ClientResponse.content.iter_chunks() will deplete the underlying stream without saving
        #       ClientResponse._body; so calls to ClientReponse.read() will return None.
        # manifest = Manifest(await response["client_response"].read())
        manifest = Manifest(manifest=await file.read())
        await be_kind_rewind(file)

        response = await docker_registry_client_async.put_manifest_from_disk(
            file=file, image_name=image_name_dest, media_type=manifest.get_media_type()
        )
        # TODO: Is this check actually redundant to put_manifest_from_disk(check_digest=True)?
        must_be_equal(
            actual=response.digest,
            error_type=DigestMismatchError,
            expected=image_name_src.digest,
            msg="Manifest digest mismatch",
        )


def import_owner_trust(*, gpg: GPG, trust_data: str):
    # pylint: disable=protected-access
    """
    Imports trust information.

    Args:
        gpg: GPG object on which to operate.
        trust_data: The trust data to be imported.
    """
    result = gpg._result_map["import"](gpg)
    data = _make_binary_stream(trust_data, gpg._encoding)
    gpg._handle_io(["--import-ownertrust"], data, result, binary=True)
    data.close()
    return result


async def read_from_tar(tar_file, tarinfo: tarfile.TarInfo) -> bytes:
    """Reads an entry from a tar file into memory."""
    bytesio = BytesIO()
    await chunk_file(
        tar_file.extractfile(tarinfo),
        bytesio,
        file_in_is_async=False,
        file_out_is_async=False,
    )
    return bytesio.getvalue()


async def retrieve_and_verify_release_metadata(
    *,
    digest: FormattedSHA256,
    image_name: ImageName,
    keys: List[str],
    locations: List[str],
    registry_v2: RegistryV2,
) -> List[AtomicSignerVerify]:
    """
    Retrieves and verifies that a matching signatures exists for given digest / key combination at a set of predefined
    locations.

    Args:
        digest: The digest for which to verify the signature(s).
        image_name: Name of the image corresponding to the digest.
        keys: The public GPG keys to use to verify the signature.
        locations: The signature store locations at which to check for matching signature(s).
        registry_v2: The underlying registry v2 image source to use to verify the metadata.

    Returns:
        dict:
            result: Boolean result. True IFF a matching signature was found.
            signatures: List of matching signatures.
    """
    LOGGER.debug(
        "Verifying release authenticity:\nKeys      :\n  %s\nLocations :\n  %s",
        f"{len(keys)} key(s)",
        "\n  ".join(locations),
    )

    # TODO: Replace use of gnupg library with raw subprocess (and clean up associated log filtering) ...
    with TemporaryDirectory() as homedir:
        LOGGER.debug("Using trust store: %s", homedir)
        gpg = GPG(
            homedir=homedir,
            ignore_homedir_permissions=True,
            options=["--pinentry-mode loopback"],
        )

        LOGGER.debug("Importing keys ...")
        for key in keys:
            gpg.import_keys(key)

        # Would be nice if this method was built-in ... =/
        for key in gpg.list_keys():
            # TODO: Is it worth it to define pretty_bad_protocol._parsers.ImportOwnerTrust to validate
            #       the return value?
            import_owner_trust(gpg=gpg, trust_data=f"{key['fingerprint']}:6:\n")

        atomic_signer = AtomicSigner(
            docker_registry_client_async=registry_v2.docker_registry_client_async,
            homedir=homedir,
            locations=locations,
        )

        LOGGER.debug("Verifying signature(s) against digest: %s", digest)
        result = await atomic_signer.atomicverify(digest=digest, image_name=image_name)
        for signature in result:
            if not signature.valid:
                raise SignatureMismatchError("Signature does not match!")

            LOGGER.debug("Signature matches:")
            LOGGER.debug("  fingerprint : %s", signature.fingerprint)
            LOGGER.debug("  timestamp   : %s", signature.timestamp)
            LOGGER.debug("  username    : %s", signature.username)
            LOGGER.debug("Signature is compliant:")
            LOGGER.debug(
                "  type                   : %s", signature.atomic_signature.get_type()
            )
            LOGGER.debug(
                "  docker reference       : %s",
                signature.atomic_signature.get_docker_reference(),
            )
            LOGGER.debug(
                "  docker manifest digest : %s",
                signature.atomic_signature.get_docker_manifest_digest(),
            )
    if not result:
        raise NoSignatureError("Unable to locate a valid signature!")
    return result
