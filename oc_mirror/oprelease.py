#!/usr/bin/env python

# pylint: disable=protected-access

"""Operator release helpers."""

import gzip
import logging
import sqlite3
import re
import tarfile

from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import (
    FormattedSHA256,
    ImageName,
)
from docker_sign_verify import RegistryV2, RegistryV2ManifestList
from docker_sign_verify.utils import be_kind_rewind

from .atomicsigner import AtomicSignerVerify
from .singleassignment import SingleAssignment
from .specs import OperatorReleaseSpecs
from .utils import (
    copy_image,
    read_from_tar,
    retrieve_and_verify_release_metadata,
    TypingRegexSubstitution,
)

LOGGER = logging.getLogger(__name__)


class TypingOperatorMetadata(NamedTuple):
    # pylint: disable=missing-class-docstring
    bundle: str
    channel: str
    images: List[ImageName]
    package: str


class TypingGetReleaseMetadata(NamedTuple):
    # pylint: disable=missing-class-docstring
    index_database: bytes
    index_name: ImageName
    manifest_digest: FormattedSHA256
    operators: List[TypingOperatorMetadata]
    signature_stores: List[str]
    signatures: List[AtomicSignerVerify]
    signing_keys: List[str]


class TypingSearchLayer(NamedTuple):
    # pylint: disable=missing-class-docstring
    index_database: Optional[bytes]


async def _get_index_db(
    *, tar_file, tarinfo: tarfile.TarInfo, path: Path
) -> Optional[bytes]:
    """
    Retrieves the index database from a given tarinfo, if available.

    Args:
        tar_file: The tar_file of the layer being processed.
        tarinfo: The tarinfo from which to retrieve the index database.
        path: Relative path of the tarinfo within the tar file.

    Returns:
        The index database, or None.
    """
    if path.name == OperatorReleaseSpecs.INDEX_DATABASE_NAME:
        LOGGER.debug("Found index database: %s", path)
        result = await read_from_tar(tar_file, tarinfo)
        return result


async def _search_layer(
    *,
    index_name: ImageName,
    layer: FormattedSHA256,
    registry_v2: RegistryV2,
) -> TypingSearchLayer:
    """
    Searches image layers in a given index image for the index database.

    Args:
        index_name: The name of the index image.
        layer: The image layer to be searched.
        registry_v2: The underlying registry v2 image source to use to retrieve the index database.

    Returns:
        index_database: The index database, or None.
    """
    LOGGER.debug("Extracting from layer : %s", layer)

    index_database = SingleAssignment("index_database")
    async with aiotempfile(mode="w+b") as file:
        await registry_v2.docker_registry_client_async.get_blob_to_disk(
            digest=layer, file=file, image_name=index_name
        )
        await be_kind_rewind(file)

        with gzip.GzipFile(filename=file.name) as gzip_file_in:
            with tarfile.open(fileobj=gzip_file_in) as tar_file_in:
                for tarinfo in tar_file_in:
                    path = Path(tarinfo.name)

                    if not str(path).startswith(
                        OperatorReleaseSpecs.DATABASE_PATH_PREFIX
                    ):
                        continue
                    tmp = await _get_index_db(
                        tar_file=tar_file_in, tarinfo=tarinfo, path=path
                    )
                    if tmp:
                        index_database.set(tmp)
    return TypingSearchLayer(index_database=index_database.get())


async def get_release_metadata(
    *,
    index_name: ImageName,
    package_channel: Dict[str, str] = None,
    registry_v2: RegistryV2,
    signature_stores: List[str] = None,
    signing_keys: List[str] = None,
    verify: bool = True,
) -> TypingGetReleaseMetadata:
    # pylint: disable=too-many-branches,too-many-locals,too-many-statements
    """
    Retrieves all metadata for a given package name(s).

    Args:
        index_name: The operator release image for which to retrieve the metadata.
        package_channel: Mapping of package names to content channels. Providing 'None' as the channel name will use the
                         default channel from the index database.
        registry_v2: The Registry V2 image source to use to connect.
        signature_stores: A list of signature store uri overrides.
        signing_keys: A list of armored GnuPG trust store overrides.
        verify: If True, the atomic signature will be retrieved and validated.

    Returns:
        dict:
            index_database: The index database containing all operator metadata.
            operators: A list of process operator metadata.
            signature_stores: A list of signature store uris.
            signing_keys: A list of armored GnuPG trust stores.
    """
    LOGGER.debug("Source index name: %s", index_name)

    # Retrieve the manifest ...
    manifest = await registry_v2.get_manifest(image_name=index_name)
    if isinstance(manifest, RegistryV2ManifestList):
        LOGGER.debug("Manifest list digest: %s", manifest.get_digest())
        manifest = await registry_v2._get_manifest_from_manifest_list(
            image_name=index_name, manifest_list=manifest
        )
    manifest_digest = manifest.get_digest()
    LOGGER.debug("Source index manifest digest: %s", manifest_digest)

    # Search through all layers in reverse order, looking for index.db under a given prefix ...
    index_database = SingleAssignment("index_database")
    for layer in manifest.get_layers():
        tmp = await _search_layer(
            layer=FormattedSHA256.parse(layer),
            registry_v2=registry_v2,
            index_name=index_name,
        )
        if tmp.index_database:
            index_database.set(tmp.index_database)
    index_database = index_database.get()
    if not index_database:
        raise Exception("Unable to locate index database!")

    # Extract the index to a temporary location for processing ...
    async with aiotempfile(mode="w+b") as file:
        await file.write(index_database)
        await file.flush()
        connection = sqlite3.connect(file._file.name)
        cursor = connection.cursor()

        # Start by retrieving all packages and default channels as the initial filter set ...
        rows = cursor.execute("SELECT name, default_channel FROM package")
        package_channel_filtered = {row[0]: row[1] for row in rows}
        LOGGER.debug(
            "Discovered %d packages in index database.", len(package_channel_filtered)
        )

        # We must be able to retrieve information from the index database
        if not package_channel_filtered:
            raise Exception("Unable retrieve package metadata from index database!")

        # If the user provided a filter set, use that instead, but populate missing channels with the defaults ...
        if package_channel:
            # All user provided package names must exist within the index database
            for package in package_channel.keys():
                if package not in package_channel_filtered:
                    raise Exception(f"Unable to locate package: {package}")
            for package in package_channel.keys():
                if package_channel[package] is None:
                    package_channel[package] = package_channel_filtered[package]
            package_channel_filtered = package_channel
        LOGGER.debug("Processing %d package(s).", len(package_channel_filtered))

        # Using the filtered packages and derived channels retrieve the bundles ...
        package_bundle = {}
        for package, channel in package_channel_filtered.items():
            rows = cursor.execute(
                "SELECT head_operatorbundle_name FROM channel WHERE name=:channel and package_name=:package",
                {"channel": channel, "package": package},
            ).fetchall()
            if len(rows) != 1:
                raise Exception(
                    f"Unexpected number of rows returned ({len(rows)}) for package, channel: {package}, {channel}"
                )
            package_bundle[package] = rows[0][0]
        LOGGER.debug("Processing %d bundle(s).", len(package_bundle))

        # Using the packages and bundles retrieved all images ...
        package_images = {}
        for package, bundle in package_bundle.items():
            rows = cursor.execute(
                "SELECT image FROM related_image where operatorbundle_name=:bundle",
                {"bundle": bundle},
            ).fetchall()
            if len(rows) < 1:
                raise Exception(f"No images found relating to bundle: {bundle}s")
            package_images[package] = [ImageName.parse(row[0]) for row in rows]
        LOGGER.debug(
            "Discovered %d related images.",
            sum([len(value) for key, value in package_images.items()]),
        )

    signatures = []
    # TODO: Do we want to default signing keys and signature stores?
    if verify:
        if not signature_stores or not signing_keys:
            raise RuntimeError(
                "Unable to verify release authenticity; signing_key or signature_store not provided!"
            )

        signatures = await retrieve_and_verify_release_metadata(
            digest=manifest_digest,
            image_name=index_name,
            keys=signing_keys,
            locations=signature_stores,
            registry_v2=registry_v2,
        )
    else:
        LOGGER.debug("Skipping source release authenticity verification!")

    result = TypingGetReleaseMetadata(
        index_database=index_database,
        index_name=index_name,
        manifest_digest=manifest_digest,
        operators=[
            TypingOperatorMetadata(
                bundle=package_bundle[package],
                channel=package_channel_filtered[package],
                images=package_images[package],
                package=package,
            )
            for package in package_channel_filtered.keys()
        ],
        signature_stores=signature_stores,
        signatures=signatures,
        signing_keys=signing_keys,
    )

    return result


async def log_release_metadata(
    *,
    index_name: ImageName,
    release_metadata: TypingGetReleaseMetadata,
    sort_metadata: bool = False,
):
    """
    Appends metadata for a given release to the log

    Args:
        index_name: The operator release image for which to retrieve the metadata.
        release_metadata: The metadata for the release to be logged.
        sort_metadata: If True, the metadata keys will be sorted.
    """
    LOGGER.info(index_name)
    operators = release_metadata.operators
    if sort_metadata:
        operators = sorted(release_metadata.operators, key=lambda x: x.package)
    for operator in operators:
        LOGGER.info(
            "  package: %s  bundle: %s  channel: %s  images: %d",
            operator.package,
            operator.bundle,
            operator.channel,
            len(operator.images),
        )

        images = operator.images
        if sort_metadata:
            images = sorted(images)
        for image in images:
            LOGGER.info("    %s", image)
        LOGGER.info("")

    LOGGER.info("  signatures:")
    signatures = release_metadata.signatures
    if sort_metadata:
        signatures = sorted(signatures, key=lambda item: item.timestamp, reverse=True)
    for signature in signatures:
        LOGGER.info(
            "    release name    : %s",
            signature.atomic_signature.get_docker_reference(),
        )
        LOGGER.info(
            "    manifest digest : %s",
            signature.atomic_signature.get_docker_manifest_digest(),
        )
        LOGGER.info("    fingerprint     : %s", signature.key_id)
        LOGGER.info("    username        : %s", signature.username)
        LOGGER.info("    timestamp       : %s", signature.timestamp)
        LOGGER.info("")


async def put_release(
    *,
    index_name: ImageName,
    registry_v2: RegistryV2,
    release_metadata: TypingGetReleaseMetadata,
    verify: bool = True,
):
    """
    Mirrors an openshift release.

    Args:
        index_name: The operator release image to which to store the metadata.
        registry_v2: The Registry V2 image source to use to connect.
        release_metadata: The metadata for the release to be mirrored.
        verify: If True, the atomic signature will be retrieved and validated.
    """
    LOGGER.debug("Destination index image name: %s", index_name)

    LOGGER.debug(
        "Replicating %d operators with %d images.",
        len(release_metadata.operators),
        sum([len(operator.images) for operator in release_metadata.operators]),
    )

    if verify:
        if not release_metadata.signature_stores or not release_metadata.signing_keys:
            raise RuntimeError(
                "Unable to verify release authenticity; signing_key or signature_store not provided!"
            )
        await retrieve_and_verify_release_metadata(
            digest=release_metadata.manifest_digest,
            image_name=index_name,
            keys=release_metadata.signing_keys,
            locations=release_metadata.signature_stores,
            registry_v2=registry_v2,
        )
    else:
        LOGGER.debug("Skipping source release authenticity verification!")

    # Replicate all operator images images ...
    for operator in release_metadata.operators:
        for image_name_src in operator.images:
            image_name_dest = image_name_src.clone()
            image_name_dest.endpoint = index_name.endpoint
            await copy_image(
                image_name_dest=image_name_dest,
                image_name_src=image_name_src,
                registry_v2=registry_v2,
            )

    # Replicate the index ...
    await copy_image(
        image_name_dest=index_name,
        image_name_src=release_metadata.index_name,
        registry_v2=registry_v2,
    )


async def translate_release_metadata(
    *,
    regex_substitutions: List[TypingRegexSubstitution],
    release_metadata: TypingGetReleaseMetadata,
    signature_stores: List[str] = None,
    signing_keys: List[str] = None,
) -> TypingGetReleaseMetadata:
    """
    Translates metadata for a given release to support hop 2-n mirroring.

    Args:
        regex_substitutions: Regular expression substitutions to be applied to source uris.
        release_metadata: The metadata for the release to be translated.
        signature_stores: A list of signature store uri overrides.
        signing_keys: A list of armored GnuPG trust store overrides.

    Returns:
        The translated metadata for a given release.
    """
    if signature_stores is None:
        signature_stores = release_metadata.signature_stores
    if signing_keys is None:
        signing_keys = release_metadata.signing_keys

    operators = release_metadata.operators
    for regex_substitution in regex_substitutions:
        pattern = re.compile(regex_substitution.pattern)
        operators = [
            TypingOperatorMetadata(
                bundle=operator.bundle,
                channel=operator.channel,
                images=[
                    ImageName.parse(
                        pattern.sub(regex_substitution.replacement, str(image))
                    )
                    for image in operator.images
                ],
                package=operator.package,
            )
            for operator in release_metadata.operators
        ]

    return TypingGetReleaseMetadata(
        index_database=release_metadata.index_database,
        index_name=release_metadata.index_name,
        manifest_digest=release_metadata.manifest_digest,
        operators=operators,
        signatures=release_metadata.signatures,
        signature_stores=signature_stores,
        signing_keys=signing_keys,
    )
