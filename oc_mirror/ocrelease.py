#!/usr/bin/env python

# pylint: disable=redefined-outer-name

"""OpenShift release helpers."""

import gzip
import logging
import re
import tarfile

from json import loads
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
from yaml import load_all, SafeLoader

from aiotempfile.aiotempfile import open as aiotempfile
from docker_registry_client_async import (
    FormattedSHA256,
    ImageName,
)
from docker_sign_verify import ImageConfig, RegistryV2, RegistryV2ManifestList
from docker_sign_verify.utils import be_kind_rewind

from .atomicsigner import AtomicSignerVerify
from .imagestream import ImageStream
from .singleassignment import SingleAssignment
from .specs import OpenShiftReleaseSpecs
from .utils import (
    copy_blob,
    copy_manifest,
    read_from_tar,
    TypingRegexSubstitution,
    retrieve_and_verify_release_metadata,
)

LOGGER = logging.getLogger(__name__)


class TypingCollectDigests(NamedTuple):
    # pylint: disable=missing-class-docstring
    blobs: Dict[FormattedSHA256, Set[str]]
    manifests: Dict[ImageName, str]


class TypingGetReleaseMetadata(NamedTuple):
    # pylint: disable=missing-class-docstring
    blobs: Dict[FormattedSHA256, Set[str]]
    manifest_digest: FormattedSHA256
    manifests: Dict[ImageName, str]
    raw_image_references: ImageStream
    raw_release_metadata: Any
    signature_stores: List[str]
    signatures: List[AtomicSignerVerify]
    signing_keys: List[str]


class TypingGetSecurityInformation(NamedTuple):
    # pylint: disable=missing-class-docstring
    keys: List[str]
    locations: List[str]


class TypingSearchLayer(NamedTuple):
    # pylint: disable=missing-class-docstring
    image_references: ImageStream
    keys: List[str]
    locations: List[str]
    release_metadata: Any


async def _collect_digests(
    *,
    image_references: ImageStream,
    registry_v2: RegistryV2,
    release_name: ImageName,
) -> TypingCollectDigests:
    """
    Retrieves all blob and manifest digests for a given release.

    Args:
        image_references: The image references for the release.
        registry_v2: The underlying registry v2 image source to use to retrieve the digests.
        release_name: The name of the release image.

    Returns:
        blobs: The mapping of blob digests to image prefixes.
        manifests: The mapping of image manifests to image stream names.
    """
    blobs = {}
    manifests = {}

    def add_blob(_digest: FormattedSHA256, i_prefix: str):
        if _digest not in blobs:
            blobs[_digest] = set()
        blobs[_digest].add(i_prefix)

    # TODO: Should we split out manifest and blob processing to separate functions?
    for image_name, name in _get_tag_mapping(
        release_name=release_name, image_references=image_references
    ):
        # Convert tags to digests
        # pkg/cli/image/mirror/mirror.go:437 - plan()
        digest = image_name.digest
        if image_name.tag and not image_name.digest:
            response = await registry_v2.docker_registry_client_async.head_manifest(
                image_name
            )
            LOGGER.debug("Resolved source image %s to %s", image_name, response.digest)
            digest = response.digest

        # Find all blobs ...
        # TODO: Handle manifest lists ...
        manifest = await registry_v2.get_manifest(image_name=image_name)
        image_prefix = f"{image_name.endpoint}/{image_name.image}"
        add_blob(manifest.get_config_digest(), image_prefix)
        for layer in manifest.get_layers():
            add_blob(layer, image_prefix)

        # Note: Must be assigned below blob inspection to prevent errors based on digest lookup
        image_name.digest = digest
        image_name.tag = ""
        manifests[image_name] = name

    return TypingCollectDigests(blobs=blobs, manifests=manifests)


async def _get_image_references(
    *, tar_file, tarinfo: tarfile.TarInfo, path: Path
) -> Optional[ImageStream]:
    """
    Retrieves images references from a given tarinfo, if available.

    Args:
        tar_file: The tar_file of the layer being processed.
        tarinfo: The tarinfo from which to retrieve the image references.
        path: Relative path of the tarinfo within the tar file.

    Returns:
        An ImageStream object containing the image references, or None.
    """
    # pkg/cli/admin/release/mirror.go:475 - Run()
    if path.name == OpenShiftReleaseSpecs.IMAGE_REFERENCES_NAME:
        LOGGER.debug("Found image references: %s", path)
        result = await read_from_tar(tar_file, tarinfo)
        return ImageStream(result)


async def _get_release_metadata(
    *, tar_file, tarinfo: tarfile.TarInfo, path: Path
) -> Optional[Any]:
    """
    Retrieves release metadata from a given tarinfo, if available.

    Args:
        tar_file: The tar_file of the layer being processed.
        tarinfo: The tarinfo from which to retrieve the release metadata.
        path: Relative path of the tarinfo within the tar file.

    Returns:
        The release metadata data structure, or None.
    """
    # pkg/cli/admin/release/mirror.go:475 - Run()
    if path.name == OpenShiftReleaseSpecs.RELEASE_METADATA:
        LOGGER.debug("Found release metadata: %s", path)
        result = await read_from_tar(tar_file, tarinfo)
        return loads(result)


async def _get_security_information(
    *, tar_file, tarinfo: tarfile.TarInfo, path: Path
) -> TypingGetSecurityInformation:
    """
    Retrieves security information from a given tarinfo, if available.

    Args:
        tar_file: The tar_file of the layer being processed.
        tarinfo: The tarinfo from which to retrieve the security information.
        path: Relative path of the tarinfo within the tar file.

    Returns:
        keys: The list of public GPG keys found within the tarinfo.
        locations: The list of signature store locations found within the tarinfo.
    """
    keys = []
    locations = []

    # pkg/cli/admin/release/extract.go:228 - Run()
    if path.suffix in [".yaml", ".yml", ".json"]:
        # LOGGER.debug("Found manifest: %s", path_file.name)

        # ... for all matching files found, parse them ...
        _bytes = await read_from_tar(tar_file, tarinfo)
        if path.suffix == ".json":
            documents = [loads(_bytes)]
        else:
            documents = load_all(_bytes, SafeLoader)

        # ... and look for a root-level "data" key ...
        for document in documents:
            if not document:
                continue
            if document.get("kind", "") != "ConfigMap":
                continue
            if (
                OpenShiftReleaseSpecs.RELEASE_ANNOTATION_CONFIG_MAP_VERIFIER
                not in document.get("metadata", []).get("annotations", [])
            ):
                continue
            LOGGER.debug("Found release security information: %s", path)
            for key, value in document.get("data", {}).items():
                if key.startswith("verifier-public-key-"):
                    # LOGGER.debug("Found in %s:\n%s %s", path.name, key, value)
                    keys.append(value)
                if key.startswith("store-"):
                    # LOGGER.debug("Found in %s:\n%s\n%s", path.name, key, value)
                    locations.append(value)
    return TypingGetSecurityInformation(keys=keys, locations=locations)


def _get_tag_mapping(
    *, release_name: ImageName, image_references: ImageStream
) -> Tuple[ImageName, str]:
    """
    Deconstructs the metadata inside an ImageStream into a mapping of image names to tag names.

    Args:
        release_name: The name of the release image.
        image_references: The image references for the release.
    Yields:
        A tuple of image name and tag name.
    """
    # Special Case: for the outer release image
    # pkg/cli/admin/release/mirror.go:565 (o.ToRelease mapping)
    yield release_name.clone(), release_name.tag

    for name, image_name in image_references.get_tags():
        assert not image_name.tag and image_name.digest
        # LOGGER.debug("Mapping %s -> %s", image_name, name)
        yield image_name, name


async def _search_layer(
    *,
    layer: FormattedSHA256,
    registry_v2: RegistryV2,
    release_name: ImageName,
) -> TypingSearchLayer:
    """
    Searches image layers in a given release image for metadata.

    Args:
        layer: The image layer to be searched.
        registry_v2: The underlying registry v2 image source to use to retrieve the metadata.
        release_name: The name of the release image.

    Returns:
        image_references: An ImageStream object containing the image references, or None.
        keys: The list of public GPG keys found within the layer.
        locations: The list of signature store locations found within the layer.
        release_metadata: The release metadata data structure, or None.
    """
    LOGGER.debug("Extracting from layer : %s", layer)

    image_references = SingleAssignment("image_references")
    keys = []
    locations = []
    release_metadata = SingleAssignment("release_metadata")
    async with aiotempfile(mode="w+b") as file:
        await registry_v2.docker_registry_client_async.get_blob_to_disk(
            digest=layer, file=file, image_name=release_name
        )
        await be_kind_rewind(file)

        with gzip.GzipFile(filename=file.name) as gzip_file_in:
            with tarfile.open(fileobj=gzip_file_in) as tar_file_in:
                for tarinfo in tar_file_in:
                    path = Path(tarinfo.name)

                    # TODO: Do we need to process tarinfo.linkname like pkg/cli/image/extract/extract.go:621 ?

                    if not str(path).startswith(
                        OpenShiftReleaseSpecs.MANIFEST_PATH_PREFIX
                    ):
                        # pkg/cli/image/extract/extract.go:616 - changeTarEntryParent()
                        # LOGGER.debug("Exclude %s due to missing prefix %s", path)
                        continue
                    tmp = await _get_image_references(
                        tar_file=tar_file_in, tarinfo=tarinfo, path=path
                    )
                    if tmp:
                        image_references.set(tmp)
                    tmp = await _get_release_metadata(
                        tar_file=tar_file_in, tarinfo=tarinfo, path=path
                    )
                    if tmp:
                        release_metadata.set(tmp)
                    tmp = await _get_security_information(
                        tar_file=tar_file_in, tarinfo=tarinfo, path=path
                    )
                    keys.extend(tmp.keys)
                    locations.extend(tmp.locations)
    return TypingSearchLayer(
        image_references=image_references.get(),
        keys=keys,
        locations=locations,
        release_metadata=release_metadata.get(),
    )


async def get_release_metadata(
    *,
    registry_v2: RegistryV2,
    release_name: ImageName,
    signature_stores: List[str] = None,
    signing_keys: List[str] = None,
    verify: bool = True,
) -> TypingGetReleaseMetadata:
    # pylint: disable=protected-access,too-many-locals
    """
    Retrieves all metadata for a given OpenShift release image.

    Args:
        registry_v2: The Registry V2 image source to use to connect.
        release_name: The OpenShift release image for which to retrieve the metadata.
        signature_stores: A list of signature store uri overrides.
        signing_keys: A list of armored GnuPG trust store overrides.
        verify: If True, the atomic signature will be retrieved and validated.

    Returns:
        dict:
            blobs: A mapping of blob digests to a set of image prefixes.
            manifests: A mapping of image manifests to tag values.
            signature_stores: A list of signature store uris.
            signing_keys: A list of armored GnuPG trust stores.
    """
    # TODO: Change assertions to runtime checks.
    LOGGER.debug("Source release image name: %s", release_name)

    # pkg/cli/image/extract/extract.go:332 - Run()
    # pkg/cli/image/manifest/manifest.go:342 - ProcessManifestList()

    # Retrieve the manifest ...
    manifest = await registry_v2.get_manifest(image_name=release_name)
    if isinstance(manifest, RegistryV2ManifestList):
        LOGGER.debug("Manifest list digest: %s", manifest.get_digest())
        manifest = await registry_v2._get_manifest_from_manifest_list(
            image_name=release_name, manifest_list=manifest
        )
    manifest_digest = manifest.get_digest()
    LOGGER.debug("Source release manifest digest: %s", manifest_digest)

    # TODO: Do we need pkg/cli/image/manifest/manifest.go:70 - Verify() ?

    # Log the image configuration (but why?)
    response = await registry_v2.docker_registry_client_async.get_blob(
        release_name, manifest.get_config_digest()
    )
    assert response.blob
    image_config = ImageConfig(response.blob)
    # pkg/cli/image/manifest/manifest.go:289 - ManifestToImageConfig()
    LOGGER.debug("Source release image config digest: %s", image_config.get_digest())

    # Search through all layers in reverse order, looking for yaml and json files under a given prefix ...
    # pkg/cli/image/extract/extract.go:307 - Run()
    image_references = SingleAssignment("image_references")
    keys = []
    locations = []
    release_metadata = SingleAssignment("release_metadata")
    for layer in manifest.get_layers():
        tmp = await _search_layer(
            layer=FormattedSHA256.parse(layer),
            registry_v2=registry_v2,
            release_name=release_name,
        )
        if tmp.image_references:
            image_references.set(tmp.image_references)
        keys.extend(tmp.keys)
        locations.extend(tmp.locations)
        if tmp.release_metadata:
            release_metadata.set(tmp.release_metadata)
    image_references = image_references.get()
    release_metadata = release_metadata.get()

    assert image_references
    assert keys
    assert locations
    assert release_metadata

    # pkg/cli/admin/release/mirror.go:517 - imageVerifier.Verify()
    signatures = []
    if verify:
        _keys = signing_keys if signing_keys else keys
        _locations = signature_stores if signature_stores else locations
        signatures = await retrieve_and_verify_release_metadata(
            digest=manifest_digest,
            image_name=release_name,
            keys=_keys,
            locations=_locations,
            registry_v2=registry_v2,
        )
    else:
        LOGGER.debug("Skipping source release authenticity verification!")

    assert image_references.get_json().get("kind", "") == "ImageStream"
    assert image_references.get_json().get("apiVersion", "") == "image.openshift.io/v1"

    tmp = await _collect_digests(
        image_references=image_references,
        registry_v2=registry_v2,
        release_name=release_name,
    )
    LOGGER.debug(
        "Collected %d manifests with %d blobs.",
        len(tmp.manifests),
        len(tmp.blobs),
    )
    result = TypingGetReleaseMetadata(
        blobs=tmp.blobs,
        manifest_digest=manifest_digest,
        manifests=tmp.manifests,
        raw_image_references=image_references,
        raw_release_metadata=release_metadata,
        signature_stores=locations,
        signatures=signatures,
        signing_keys=keys,
    )

    # pkg/cli/image/mirror/plan.go:244 - Print()
    # LOGGER.debug(release_name)
    # LOGGER.debug("  blobs:")
    # for digest, image_prefixes in result.blobs.items():
    #     for image_prefix in image_prefixes:
    #         LOGGER.debug("    %s %s", image_prefix, digest)
    # LOGGER.debug("  manifests:")
    # for image_name in result.manifests.keys():
    #     LOGGER.debug("    %s -> %s", image_name, result.manifests[image_name])

    return result


async def log_release_metadata(
    *,
    release_name: ImageName,
    release_metadata: TypingGetReleaseMetadata,
    sort_metadata: bool = False,
):
    """
    Appends metadata for a given release to the log

    Args:
        release_name: The OpenShift release image for which to retrieve the metadata.
        release_metadata: The metadata for the release to be logged.
        sort_metadata: If True, the metadata keys will be sorted.
    """

    def make_image_name(img_name: ImageName, tag: str):
        result = img_name.clone()
        result.tag = tag
        return result

    LOGGER.info(release_name)
    LOGGER.info("  manifests:")
    manifests = [
        make_image_name(image_name, tag)
        for image_name, tag in release_metadata.manifests.items()
    ]
    if sort_metadata:
        manifests = sorted(manifests)
    for manifest in manifests:
        LOGGER.info("    %s", manifest)
    LOGGER.info("  blobs:")
    blobs = [
        ImageName.parse(f"{image_prefix}@{digest}")
        for digest, image_prefixes in release_metadata.blobs.items()
        for image_prefix in image_prefixes
    ]
    if sort_metadata:
        blobs = sorted(blobs)
    for blob in blobs:
        LOGGER.info("    %s", blob)
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
    registry_v2: RegistryV2,
    release_metadata: TypingGetReleaseMetadata,
    release_name: ImageName,
    verify: bool = True,
):
    """
    Mirrors an openshift release.

    Args:
        registry_v2: The Registry V2 image source to use to connect.
        release_metadata: The metadata for the release to be mirrored.
        release_name: The OpenShift release image to which to store the metadata.
        verify: If True, the atomic signature will be retrieved and validated.
    """
    LOGGER.debug("Destination release image name: %s", release_name)

    LOGGER.debug(
        "Replicating %d manifests with %d blobs.",
        len(release_metadata.manifests),
        len(release_metadata.blobs),
    )

    if verify:
        await retrieve_and_verify_release_metadata(
            digest=release_metadata.manifest_digest,
            image_name=release_name,
            keys=release_metadata.signing_keys,
            locations=release_metadata.signature_stores,
            registry_v2=registry_v2,
        )
    else:
        LOGGER.debug("Skipping source release authenticity verification!")

    # Replicate all blobs ...
    last_image_name_dest = None
    last_image_name_src = None
    for digest, image_prefixes in release_metadata.blobs.items():
        # TODO: Handle blob mounting ...
        for image_prefix in image_prefixes:
            image_name_src = ImageName.parse(image_prefix)
            image_name_dest = image_name_src.clone()
            # Note: Only update the endpoint; keep the digest and image the same
            image_name_dest.endpoint = release_name.endpoint

            if (
                last_image_name_dest != image_name_dest
                or last_image_name_src != image_name_src
            ):
                LOGGER.debug("Copy blobs ...")
                LOGGER.debug("    from : %s", image_name_src)
                LOGGER.debug("    to   : %s", image_name_dest)
            await copy_blob(
                digest=digest,
                image_name_dest=image_name_dest,
                image_name_src=image_name_src,
                registry_v2=registry_v2,
            )
            last_image_name_dest = image_name_dest
            last_image_name_src = image_name_src

    # Replicate all manifests ...
    for image_name_src in release_metadata.manifests.keys():
        # Note: Update the endpoint; keep the image unchanged; use the derived tag; do not use digest
        image_name_dest = ImageName(
            image_name_src.image,
            endpoint=release_name.endpoint,
            tag=release_metadata.manifests[image_name_src],
        )
        await copy_manifest(
            image_name_dest=image_name_dest,
            image_name_src=image_name_src,
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

    blobs = release_metadata.blobs
    manifests = release_metadata.manifests
    for regex_substitution in regex_substitutions:
        pattern = re.compile(regex_substitution.pattern)
        blobs = {
            k: {pattern.sub(regex_substitution.replacement, x) for x in v}
            for (k, v) in release_metadata.blobs.items()
        }
        manifests = {
            ImageName.parse(pattern.sub(regex_substitution.replacement, str(k))): v
            for (k, v) in release_metadata.manifests.items()
        }

    return TypingGetReleaseMetadata(
        blobs=blobs,
        manifest_digest=release_metadata.manifest_digest,
        manifests=manifests,
        raw_image_references=release_metadata.raw_image_references,
        raw_release_metadata=release_metadata.raw_release_metadata,
        signatures=release_metadata.signatures,
        signature_stores=signature_stores,
        signing_keys=signing_keys,
    )
