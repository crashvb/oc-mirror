#!/usr/bin/env python

# pylint: disable=too-many-arguments

"""docker-sign-verify command line interface."""

import logging
import os
import sys

from pathlib import Path
from traceback import print_exception
from typing import List, NamedTuple

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import NoSignatureError, RegistryV2, SignatureMismatchError
from docker_sign_verify.scripts.utils import (
    async_command,
    HiddenPassword,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    to_image_name,
)

from oc_mirror.atomicsigner import AtomicSignerVerify, AtomicSigner, FindAllSignatures

from .utils import OPENSHIFT_SIGNATURE_STORES, __version__

LOGGER = logging.getLogger(__name__)


class TypingContextObject(NamedTuple):
    # pylint: disable=missing-class-docstring
    registry_v2: RegistryV2
    signature_stores: List[str]
    signature_type: str
    signing_keys: List[str]
    verbosity: int


def get_context_object(*, context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


@click.group()
@click.option(
    "-s",
    "--signature-store",
    envvar="ATOMIC_SIGNATURE_STORE",
    help="Url of a signature store to use for retrieving signatures. Can be passed multiple times.",
    multiple=True,
)
@click.option(
    "-s",
    "--signature-type",
    envvar="ATOMIC_SIGNATURE_TYPE",
    help="Whether to sign the image configuration, or the registry manifest (atomic compatible).",
    default="image-config",
    type=click.Choice(["image-config", "manifest"], case_sensitive=False),
)
@click.option(
    "-k",
    "--signing-key",
    envvar="ATOMIC_SIGNING_KEY",
    help="Armored GnuPG trust store to use for signature verification. Can be passed multiple times.",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
)
@logging_options
@click.pass_context
def cli(
    context: Context,
    signature_store: List[str],
    signature_type: str,
    signing_key: List[str],
    verbosity: int = LOGGING_DEFAULT,
):
    """Utility for creating and verifying atomic signatures."""

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)

    if not signature_store:
        signature_store = OPENSHIFT_SIGNATURE_STORES

    signing_keys = []
    for path in [Path(x) for x in signing_key]:
        LOGGER.debug("Loading signing key: %s", path)
        signing_keys.append(path.read_text("utf-8"))

    context.obj = TypingContextObject(
        registry_v2=RegistryV2(),
        signature_stores=signature_store,
        signature_type=signature_type,
        signing_keys=signing_keys,
        verbosity=verbosity,
    )


@cli.command()
@click.argument("image_name", callback=to_image_name, required=True)
@click.option(
    "-k",
    "--keyid",
    help="Signing key identifier.",
    required=True,
    envvar="ATOMIC_KEYID",
)
@click.option(
    "-p",
    "--keypass",
    default=lambda: HiddenPassword(os.environ.get("ATOMIC_KEYPASS", "")),
    help="Signing key passphrase.",
    hide_input=True,
    prompt=True,
)
@click.pass_context
@async_command
async def sign(
    context: Context,
    image_name: ImageName,
    keyid: str,
    keypass: str,
) -> FindAllSignatures:
    """Creates an atomic signature."""

    result = None
    ctx = get_context_object(context=context)
    try:
        atomic_signer = AtomicSigner(
            docker_registry_client_async=ctx.registry_v2.docker_registry_client_async,
            keyid=keyid,
            locations=ctx.signature_stores,
            passphrase=keypass,
        )
        digest = image_name.digest
        if not digest:
            LOGGER.debug(
                "Resolving digest for signature type: %s ...", ctx.signature_type
            )
            manifest = await ctx.registry_v2.get_manifest(image_name=image_name)
            digest = manifest.get_digest()
            LOGGER.debug("  manifest digest : %s", digest)
            if ctx.signature_type == "image-config":
                image_config = await ctx.registry_v2.get_image_config(
                    image_name=image_name
                )
                digest = image_config.get_digest()
                LOGGER.debug("  config digest   : %s", digest)
        result = await atomic_signer.atomicsign(digest=digest, image_name=image_name)
        if not result:
            raise RuntimeError(f"Unable to create new signature for digest: {digest}")
        LOGGER.info("Created new signature: %s (%s)", result.url, digest)
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registry_v2.close()

    return result


@cli.command()
@click.argument("image_name", callback=to_image_name, nargs=-1, required=True)
@click.pass_context
@async_command
async def verify(
    context: Context,
    image_name: List[ImageName],
) -> List[List[AtomicSignerVerify]]:
    """Verifies an atomic signature(s)."""

    results = []
    ctx = get_context_object(context=context)
    try:
        atomic_signer = AtomicSigner(
            docker_registry_client_async=ctx.registry_v2.docker_registry_client_async,
            locations=ctx.signature_stores,
        )
        for img_name in image_name:
            LOGGER.info(img_name)
            digest = img_name.digest
            if not digest:
                LOGGER.debug(
                    "Resolving digest for signature type: %s ...", ctx.signature_type
                )
                manifest = await ctx.registry_v2.get_manifest(image_name=img_name)
                digest = manifest.get_digest()
                LOGGER.debug("  manifest digest : %s", digest)
                if ctx.signature_type == "image-config":
                    image_config = await ctx.registry_v2.get_image_config(
                        image_name=img_name
                    )
                    digest = image_config.get_digest()
                    LOGGER.debug("  config digest   : %s", digest)
            result = await atomic_signer.atomicverify(
                digest=digest, image_name=img_name
            )
            for signature in result:
                if not signature.valid:
                    raise SignatureMismatchError("Signature does not match!")

                LOGGER.debug("Signature matches:")
                LOGGER.debug("  fingerprint : %s", signature.fingerprint)
                LOGGER.debug("  timestamp   : %s", signature.timestamp)
                LOGGER.debug("  username    : %s", signature.username)
                LOGGER.debug("Signature is compliant:")
                LOGGER.debug(
                    "  type                   : %s",
                    signature.atomic_signature.get_type(),
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
            LOGGER.info("Verified %s signatures.", len(result))
            results.append(result)
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registry_v2.docker_registry_client_async.close()

    return results


@click.command()
def version():
    """Displays the utility version."""
    print(__version__)


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
