#!/usr/bin/env python

"""OpenShift mirror command line interface."""

import logging
import sys

from pathlib import Path
from traceback import print_exception
from typing import List, NamedTuple

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import RegistryV2
from docker_sign_verify.scripts.utils import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    to_image_name,
)

from oc_mirror.ocrelease import (
    get_release_metadata,
    log_release_metadata,
    translate_release_metadata,
    put_release,
    TypingGetReleaseMetadata,
    TypingRegexSubstitution,
)

from .utils import version


LOGGER = logging.getLogger(__name__)


class TypingContextObject(NamedTuple):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    registry_v2: RegistryV2
    signature_stores: List[str]
    signing_keys: List[str]
    verbosity: int


def get_context_object(context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


@click.group()
@click.option(
    "--check-signatures/--no-check-signatures",
    default=True,
    help="Toggles integrity vs integrity and signature checking.",
    show_default=True,
)
@click.option(
    "--dry-run", help="Do not write to destination image sources.", is_flag=True
)
@click.option(
    "-s",
    "--signature-store",
    envvar="OCM_SIGNATURE_STORE",
    help="Url of a signature store to use for retrieving signatures. Can be passed multiple times.",
    multiple=True,
)
@click.option(
    "-k",
    "--signing-key",
    envvar="OCM_SIGNING_KEY",
    help="Armored GnuPG trust store to use for signature verification. Can be passed multiple times.",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
)
@logging_options
@click.pass_context
def cli(
    context: Context,
    check_signatures: bool,
    dry_run: False,
    signature_store: List[str],
    signing_key: List[str],
    verbosity: int = LOGGING_DEFAULT,
):
    # pylint: disable=too-many-arguments
    """Utilities for working with OpenShift releases."""
    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)

    signing_keys = []
    for path in [Path(x) for x in signing_key]:
        LOGGER.debug("Loading signing key: %s", path)
        signing_keys.append(path.read_text("utf-8"))

    context.obj = TypingContextObject(
        check_signatures=check_signatures,
        registry_v2=RegistryV2(dry_run=dry_run),
        signature_stores=signature_store,
        signing_keys=signing_keys,
        verbosity=verbosity,
    )


@cli.command()
@click.argument("image_name", callback=to_image_name, nargs=-1, required=True)
@click.option("--sort-metadata", help="Sort metadata keys.", is_flag=True)
@click.pass_context
@async_command
async def dump(
    context: Context, image_name: List[ImageName], sort_metadata: bool = False
) -> List[TypingGetReleaseMetadata]:
    """Dumps the metadata for an OpenShift release(s)."""
    result = []

    ctx = get_context_object(context)
    try:
        for img_name in image_name:
            LOGGER.info("Retrieving metadata for release: %s ...", img_name)
            release_metadata = await get_release_metadata(
                registry_v2=ctx.registry_v2,
                release_name=img_name,
                signature_stores=ctx.signature_stores,
                signing_keys=ctx.signing_keys,
                verify=ctx.check_signatures,
            )
            result.append(release_metadata)
            await log_release_metadata(
                release_name=img_name,
                release_metadata=release_metadata,
                sort_metadata=sort_metadata,
            )
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
@click.argument("image_name_src", callback=to_image_name, required=True)
@click.argument("image_name_dest", callback=to_image_name, nargs=-1, required=True)
@click.pass_context
@async_command
async def mirror(
    context: Context, image_name_dest: List[ImageName], image_name_src: ImageName
):
    """Replicates an OpenShift release between a source and destination registry(ies)."""
    ctx = get_context_object(context)
    try:
        LOGGER.info("Retrieving metadata for release: %s ...", image_name_src)
        release_metadata = await get_release_metadata(
            registry_v2=ctx.registry_v2,
            release_name=image_name_src,
            signature_stores=ctx.signature_stores,
            signing_keys=ctx.signing_keys,
            verify=ctx.check_signatures,
        )
        regex_substitutions = [
            TypingRegexSubstitution(
                pattern=r"quay\.io", replacement=image_name_src.endpoint
            )
        ]
        release_metadata_translated = await translate_release_metadata(
            regex_substitutions=regex_substitutions,
            release_metadata=release_metadata,
        )
        for img_name_dest in image_name_dest:
            LOGGER.info("Mirroring release to: %s ...", img_name_dest)
            await put_release(
                release_name=img_name_dest,
                registry_v2=ctx.registry_v2,
                release_metadata=release_metadata_translated,
                verify=False,  # Already verified above (or not =/) ...
            )
            if ctx.registry_v2.dry_run:
                LOGGER.info(
                    "Dry run completed for release: %s", img_name_dest.resolve_name()
                )
            else:
                LOGGER.info("Mirrored release to: %s", img_name_dest.resolve_name())
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registry_v2.close()


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
