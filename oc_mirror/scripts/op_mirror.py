#!/usr/bin/env python

"""Operator mirror command line interface."""

import logging
import sys

from pathlib import Path
from traceback import print_exception
from typing import Dict, List, NamedTuple, Optional

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

from oc_mirror.oprelease import (
    get_release_metadata,
    log_release_metadata,
    put_release,
    translate_release_metadata,
    TypingGetReleaseMetadata,
    TypingRegexSubstitution,
)

from .utils import OPENSHIFT_SIGNATURE_STORES, version

LOGGER = logging.getLogger(__name__)


class TypingContextObject(NamedTuple):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    registry_v2: RegistryV2
    signature_stores: List[str]
    signing_keys: List[str]
    verbosity: int


def _convert_package_channel(*, package_channel: Optional[List[str]]) -> Dict[str, str]:
    """Convert tuple of ":" separated pairs into a dictionary, or None."""
    if package_channel:
        package_channel = [
            item.split(":") if ":" in item else (item, None) for item in package_channel
        ]
        package_channel = {package: channel for package, channel in package_channel}
    return package_channel


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
    envvar="OPM_SIGNATURE_STORE",
    help="Url of a signature store to use for retrieving signatures. Can be passed multiple times.",
    multiple=True,
)
@click.option(
    "-k",
    "--signing-key",
    envvar="OPM_SIGNING_KEY",
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
    """Utilities for working with operator releases."""
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
        check_signatures=check_signatures,
        registry_v2=RegistryV2(dry_run=dry_run),
        signature_stores=signature_store,
        signing_keys=signing_keys,
        verbosity=verbosity,
    )


@cli.command()
@click.argument("index_name", callback=to_image_name, required=True)
@click.argument("package_channel", nargs=-1)
@click.option("--sort-metadata", help="Sort metadata keys.", is_flag=True)
@click.option(
    "--translate",
    help="Translate the registry endpoint(s) based on the index location.",
    is_flag=True,
)
@click.pass_context
@async_command
async def dump(
    context: Context,
    index_name: ImageName,
    package_channel: List[str],
    sort_metadata: bool = False,
    translate: bool = False,
) -> TypingGetReleaseMetadata:
    """Dumps the metadata for an operator release(s)."""
    ctx = get_context_object(context)

    try:
        LOGGER.info("Retrieving metadata for index: %s ...", index_name)
        release_metadata = await get_release_metadata(
            index_name=index_name,
            package_channel=_convert_package_channel(package_channel=package_channel),
            registry_v2=ctx.registry_v2,
            signature_stores=ctx.signature_stores,
            signing_keys=ctx.signing_keys,
            verify=ctx.check_signatures,
        )
        if translate:
            regex_substitutions = [
                TypingRegexSubstitution(
                    pattern=r"quay\.io", replacement=index_name.endpoint
                ),
                TypingRegexSubstitution(
                    pattern=r"registry\.redhat\.io", replacement=index_name.endpoint
                ),
            ]
            release_metadata = await translate_release_metadata(
                regex_substitutions=regex_substitutions,
                release_metadata=release_metadata,
            )
        await log_release_metadata(
            index_name=index_name,
            release_metadata=release_metadata,
            sort_metadata=sort_metadata,
        )
        return release_metadata
    except Exception as exception:  # pylint: disable=broad-except
        if ctx.verbosity > 0:
            logging.fatal(exception)
        if ctx.verbosity > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        await ctx.registry_v2.close()


@cli.command()
@click.argument("index_name_src", callback=to_image_name, required=True)
@click.argument("index_name_dest", callback=to_image_name, required=True)
@click.argument("package_channel", nargs=-1)
@click.pass_context
@async_command
async def mirror(
    context: Context,
    index_name_dest: ImageName,
    index_name_src: ImageName,
    package_channel: List[str],
):
    """Replicates a operator release(s) between a source and destination registry(ies)."""
    ctx = get_context_object(context)
    try:
        LOGGER.info("Retrieving metadata for index: %s ...", index_name_src)
        release_metadata = await get_release_metadata(
            index_name=index_name_src,
            package_channel=_convert_package_channel(package_channel=package_channel),
            registry_v2=ctx.registry_v2,
            signature_stores=ctx.signature_stores,
            signing_keys=ctx.signing_keys,
            verify=ctx.check_signatures,
        )
        regex_substitutions = [
            TypingRegexSubstitution(
                pattern=r"quay\.io", replacement=index_name_src.endpoint
            ),
            TypingRegexSubstitution(
                pattern=r"registry\.redhat\.io", replacement=index_name_src.endpoint
            ),
        ]
        release_metadata_translated = await translate_release_metadata(
            regex_substitutions=regex_substitutions,
            release_metadata=release_metadata,
        )
        LOGGER.info("Mirroring index to: %s ...", index_name_dest)
        await put_release(
            index_name=index_name_dest,
            registry_v2=ctx.registry_v2,
            release_metadata=release_metadata_translated,
            verify=False,  # Already verified above (or not =/) ...
        )
        if ctx.registry_v2.dry_run:
            LOGGER.info(
                "Dry run completed for index: %s", index_name_dest.resolve_name()
            )
        else:
            LOGGER.info("Mirrored index to: %s", index_name_dest.resolve_name())
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
