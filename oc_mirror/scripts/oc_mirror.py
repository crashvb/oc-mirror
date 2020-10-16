#!/usr/bin/env python

"""Docker verify command line interface."""

import logging
import sys

from traceback import print_exception
from typing import List, TypedDict

import click

from click.core import Context
from docker_registry_client_async import ImageName
from docker_sign_verify import (
    ArchiveImageSource,
    DeviceMapperRepositoryImageSource,
    ImageSource,
    RegistryV2ImageSource,
)

from .utils import (
    async_command,
    LOGGING_DEFAULT,
    logging_options,
    set_log_levels,
    version,
)
from .utils import to_image_name

LOGGER = logging.getLogger(__name__)


class TypingContextObject(TypedDict):
    # pylint: disable=missing-class-docstring
    check_signatures: bool
    dest_image_name: ImageName
    dry_run: bool
    src_image_name: ImageName
    verbosity: int


def get_context_object(context: Context) -> TypingContextObject:
    """Wrapper method to enforce type checking."""
    return context.obj


@async_command
async def verify(context: Context):  # -> List[ImageSourceVerifyImageSignatures]:
    """Verifies an image(s)."""

    results = []

    ctx = get_context_object(context)
    try:
        # results = await TODO
        ...
    except Exception as exception:  # pylint: disable=broad-except
        if ctx["verbosity"] > 0:
            logging.fatal(exception)
        if ctx["verbosity"] > LOGGING_DEFAULT:
            exc_info = sys.exc_info()
            print_exception(*exc_info)
        sys.exit(1)
    finally:
        # await ctx["imagesource"].close()
        ...

    return results


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
@logging_options
@click.argument("src_image_name", callback=to_image_name, required=True)
@click.argument("dest_image_name", callback=to_image_name, required=True)
@click.pass_context
def cli(
    context: Context,
    check_signatures: bool,
    dry_run: False,
    src_image_name: ImageName,
    dest_image_name: ImageName,
    verbosity: int = LOGGING_DEFAULT,
):
    """Replicates an OpenShift release between a source and destination registry."""

    if verbosity is None:
        verbosity = LOGGING_DEFAULT

    set_log_levels(verbosity)
    context.obj = {
        "check_signatures": check_signatures,
        "dry_run": dry_run,
        "verbosity": verbosity,
        "src_image_name": src_image_name,
        "dest_image_name": dest_image_name,
    }

    verify(context)


cli.add_command(version)

if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    cli()
