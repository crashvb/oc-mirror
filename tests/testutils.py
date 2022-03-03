#!/usr/bin/env python

"""Utility classes."""

import logging
import shlex
import sys

from functools import wraps
from pathlib import Path
from typing import Union

import pytest

from click.testing import CliRunner, Result
from docker_registry_client_async import ImageName

LOGGER = logging.getLogger(__name__)


class OCMCliRunner(CliRunner):
    """
    click.testing.CliRunner.invoke w/o isolation, as it breaks logging:
    https://github.com/pallets/click/issues/824
    """

    def invoke(self, cli, args=None, catch_exceptions=True, **extra) -> Result:
        # pylint: disable=arguments-differ
        exc_info = None
        exception = None
        exit_code = 0

        if isinstance(args, str):
            args = shlex.split(args)

        if "prog_name" not in extra:
            extra["prog_name"] = self.get_default_prog_name(cli)

        try:
            cli.main(args=args or (), **extra)
        except SystemExit as exc:
            exc_info = sys.exc_info()
            exit_code = exc.code
            if exit_code is None:
                exit_code = 0

            if exit_code != 0:
                exception = exc

            if not isinstance(exit_code, int):
                sys.stdout.write(str(exit_code))
                sys.stdout.write("\n")
                exit_code = 1

        except Exception as exc:  # pylint: disable=broad-except
            if not catch_exceptions:
                raise
            exc_info = sys.exc_info()
            exit_code = 1
            exception = exc

        return Result(
            exception=exception,
            exit_code=exit_code,
            exc_info=exc_info,
            return_value=exit_code,
            runner=self,
            stderr_bytes=b"",
            stdout_bytes=b"",
        )


def equal_if_unqualified(image_name0: ImageName, image_name1: ImageName) -> bool:
    """
    Determines if two images names are equal if evaluated as unqualified.

    Args:
        image_name0: The name of the first image.
        image_name1: The name of the second image.

    Returns:
        True if the images names are equal without considering the endpoint component.
    """
    img_name0 = image_name0.clone()
    img_name0.endpoint = None
    img_name1 = image_name1.clone()
    img_name1.endpoint = None
    return str(img_name0) == str(img_name1)


def get_test_data_path(request, name) -> Path:
    """Helper method to retrieve the path of test data."""
    return Path(request.fspath).parent.joinpath("data").joinpath(name)


def get_test_data(request, klass, name, mode="rb") -> Union[bytes, str]:
    # pylint: disable=unspecified-encoding
    """Helper method to retrieve test data."""
    key = f"{klass}/{name}"
    result = request.config.cache.get(key, None)
    if result is None:
        path = get_test_data_path(request, name)
        with open(path, mode) as file:
            result = file.read()
            # TODO: How do we / Should we serialize binary data?
            # request.config.cache.set(key, result)
    return result


def needs_credentials(*credentials):
    """Validates the state of RegistryV2.docker_registry_client_async.credentials before invoking the wrapped method."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            param = "registry_v2"
            if "registry_v2" in kwargs:
                ...
                for credential in credentials:
                    if credential not in str(
                        kwargs[param].docker_registry_client_async.credentials
                    ):
                        pytest.skip(
                            f"RegistryV2 does not contain required credentials for: {credential}! "
                            "Verify the default docker credentials store, or the location specified "
                            "by DRCA_CREDENTIALS_STORE."
                        )
            else:
                LOGGER.warning(
                    "Decorator %s used on %s without parameter %s!",
                    __name__,
                    func,
                    param,
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
