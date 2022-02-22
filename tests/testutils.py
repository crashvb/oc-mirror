#!/usr/bin/env python

"""Utility classes."""

from pathlib import Path
from typing import Union

from docker_registry_client_async import ImageName


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
