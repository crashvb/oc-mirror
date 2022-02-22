#!/usr/bin/env python

"""Utility classes."""

import click

from oc_mirror import __version__


@click.command()
def version():
    """Displays the utility version."""
    print(__version__)
