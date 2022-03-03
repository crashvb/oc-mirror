#!/usr/bin/env python

"""Utility classes."""

import click

from oc_mirror import __version__

OPENSHIFT_SIGNATURE_STORES = [
    "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release"
]


@click.command()
def version():
    """Displays the utility version."""
    print(__version__)
