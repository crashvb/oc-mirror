#!/usr/bin/env python

"""Utility classes."""

import click
from textwrap import dedent

from oc_mirror import __version__

OPENSHIFT_SIGNATURE_STORES = [
    "https://mirror.openshift.com/pub/openshift-v4/signatures/openshift/release"
]


@click.command()
def version():
    """Displays the utility version."""
    print(
        dedent(
            f"""\
            oc-mirror {__version__}
            
            Copyright (C) 2020-2022  Richard Davis
            License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>
            This program comes with ABSOLUTELY NO WARRANTY.
            This is free software, and you are welcome to redistribute it under certain
            conditions; reference the full license for details.
            """
        )
    )
