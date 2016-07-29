#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
# This software is under the terms of Apache License v2 or later.

from __future__ import print_function

import sys
from gattlib import GATTRequester

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <addr>".format(sys.argv[0]))
        sys.exit(1)

    requester = GATTRequester(sys.argv[1], False)

    print("Connecting...")
    sys.stdout.flush()
    requester.connect(True)

    primary = requester.discover_primary()
    for prim in primary:
        print(prim)

    print("Done.")
