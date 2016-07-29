#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
# This software is under the terms of Apache License v2 or later.

from __future__ import print_function

import sys
import time
from gattlib import GATTRequester


class ActiveDisconnect(object):
    def __init__(self, address):
        self.requester = GATTRequester(address, False)

        self.connect()
        self.check_status()
        self.disconnect()
        self.check_status()

    def connect(self):
        print("Connecting...", end=' ')
        sys.stdout.flush()

        self.requester.connect(True)
        print("OK!")

    def check_status(self):
        status = "connected" if self.requester.is_connected() else "not connected"
        print("Checking current status: {}".format(status))
        time.sleep(1)

    def disconnect(self):
        print("Disconnecting...", end=' ')
        sys.stdout.flush()

        self.requester.disconnect()
        print("OK!")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <addr>".format(sys.argv[0]))
        sys.exit(1)

    ActiveDisconnect(sys.argv[1])
    print("Done.")
