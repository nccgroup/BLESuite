#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
# This software is under the terms of Apache License v2 or later.

from __future__ import print_function

import sys
import time
from gattlib import GATTRequester


class PassiveDisconnect(object):
    def __init__(self, address):
        self.requester = GATTRequester(address, False)

        self.connect()
        self.wait_disconnection()

    def connect(self):
        print("Connecting...", end=' ')
        sys.stdout.flush()

        self.requester.connect(True)
        print("OK!")

    def wait_disconnection(self):
        status = "connected" if self.requester.is_connected() else "not connected"
        print("Checking current status: {}".format(status))
        print("\nNow, force a hardware disconnect. To do so, please switch off,\n"
              "reboot or move away your device. Don't worry, I'll wait...")

        while self.requester.is_connected():
            time.sleep(1)

        print("\nOK. Current state is disconnected. Congratulations ;)")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: {} <addr>".format(sys.argv[0]))
        sys.exit(1)

    PassiveDisconnect(sys.argv[1])
    print("Done.")
