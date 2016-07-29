#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
# This software is under the terms of Apache License v2 or later.

from gattlib import DiscoveryService

service = DiscoveryService("hci0")
devices = service.discover(4)

for address, name in list(devices.items()):
    print("name: {}, address: {}".format(name, address))

print("Done.")
