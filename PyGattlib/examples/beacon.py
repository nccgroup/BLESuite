#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

# Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
# This software is under the terms of Apache License v2 or later.

from gattlib import BeaconService
import time

service = BeaconService("hci0")

service.start_advertising("11111111-2222-3333-4444-555555555555",
            1, 1, 1, 200)
time.sleep(5)
service.stop_advertising()

print("Done.")
