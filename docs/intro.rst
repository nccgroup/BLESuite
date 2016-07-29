Introduction
============

BLESuite is a python package to make Bluetooth Low Energy (BLE) device communication more user
friendly. By utilizing pygattlib and the Bluez Bluetooth stack,
we are able to scan, read from, and write to BLE devices using Generic Attribute Profile (GATT) over the
Attribute protocol (ATT).

Features:
    * Scan for BTLE devices
    * Scan BTLE devices for primary services and characteristics
    * SmartScan - Scan a BTLE device for basic information, primary services, characteristics, and
    then determining which descriptors are present, their handle, permissions, and current value (if applicable)
    * Write arbitrary values to a BTLE device (synchronously or asynchronously)
    * Read values from a specific handle and/or UUID on a BTLE device (synchronously or asynchronously)
    * Installs a python module called bdaddr that enables a user to spoof the BD_ADDR of their host's
    Bluetooth adapter (only supports some chipsets. This is a modified version of the BlueZ's bdaddr.c). This can be enabled by uncommenting a line in setup.py.
    Beware that this does require tools to compile CPython and libbluetooth.

Note to the reader:
    This tool library developed and tested on Debian 8. Specifically the testing distribution that
    includes a more current version of the Bluez Bluetooth stack (version 5.36 at the time of writing this)

    In order to access Bluetooth Low Energy functionality, you must have access
    to a Bluetooth adapter that
    supports it. I use the Pluggable Technologies USB-BT4LE adapter.
