Using
=============

`blesuite`
-----------

The `blesuite` CLI provides some of the basic functionality provided by BLESuite that a
user can call to quickly interact with a Peripheral BLE device. The CLI supports the following:

* BLE advertisement scanning
* BLE Peripheral service scanning - discover services, characteristics, and descriptors running on a device
* BLE Peripheral smart scanning - same as service scanning, but can attempt to read from all descriptors and generates a populated BLEDevice class instance
* Read/Write (sync/async, depending how fast the requests need to fire) - Read/write from/to attributes using specified handles, UUIDs, data, and/or files
* Subscribe - enable indications and/or notifications for specified attributes and listen until specified timeout is reached
* BDADDR Spoofing - Change the Bluetooth address of your host's Bluetooth adapter (only supported by some chipsets)

Usage
^^^^^^^^^^

.. code-block:: text

    blesuite -h


Examples
^^^^^^^^^^^^^

Advertising scan:

.. code-block:: text

    blesuite scan


Smart Scan:

.. code-block:: text

    blesuite smartscan -d 11:22:33:44:55:66 -t random


Read (using both handles and UUIDs):

.. code-block:: text

    blesuite read -d 11:22:33:44:55:66 -t random -u 00002a38-0000-1000-8000-00805f9b34fb 00002901-0000-1000-8000-00805f9b34fb -a 0052 0053


Write:

.. code-block:: text

    blesuite write -d 11:22:33:44:55:66 -t random -a 4e --data "test"


Write using payload in file:

.. code-block:: text

    blesuite write -d 11:22:33:44:55:66 -t random -a 4e --files payloads.txt --payload-delimiter :


Subscribe:

.. code-block:: text

    blesuite subscribe -d 11:22:33:44:55:66 -t random -m 1 -a 0056



Spoof:

.. code-block:: text

    blesuite spoof --address 55:44:33:22:11:00



`ble-replay`
-------------

`ble-replay` is a tool for recording, modifying, and replaying Bluetooth Low
Energy (BLE) communications for testing application layer interactions between a
mobile app and a BLE peripheral. This tool is useful if an app writes some
characteristics on the BLE device in order to configure/unlock/disable some
feature or perform some other state-changing action on the device.

The `ble-replay` CLI provides a quick and easy method of parsing packet captures, parsing them into a readable
JSON format, and automatically replaying them to a target BLE peripheral device.

The tool currently supports parsing Bluetooth logs in `btsnoop` formats (used by Android HCI logs and `hcidump`)
and the PCAPNG format output by Ubertooth One's BTLE tools (see <https://github.com/greatscottgadgets/ubertooth/blob/master/host/doc/ubertooth-btle.md>).



Prerequisites
^^^^^^^^^^^^^^^^

* BLESuite
* PyShark - Note: Be sure to run Wireshark, open Preferences-> Protocols -> DLT_USER and add an entry for DLT=147 where payload protocol is btle.

Usage
^^^^^^^^

.. code-block:: text

    ble-replay -h


Examples
^^^^^^^^^^^^^

Fetch the HCI log from Android device and replay it as is:

.. code-block:: text

    ble-replay -f -r


Parse an HCI log from your computer and replay it as is:

.. code-block:: text

    ble-replay -p btsnoop_hci.log -r



Fetch the HCI log from Android device and write modifiable replay data to disk:

.. code-block:: text

    ble-replay -f -of replaydata.json


Modify the hex values as needed and then replay that file using:

.. code-block:: text

    ble-replay -i 0 -d 11:22:33:44:55:66 -t random -if replaydata.json -r



