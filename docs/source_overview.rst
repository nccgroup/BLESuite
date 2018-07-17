Contributing
==============================

The purpose of this guide is to provide the layout for the BLESuite module and provide a brief description
for what each module is responsible for. This information can be used to add use-case specific modifications
or for further development.

Module Structure and Descriptions
------------------



* **blesuite.connection_manager module** - Creates and manages the BLEConnectionManager that represents the host's HCI device. The manager can then be used to establish connections with other BLE devices and send/receive messages.
* **blesuite.event_handler module** - An event handler class that provides several classes of event hooks. These hooks are passed to the connection manager and called when certain events are triggered (ATT events, SM events, security checks, etc...).
* **blesuite.gatt_procedures module** - Used by the BLEConnectionManager to execute various GATT procedures. This module does not need to be called directly by the user.
* **blesuite.scan module** - A tool with a predefined procedure to scan for advertising BLE devices.
* **blesuite.smart_scan module** - Used by the BLEConnectionManager to conduct a Smart Scan of a target BLE device. The scan will check for services, include services, characteristics, and descriptors. A scan can also attempt to read from each discovered attribute. This module does not need to be called directly by the user.
* blesuite.cli package - This package contains the BLESuite CLI tools, which are installed by default.
    * blesuite.cli.ble_replay module - BLE-Replay CLI tool. Used to replay a set of GATT write operations that have been parsed from a packet capture source.
    * blesuite.cli.blesuite_cli module - The BLESuite CLI tool that provides access to the core functionality of BLESuite: device scanning, GATT read, GATT write, BDADDR spoofing (if installed)
    * blesuite.cli.blesuite_wrapper module - Several wrapper functions around BLESuite, used by the CLI.
* blesuite.entities package - BLESuite entities that represent a BLE device and all attributes served by it.
    * blesuite.entities.gatt_characteristic module
    * blesuite.entities.gatt_descriptor module
    * blesuite.entities.gatt_device module
    * blesuite.entities.gatt_include module
    * blesuite.entities.gatt_service module
    * blesuite.entities.permissions module
* blesuite.pybt package - The PyBT stack used to create a Bluetooth Socket and manage all BLE communication.
    * blesuite.pybt.att module - Contains logic for handling ATT packets as the Peripheral role.
    * blesuite.pybt.core module - Contains all logic for communicating with a BLE device, handles packet processing and routing, and is responsible for making a best-effort matching of GATT requests sent to received GATT responses (if the host is acting as a central device).
    * blesuite.pybt.gap module - Contains GAP definitions and helper functions.
    * blesuite.pybt.gatt module - Contains logic for GATT server and Attribute Database.
    * blesuite.pybt.roles module - Contains definitions for BLE roles the host can assume.
    * blesuite.pybt.sm module - Contains logic for the Security Manager and Security Manager protocol.
    * blesuite.pybt.stack module - Contains logic for creating the socket to the host's HCI device, is responsible for marking packets with correct metadata (target layer, event type, etc...), and contains logic for gracefully closing the socket.
* blesuite.replay package - The BLE replay package used to parse and replay BLE packets.
    * blesuite.replay.hci_parser module
    * blesuite.replay.util module
* blesuite.utils package - Utility functions used by BLESuite.
    * blesuite.utils.att_utils module
    * blesuite.utils.gap_utils module
    * blesuite.utils.print_helper module
    * blesuite.utils.validators module


