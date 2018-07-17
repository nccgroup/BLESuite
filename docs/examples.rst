BLESuite Examples
=================

The following are examples of how to use BLESuite:

Using the Central role
#############################

Scanning
---------
The following are examples of how to scan for advertising BLE devices.

Method 1: Timeout-based scan function
^^^^^^^^^^^^^^^^^^^^^^
This method uses the BLEConnectionManager scan() function to scan for devices until
a desired timeout is reached. The function then returns a list of discovered devices.

.. literalinclude:: examples/scan_timeout.py
            :language: python
            :linenos:

Method 2: Continual scan until desired device is found
^^^^^^^^^^^^^^^^^^^^^
This method directly enables the scan function through the BLEConnectionManager and then manages
the scanning state itself. The following example begins scanning for devices and stops scanning when either
a device with the Complete Local Name "BLEBoy" is found or the 10 second timeout is reached:

.. literalinclude:: examples/scan_particular_name.py
            :language: python
            :linenos:

Connecting to a BLE Peripheral
-------------------------------
The example below demonstrates how to connect to a Peripheral BLE device. Normally, the connection is established before continuing with further BLE communications, but BLESuite does not prevent a user from attempting to send communications on a connection handle without an established connection.
The `BLEConnectionManager.connect` function returns a boolean that represents whether a connection has been
established or not. Furthermore, the `BLEConnectionManager.is_connected` function can be used to determine
if a particular BLEConnection object is currently connected to a peer device.

.. literalinclude:: examples/connect_to_device.py
            :language: python
            :linenos:

Basic interactions with a BLE Peripheral
------------------------------------------

The following examples provide some general operations that can be performed on Peripheral devices when the
BLEConnectionManager is configured as the Central role.

All GATT procedures within BLESuite have a synchronous and asynchronous version. The synchronous version
will block the user's program until a response is received or the defined timeout is reached. The asynchronous version
sends the requests packet and then returns a GATTRequest object that can then be monitored and manged by the user or
ignored all together.

Synchronous read/write
^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: examples/sync_read_write.py
            :language: python
            :linenos:

Asynchronous read/write
^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: examples/async_read_write.py
            :language: python
            :linenos:

Smart scan
^^^^^^^^^^^

.. literalinclude:: examples/smart_scan_example.py
            :language: python
            :linenos:

Initiating pairing with a Peripheral
--------------------------------------

The following example demonstrates how to initiate pairing with a peer BLE device. The pairing security used
is determined based on the pairing parameters configured within the Security Manager associated with the BLEConnection
instance used for the connection and the peer's pairing parameters sent in the Pairing Response. To modify these
values, see :ref:`sm_pairing_properties_config`.

.. literalinclude:: examples/initiate_pairing.py
            :language: python
            :linenos:


Using the Peripheral role
#################################

Configuring the GATT server
----------------------------
When the BLEConnectionManager is configured to use the Peripheral role, it can expose a GATT server that
can be accessed by connected Central devices. The GATT server can be populated several ways, as demonstrated in the
following sections.

Method 1: From BLEDevice
^^^^^^^^^^^^^^^^^^^^^^^^^^
A BLEDevice object populated with GATT entities can be imported by the BLEConnectionManager to generate
corresponding GATT entities in the GATT server. This can be useful when using Smart Scan to analyze a target
device and then spoof the target by passing the newly created BLEDevice for import.

.. literalinclude:: examples/gatt_import_bledevice.py
            :language: python
            :linenos:


Method 2: Manual GATT server creation using PyBT
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The GATT server can also be populated directly by using BLEConnectionManager to retrieve its instance of
GATTServer and directly adding GATT entities using GATTServer class instance. This method requires
more in-depth knowledge about the GATT server, but can be used to add malformed values to GATT entities. The same
method could be used to access the ATT database directly and add malformed data there, depending on the use-case.

.. literalinclude:: examples/gatt_import_manual.py
            :language: python
            :linenos:



Advertising
------------
When a BLE Peripheral is advertising, it sends advertisement packets that can be read by other BLE devices
scanning for BLE devices (or sniffed). This data usually contains information about the advertising device, such
as the device name, number of services, or even the manufacturer.

.. literalinclude:: examples/advertising.py
            :language: python
            :linenos:

General operations
###################

.. _sm_pairing_properties_config:

Configuring security manager pairing properties
------------------------------------------------
Pairing properties are sent during the pairing process in the Pairing Request and Pairing
Response packets to indicate the sender's device properties and requested pairing attributes (request for MitM protections,
etc...). These properties are then used by the devices to select a pairing method (LE Legacy or LESC) and
an association model used to establish the temporary key (JustWorks, Passkey Entry, Numeric Comparison, OOB, etc...).

To set these properties, use the BLEConnectionManager class instance to modify the Security Manager's
default property values or just the properties for a specific BLE connection that has already been established. The
following code example demonstrates both mechanisms:

.. literalinclude:: examples/configure_sm_pairing_properties.py
			:language: python
			:linenos:

Configuring security manager keys
-----------------------------
The Security Manager is responsible for storing LTKs and STKs for devices that have gone through the pairing process
and optionally the bonding process. These keys are used to establish an encrypted connection and must be saved in order
to re-establish an encrypted connection in the future (in the case of a bonding).

The keys are also associated
with a specific security mode and level, which are determined by the pairing method used to establish the encryption
keys. The security mode and level will be applied to the connection once the encryption is re-established.

The following examples allow users to insert encryption keys into the Security Manager for a particular device.

Note: The Security Manager encryption re-establishment is only supported by LE Legacy connections. Key look-ups are
done based on the EDIV and RAND supplied by the peer device.

Method 1: Programmatic configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. literalinclude:: examples/configure_sm_key_programmatic.py
            :language: python
            :linenos:

Method 2: From JSON
^^^^^^^^^^^^^^^^^^^^

Example Security Manager key database JSON:

.. literalinclude:: examples/long_term_key_database.json
            :language: json

Importing the above file into the Security Manager:

.. literalinclude:: examples/configure_sm_key_json.py
            :language: python
            :linenos:

Exporting security manager
----------------------------
The data stored within the Security Manager database can be retrieved by the user for storage or other
uses. The following is an example that creates a BLE Peripheral that begins advertising, waits for a connection,
waits for successful pairing to occur, then dumps the Security Manager database:

.. literalinclude:: examples/export_security_manager.py
            :language: python
            :linenos:

The scenario above can be reproduced with a mobile device running a BLE application that can interact with the
GATT server BLESuite is hosting, such as LightBlue or Nordic's nRF Connect. To do so, connect to the device and
attempt to read from the exposed characteristic. This will cause an error to be returned since the connection
has insufficient encryption and the mobile application should immediately attempt to pair (a common behavior with mobile devices).


.. _gatt_server_export

Exporting a BLEDevice
----------------------
A BLEDevice object represents a BLE device and any attributes stored on the device. This object is automatically
created when performing a scan of a target device, such as using a smart scan, service scan, etc... The BLEDevice
object can then be exported to a JSON file for storage and/or manipulation for later use (see :ref:gatt_server_export).

.. literalinclude:: examples/export_bledevice.pyt
            :language: python
            :linenos:

The following is the exported JSON file created from the example above:

.. literalinclude:: examples/export_device.json
            :language: json

Importing a BLEDevice from JSON
-------------------------

Using the JSON format described above, a BLEDevice object can be populated using the import functionality:

.. literalinclude:: examples/import_bledevice.py
            :language: python
            :linenos:

Configuring GATT event handling
--------------------------------
The following sections describe the various event and procedure hooks that can be configured with BLESuite.
This allows the user to trigger user-code based on certain events, modify results of a client ATT operation (or
prevent a response from being sent at all), and even modify the results of ATT security checks when attributes
are accessed by a client.

Event routing handlers
^^^^^^^^^^^^^^^^^^^^
Event routing handlers (`blesuite.event_handler.BTEventHandler`) is an event handling class that
can be passed to a BLEConnectionManager instance. The handlers are invoked after a specific event type
has been received and processed in blesuite.pybt.core . By default, the BTEventHandler used by BLEConnectionManager
provides useful logging and handles sending a Handle Value Confirmation when a Handle Value Indication ATT packet
is received.

The following is an example of how the class can be used to simply send a random and malformed ATT packet
to a peer device when receiving a Handle Value Indication ATT packet.

.. literalinclude:: examples/hooks_event_handler.py
            :language: python
            :linenos:

Client ATT operation hooks (BLEConnectionManger as Peripheral)
^^^^^^^^^^^
Client ATT operation hooks (blesuite.event_handler.ATTEventHook) are a function hooking method for ATT operations
carried out by a peer Central role device (ATT read, write, etc...). The functions intercept incoming state-changing
operations and allows the users to modify the state-changing parameters or discard them. Additionally, the user
can intercept outgoing ATT responses to modify or discard the response. By default, the hooks log the event
and allow the program to continue.

The following example shows how the hook can be used to alter all incoming write requests to have the same
static value and modify all ATT Responses generated in response to an ATT Read Request to always be an ATT Read
Response containing the payload "Intercepted!":

.. literalinclude:: examples/hooks_att_operation_hooks.py
            :language: python
            :linenos:


ATT security hooks
^^^^^^^^^^^^^^^^^^
ATT security hooks (blesuite.event_handlers.ATTSecurityHook) allow ATT security checks to be hooked by the user.
These security checks occur when a BLE Central device attempts to access an attribute on the locally running
GATT server, which requires a query to the attribute database. When the access attempt is made, the database
checks the target attribute's configured properties and permissions to determine whether the operation is valid,
whether encryption is required and set, and then makes several authentication and authorization checks.

Each of the previously described security checks call the ATT security hooks before returning the results
to the attribute database. This allows the user to view the attribute properties, the requested operation and
its associated properties, and modify the overall result.

These hooks are also how a user can implement the authorization property for a given attribute. By default, if
an attribute is marked as requiring authorization (implementation specific) and the associated event hook is not
set, requested access of the target attribute will always be denied unless overridden.

The following example demonstrates how to use the ATT security hooks in order to implement an authorization
procedure and also shows how the user can hook the ATT authentication check
when an ATT request is made by a peer.

.. literalinclude:: examples/hooks_att_security_hooks.py
            :language: python
            :linenos:


Advanced operations
#####################

Sending manually constructed packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some use-cases may require the ability to send manually constructed packets. The packets may either be
valid and well-formed or malformed.

.. literalinclude:: examples/advanced_manual_packets.py
            :language: python
            :linenos:

Sending packets as a Peripheral
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some use-cases may require BLESuite applications to send BLE packets while running as a Peripheral device.

.. literalinclude:: examples/advanced_peripheral_send_packets.py
            :language: python
            :linenos:

Scanning and spoofing a device
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following example demonstrates using both BLE roles to scan a target Peripheral BLE device to then
generate a similar GATT server and spoof the same Bluetooth address as the target:

.. literalinclude:: examples/advanced_find_bleboy_clone_advertise.py
            :language: python
            :linenos:
