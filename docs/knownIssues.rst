Known Issues
============

The following are a list of known issues and potential solutions:

* "RuntimeError: Could not update HCI connection: Operation not permitted"
    Ensure that a BTLE compatible adapter is being used
    (should be labeled Bluetooth Smart or Bluetooth 4.0+ compatible),
    that your OS recognizes the Bluetooth adapter, and that
    the tool is being run with sudo privilege.

* "RuntimeError: Channel or attrib not ready"
    Ensure that the device you are trying to communicate with
    is advertising and/or powered on. If you sure the device
    is advertising, then try setting the address type as "random" instead of public
    or chaning the security level [low | medium | high]
    (some devices use a random address and different security levels for pairing,
    please see the Bluetooth specification
    for more information about this feature)

* "When scanning for BTLE devices, some of the devices are listed as 'Unavailable'"
    If you need to know the name of a device and it was not available via the device's
    advertising, try reading UUID "2A00" (the defined device name UUID). For additional defined
    device UUIDs, see bleSmartScan.py or https://developer.bluetooth.org/gatt/Pages/default.aspx
    and view the defined characteristics and services (not all of the listed attributes
    have to be defined for a device)