from blesuite.entities.gatt_device import BLEDevice
from blesuite.entities.permissions import Permissions
import blesuite.utils.att_utils as att_utils
import json

# Initialize new BLEDevice object
ble_device = BLEDevice()

# Create a new primary service with starting handle 1, ending handle 6, and UUID 2124
service1 = ble_device.add_service(0x01, 0x06, "2124")

# Add characteristic to service1 with value at 0x03, declaration at handle 0x02, UUID 2124,
# GATT properties read and write, and with value "testValue1"
characteristic1 = service1.add_characteristic(0x03, 0x02, "2124",
                                              Permissions.READ | Permissions.WRITE,
                                              "testValue1")
# Add a user descriptor to characteristic that describes its value at handle 4
characteristic1.add_user_description_descriptor(0x04,
    "Characteristic 1")

# Add a service include at handle 5, handle of service to be included (service2), end handle of included service,
# and UUID of included service
service1.add_include(0x05, 0x07, 0x0c, "000AA000-0BB0-10C0-80A0-00805F9B34FB")

# Add service 2
service2 = ble_device.add_service(0x07, 0x0c, "000AA000-0BB0-10C0-80A0-00805F9B34FB")

# Add characteristic2 to service 2, this time specifying GATT propertries: read, write, and notify. As well
# as setting ATT attribute permissions for the characterisitic value descriptor attribute
characteristic2 = service2.add_characteristic(0x09, 0x08, "2125",
                                              Permissions.READ | Permissions.WRITE | Permissions.NOTIFY,
                                              "newTestValue",
                                              characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                              characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION)

# To generate Security Mode objects used as attribute permissions,
# you can alternatively use the att_utils helper function:
# att_utils.get_att_security_mode_from_mode_and_level(mode, level)

# Add user descriptor to characteristic
characteristic2.add_user_description_descriptor(0x0a, "Characteristic2")

# Add client characteristic configuration descriptor to support the NOTIFY GATT property.
characteristic2.add_client_characteristic_configuration_descriptor(0x0b)

# Export device
export_dict = ble_device.export_device_to_dictionary()

# Write device to JSON
device_json_output = json.dumps(export_dict, indent=4)
f = open("device.json", "w")
f.write(device_json_output)
f.close()
