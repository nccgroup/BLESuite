from blesuite.entities.gatt_device import BLEDevice
import json

# read BLEDevice configuration from device.json
with open("device.json", "r") as f:
    device_dict = json.loads(f.read())

# create new BLEDevice class instance
ble_device = BLEDevice()

# import device configuration using JSON file
ble_device.import_device_from_dictionary(device_dict)

# modify characteristic value
ble_device.services[0].characteristics[0].value = "MY NEW TEST VALUE"

# print device structure
ble_device.print_device_structure()
