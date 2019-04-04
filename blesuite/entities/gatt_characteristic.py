from blesuite.entities.permissions import Permissions
from blesuite.entities.gatt_descriptor import BLEDescriptor
import blesuite.utils.att_utils as att_utils


# Includes information to create Characteristic Declaration Descriptor and Characteristic Value Declaration Descriptor
class BLECharacteristic(object):
    """ BLECharacteristic is used to represent a characteristic of a service located on a BTLE device

        :var value_handle: Handle for attribute the characteristic's value is stored in (characteristic value declaration descriptor). Type int
        :var handle: Handle for attribute of characteristic declaration descriptor.Type int
        :var uuid: UUID of characteristic. Type str
        :var gatt_properties: GATT properties value of characteristic (blesuite.entities.permissions.Permissions.*)
        :var service_uuid: UUID of parent service. Type str
        :var value: Value held by characteristic. Type str
        :var characteristic_definition_attribute_properties: Characteristic definition attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ). Type: blesuite.utils.att_utils.ATT_PROP_*
        :var characteristic_definition_attribute_read_permission: Required security mode to read Characteristic definition attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var characteristic_definition_attribute_write_permission: Required security mode to write to Characteristic definition attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var characteristic_definition_attribute_require_authorization: Flag to indicate that access of the Characteristic definition attribute requires authorization (default False)
        :var characteristic_value_attribute_properties: Characteristic value attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ|blesuite.utils.att_utils.ATT_PROP_WRITE). Type: blesuite.utils.att_utils.ATT_PROP_*
        :var characteristic_value_attribute_read_permission: Required security mode to read Characteristic value attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var characteristic_value_attribute_write_permission: Required security mode to Characteristic value write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var characteristic_value_attribute_require_authorization: Flag to indicate that access of the Characteristic value attribute requires authorization (default False)
        :type characteristic_definition_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type characteristic_definition_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_definition_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_definition_attribute_require_authorization: bool
        :type characteristic_value_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type characteristic_value_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_value_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_value_attribute_require_authorization: bool
        :type value_handle: int - base 10
        :type handle: int - base 10
        :type uuid: str
        :type gatt_properties: int
        :type service_uuid: str
        :type value: str

    """
    def __init__(self, value_handle, handle, uuid, gatt_properties, service_uuid, value="",
                 characteristic_definition_attribute_properties=att_utils.ATT_PROP_READ,
                 characteristic_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 characteristic_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                 characteristic_definition_attribute_require_authorization=False,
                 characteristic_value_attribute_properties=att_utils.ATT_PROP_READ|att_utils.ATT_PROP_WRITE,
                 characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 characteristic_value_attribute_require_authorization=False
                 ):
        self.uuid = uuid
        self.parent_service_uuid = service_uuid
        self.value_handle = value_handle
        self.handle = handle
        # property is the permission set on a characteristic
        self.gatt_properties = gatt_properties
        self.value = value
        self.type = None
        self.type_string = ""
        self.descriptors = []
        self.characteristic_definition_attribute_properties = characteristic_definition_attribute_properties
        self.characteristic_definition_attribute_read_permission = characteristic_definition_attribute_read_permission
        self.characteristic_definition_attribute_write_permission = characteristic_definition_attribute_write_permission
        self.characteristic_definition_attribute_require_authorization = characteristic_definition_attribute_require_authorization
        self.characteristic_value_attribute_properties = characteristic_value_attribute_properties
        self.characteristic_value_attribute_read_permission = characteristic_value_attribute_read_permission
        self.characteristic_value_attribute_write_permission = characteristic_value_attribute_write_permission
        self.characteristic_value_attribute_require_authorization = characteristic_value_attribute_require_authorization

        self.determine_type()

    def calculate_permission(self):
        """
        Calculate a printable string of permissions for a characteristic
        based on its properties

        :return: Permission String
        :rtype: str
        """
        permission = ""
        for perm in Permissions.permission_dict.keys():
            if self.gatt_properties & perm == perm:
                if len(permission) == 0:
                    permission += Permissions.permission_dict[perm]
                else:
                    permission += " / " + Permissions.permission_dict[perm]

        return permission

    def determine_type(self):
        """
        Used by blesuite.entities.gatt_characteristic to populate gatt_characteristic.type_string with a readable
        type based on the characteristic's UUID. The defined characteristic types were pulled from
        https://www.bluetooth.com/specifications/gatt/characteristics

        :return:
        :rtype:
        """
        # Defined Characteristics from https://www.bluetooth.com/specifications/gatt/characteristics
        # last updated dict on 1/12/18
        type_dict = {
            0x2A7E: "Aerobic Heart Rate Lower Limit",
            0x2A84: "Aerobic Heart Rate Upper Limit",
            0x2A7F: "Aerobic Threshold",
            0x2A80: "Age",
            0x2A5A: "Aggregate",
            0x2A43: "Alert Category ID",
            0x2A42: "Alert Category ID Bit Mask",
            0x2A06: "Alert Level",
            0x2A44: "Alert Notification Control Point",
            0x2A3F: "Alert Status",
            0x2AB3: "Altitude",
            0x2A81: "Anaerobic Heart Rate Lower Limit",
            0x2A82: "Anaerobic Heart Rate Upper Limit",
            0x2A83: "Anaerobic Threshold",
            0x2A58: "Analog",
            0x2A59: "Analog Output",
            0x2A73: "Apparent Wind Direction",
            0x2A72: "Apparent Wind Speed",
            0x2A01: "Appearance",
            0x2AA3: "Barometric Pressure Trend",
            0x2A19: "Battery Level",
            0x2A1B: "Battery Level State",
            0x2A1A: "Battery Power State",
            0x2A49: "Blood Pressure Feature",
            0x2A35: "Blood Pressure Measurement",
            0x2A9B: "Body Composition Feature",
            0x2A9C: "Body Composition Measurement",
            0x2A38: "Body Sensor Location",
            0x2AA4: "Bond Management Control Point",
            0x2AA5: "Bond Management Features",
            0x2A22: "Boot Keyboard Input Report",
            0x2A32: "Boot Keyboard Output Report",
            0x2A33: "Boot Mouse Input Report",
            0x2AA6: "Central Address Resolution",
            0x2AA8: "CGM Feature",
            0x2AA7: "CGM Measurement",
            0x2AAB: "CGM Session Run Time",
            0x2AAA: "CGM Session Start Time",
            0x2AAC: "CGM Specific Ops Control Point",
            0x2AA9: "CGM Status",
            0x2ACE: "Cross Trainer Data",
            0x2A5C: "CSC Feature",
            0x2A5B: "CSC Measurement",
            0x2A2B: "Current Time",
            0x2A66: "Cycling Power Control Point",
            0x2A66: "Cycling Power Control Point",
            0x2A65: "Cycling Power Feature",
            0x2A65: "Cycling Power Feature",
            0x2A63: "Cycling Power Measurement",
            0x2A64: "Cycling Power Vector",
            0x2A99: "Database Change Increment",
            0x2A85: "Date of Birth",
            0x2A86: "Date of Threshold Assessment",
            0x2A08: "Date Time",
            0x2A0A: "Day Date Time",
            0x2A09: "Day of Week",
            0x2A7D: "Descriptor Value Changed",
            0x2A00: "Device Name",
            0x2A7B: "Dew Point",
            0x2A56: "Digital",
            0x2A57: "Digital Output",
            0x2A0D: "DST Offset",
            0x2A6C: "Elevation",
            0x2A87: "Email Address",
            0x2A0B: "Exact Time 100",
            0x2A0C: "Exact Time 256",
            0x2A88: "Fat Burn Heart Rate Lower Limit",
            0x2A89: "Fat Burn Heart Rate Upper Limit",
            0x2A26: "Firmware Revision String",
            0x2A8A: "First Name",
            0x2AD9: "Fitness Machine Control Point",
            0x2ACC: "Fitness Machine Feature",
            0x2ADA: "Fitness Machine Status",
            0x2A8B: "Five Zone Heart Rate Limits",
            0x2AB2: "Floor Number",
            0x2A8C: "Gender",
            0x2A51: "Glucose Feature",
            0x2A18: "Glucose Measurement",
            0x2A34: "Glucose Measurement Context",
            0x2A74: "Gust Factor",
            0x2A27: "Hardware Revision String",
            0x2A39: "Heart Rate Control Point",
            0x2A8D: "Heart Rate Max",
            0x2A37: "Heart Rate Measurement",
            0x2A7A: "Heat Index",
            0x2A8E: "Height",
            0x2A4C: "HID Control Point",
            0x2A4A: "HID Information",
            0x2A8F: "Hip Circumference",
            0x2ABA: "HTTP Control Point",
            0x2AB9: "HTTP Entity Body",
            0x2AB7: "HTTP Headers",
            0x2AB8: "HTTP Status Code",
            0x2ABB: "HTTPS Security",
            0x2A6F: "Humidity",
            0x2A2A: "IEEE 11073-20601 Regulatory Certification Data List",
            0x2AD2: "Indoor Bike Data",
            0x2AAD: "Indoor Positioning Configuration",
            0x2A36: "Intermediate Cuff Pressure",
            0x2A1E: "Intermediate Temperature",
            0x2A77: "Irradiance",
            0x2AA2: "Language",
            0x2A90: "Last Name",
            0x2AAE: "Latitude",
            0x2A6B: "LN Control Point",
            0x2A6A: "LN Feature",
            0x2AB1: "Local East Coordinate",
            0x2AB0: "Local North Coordinate",
            0x2A0F: "Local Time Information",
            0x2A67: "Location and Speed Characteristic",
            0x2AB5: "Location Name",
            0x2AAF: "Longitude",
            0x2A2C: "Magnetic Declination",
            0x2AA0: "Magnetic Flux Density - 2D",
            0x2AA1: "Magnetic Flux Density - 3D",
            0x2A29: "Manufacturer Name String",
            0x2A91: "Maximum Recommended Heart Rate",
            0x2A21: "Measurement Interval",
            0x2A24: "Model Number String",
            0x2A68: "Navigation",
            0x2A3E: "Network Availability",
            0x2A46: "New Alert",
            0x2AC5: "Object Action Control Point",
            0x2AC8: "Object Changed",
            0x2AC1: "Object First-Created",
            0x2AC3: "Object ID",
            0x2AC2: "Object Last-Modified",
            0x2AC6: "Object List Control Point",
            0x2AC7: "Object List Filter",
            0x2ABE: "Object Name",
            0x2AC4: "Object Properties",
            0x2AC0: "Object Size",
            0x2ABF: "Object Type",
            0x2ABD: "OTS Feature",
            0x2A04: "Peripheral Preferred Connection Parameters",
            0x2A02: "Peripheral Privacy Flag",
            0x2A5F: "PLX Continuous Measurement Characteristic",
            0x2A60: "PLX Features",
            0x2A5E: "PLX Spot-Check Measurement",
            0x2A50: "PnP ID",
            0x2A75: "Pollen Concentration",
            0x2A2F: "Position 2D",
            0x2A30: "Position 3D",
            0x2A69: "Position Quality",
            0x2A6D: "Pressure",
            0x2A4E: "Protocol Mode",
            0x2A62: "Pulse Oximetry Control Point",
            0x2A78: "Rainfall",
            0x2A03: "Reconnection Address",
            0x2A52: "Record Access Control Point",
            0x2A14: "Reference Time Information",
            0x2A3A: "Removable",
            0x2A4D: "Report",
            0x2A4B: "Report Map",
            0x2AC9: "Resolvable Private Address Only",
            0x2A92: "Resting Heart Rate",
            0x2A40: "Ringer Control point",
            0x2A41: "Ringer Setting",
            0x2AD1: "Rower Data",
            0x2A54: "RSC Feature",
            0x2A53: "RSC Measurement",
            0x2A55: "SC Control Point",
            0x2A4F: "Scan Interval Window",
            0x2A31: "Scan Refresh",
            0x2A3C: "Scientific Temperature Celsius",
            0x2A10: "Secondary Time Zone",
            0x2A5D: "Sensor Location",
            0x2A25: "Serial Number String",
            0x2A05: "Service Changed",
            0x2A3B: "Service Required",
            0x2A28: "Software Revision String",
            0x2A93: "Sport Type for Aerobic and Anaerobic Thresholds",
            0x2AD0: "Stair Climber Data",
            0x2ACF: "Step Climber Data",
            0x2A3D: "String",
            0x2AD7: "Supported Heart Rate Range",
            0x2AD5: "Supported Inclination Range",
            0x2A47: "Supported New Alert Category",
            0x2AD8: "Supported Power Range",
            0x2AD6: "Supported Resistance Level Range",
            0x2AD4: "Supported Speed Range",
            0x2A48: "Supported Unread Alert Category",
            0x2A23: "System ID",
            0x2ABC: "TDS Control Point",
            0x2A6E: "Temperature",
            0x2A1F: "Temperature Celsius",
            0x2A20: "Temperature Fahrenheit",
            0x2A1C: "Temperature Measurement",
            0x2A1D: "Temperature Type",
            0x2A94: "Three Zone Heart Rate Limits",
            0x2A12: "Time Accuracy",
            0x2A15: "Time Broadcast",
            0x2A13: "Time Source",
            0x2A16: "Time Update Control Point",
            0x2A17: "Time Update State",
            0x2A11: "Time with DST",
            0x2A0E: "Time Zone",
            0x2AD3: "Training Status",
            0x2ACD: "Treadmill Data",
            0x2A71: "True Wind Direction",
            0x2A70: "True Wind Speed",
            0x2A95: "Two Zone Heart Rate Limit",
            0x2A07: "Tx Power Level",
            0x2AB4: "Uncertainty",
            0x2A45: "Unread Alert Status",
            0x2AB6: "URI",
            0x2A9F: "User Control Point",
            0x2A9A: "User Index",
            0x2A76: "UV Index",
            0x2A96: "VO2 Max",
            0x2A97: "Waist Circumference",
            0x2A98: "Weight",
            0x2A9D: "Weight Measurement",
            0x2A9E: "Weight Scale Feature",
            0x2A79: "Wind Chill"
        }
        if self.uuid is None:
            return
        type_int = int(self.uuid[:8], 16)
        self.type = type_int
        if type_int in type_dict.keys():
            self.type_string = type_dict[type_int]

    def get_type_string(self):
        """
        Returns readable characteristic type string.

        :return: Type of characteristic
        :rtype: str
        """
        return self.type_string

    def get_descriptors(self):
        """
        Return a list of blesuite.entities.gatt_descriptors defined within the
        characteristic class instance.

        :return: List of descriptors
        :rtype: blesuite.entities.gatt_descriptors
        """
        return self.descriptors

    def export_characteristic_to_dictionary(self):
        """
        Exports characteristic information to a dictionary for use by the BLEDevice export functionality.

        :return: Dictionary representation of characteristic
        :rtype: dict
        """
        from collections import OrderedDict
        # ordered dictionary allows us to maintain the order we insert keys, this makes reading the resulting
        # dictionary easier
        characteristic_dict = OrderedDict()

        characteristic_dict['uuid'] = self.uuid
        characteristic_dict['handle'] = self.handle
        characteristic_dict['value_handle'] = self.value_handle
        characteristic_dict['value'] = self.value

        gatt_properties = []
        for perm in Permissions.permission_dict.keys():
            if self.gatt_properties & perm == perm:
                gatt_properties.append(Permissions.permission_dict[perm].lower())
        characteristic_dict['gatt_properties'] = gatt_properties

        attribute_properties = []
        if self.characteristic_definition_attribute_properties & att_utils.ATT_PROP_READ == att_utils.ATT_PROP_READ:
            attribute_properties.append("read")
        if self.characteristic_definition_attribute_properties & att_utils.ATT_PROP_WRITE == att_utils.ATT_PROP_WRITE:
            attribute_properties.append("write")
            characteristic_dict['characteristic_definition_attribute_properties'] = attribute_properties

        attribute_read_permissions = {"security_mode": self.characteristic_definition_attribute_read_permission.security_mode,
                                      "security_level": self.characteristic_definition_attribute_read_permission.security_level
                                      }
        characteristic_dict['characteristic_definition_attribute_read_permission'] = attribute_read_permissions

        attribute_write_permissions = {
            "security_mode": self.characteristic_definition_attribute_write_permission.security_mode,
            "security_level": self.characteristic_definition_attribute_write_permission.security_level
        }
        characteristic_dict['characteristic_definition_attribute_write_permission'] = attribute_write_permissions

        characteristic_dict[
            'characteristic_definition_attribute_require_authorization'] = self.characteristic_definition_attribute_require_authorization

        attribute_properties = []
        if self.characteristic_value_attribute_properties & att_utils.ATT_PROP_READ == att_utils.ATT_PROP_READ:
            attribute_properties.append("read")
        if self.characteristic_value_attribute_properties & att_utils.ATT_PROP_WRITE == att_utils.ATT_PROP_WRITE:
            attribute_properties.append("write")
            characteristic_dict['characteristic_value_attribute_properties'] = attribute_properties

        attribute_read_permissions = {
            "security_mode": self.characteristic_value_attribute_read_permission.security_mode,
            "security_level": self.characteristic_value_attribute_read_permission.security_level
            }
        characteristic_dict['characteristic_value_attribute_read_permission'] = attribute_read_permissions

        attribute_write_permissions = {
            "security_mode": self.characteristic_value_attribute_write_permission.security_mode,
            "security_level": self.characteristic_value_attribute_write_permission.security_level
        }
        characteristic_dict['characteristic_value_attribute_write_permission'] = attribute_write_permissions

        characteristic_dict[
            'characteristic_value_attribute_require_authorization'] = self.characteristic_value_attribute_require_authorization

        descriptors = []
        for descriptor in self.descriptors:
            descriptor_dict = descriptor.export_descriptor_to_dictionary()
            descriptors.append(descriptor_dict)

        characteristic_dict['descriptors'] = descriptors

        return characteristic_dict

    def import_characteristic_from_dictionary(self, characteristic_dictionary):
        """
        Populate characteristic attributes from a dictionary containing characteristic information.
        This is complimentary to export_characteristic_to_dictionary .

        :param characteristic_dictionary: Dictionary containing characteristic information
        :type characteristic_dictionary: dict
        :return:
        :rtype:
        :raises blesuite.pybt.gatt.InvalidUUIDException: if the provided characteristic dictionary contains a characteristic with an invalid UUID
        :raises blesuite.utils.validators.InvalidATTHandle: if the provided characteristic dictionary contains a characteristic with an invalid handle
        :raises blesuite.utils.validators.InvalidGATTProperty: if the provided characteristic dictionary contains a characteristic with an invalid GATT property
        :raises blesuite.utils.validators.InvalidATTProperty: if the provided characteristic dictionary contains a characteristic with an invalid attribute property
        :raises blesuite.utils.validators.InvalidATTSecurityMode: if the provided characteristic dictionary contains a characteristic with an invalid attribute permission
        """
        import blesuite.utils.validators as validator

        characteristic_attributes = characteristic_dictionary.keys()

        if 'uuid' in characteristic_attributes:
            uuid = validator.validate_attribute_uuid(characteristic_dictionary['uuid'])
            self.uuid = uuid
        else:
            return validator.InvalidUUIDException(None)

        self.determine_type()

        if 'handle' in characteristic_attributes:
            handle = validator.validate_int_att_handle(characteristic_dictionary['handle'])
            self.handle = handle
        else:
            # This will allow us to disregard adding handles to our import JSON file and we can calculate during
            # the gatt_server creation that uses the BLEDevice (flag enabled by default)
            self.handle = 0x00

        if 'value_handle' in characteristic_attributes:
            handle = validator.validate_int_att_handle(characteristic_dictionary['value_handle'])
            self.value_handle = handle
        else:
            self.value_handle = 0x00

        if 'value' in characteristic_attributes:
            self.value = characteristic_dictionary['value']

        gatt_properties = 0
        if 'gatt_properties' in characteristic_attributes:
            property_list = characteristic_dictionary['gatt_properties']
            for gatt_property in property_list:
                validated_property = validator.validate_gatt_property(gatt_property)
                translated_property = Permissions.permission_dictionary_lookup_by_name[validated_property]
                gatt_properties |= translated_property
        self.gatt_properties = gatt_properties

        # Characteristic Definition (aka Characteristic Declaration)

        if 'characteristic_definition_attribute_properties' in characteristic_attributes:
            att_properties = characteristic_dictionary['characteristic_definition_attribute_properties']

            for att_property in att_properties:
                self.characteristic_definition_attribute_properties = 0
                validated_att_property = validator.validate_att_property(att_property)
                if validated_att_property == "read":
                    self.characteristic_definition_attribute_properties |= att_utils.ATT_PROP_READ
                elif validated_att_property == "write":
                    self.characteristic_definition_attribute_properties |= att_utils.ATT_PROP_WRITE

        if 'characteristic_definition_attribute_read_permission' in characteristic_attributes:
            permission_dictionary = characteristic_dictionary['characteristic_definition_attribute_read_permission']
            permission_keys = permission_dictionary.keys()
            if "security_mode" not in permission_keys:
                mode = None
            else:
                mode = permission_dictionary['security_mode']
            if "security_level" not in permission_keys:
                level = None
            else:
                level = permission_dictionary['security_level']

            mode, level = validator.validate_att_security_mode(mode, level)
            self.characteristic_definition_attribute_read_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'characteristic_definition_attribute_write_permission' in characteristic_attributes:
            permission_dictionary = characteristic_dictionary['characteristic_definition_attribute_write_permission']
            permission_keys = permission_dictionary.keys()
            if "security_mode" not in permission_keys:
                mode = None
            else:
                mode = permission_dictionary['security_mode']
            if "security_level" not in permission_keys:
                level = None
            else:
                level = permission_dictionary['security_level']

            mode, level = validator.validate_att_security_mode(mode, level)
            self.characteristic_definition_attribute_write_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'characteristic_definition_attribute_require_authorization' in characteristic_attributes:
            require_auth = characteristic_dictionary['characteristic_definition_attribute_require_authorization']
            if require_auth is not None:
                self.characteristic_definition_attribute_require_authorization = require_auth

        # Characteristic Value Declaration

        if 'characteristic_value_attribute_properties' in characteristic_attributes:
            att_properties = characteristic_dictionary['characteristic_value_attribute_properties']
            self.characteristic_value_attribute_properties = 0
            for att_property in att_properties:

                validated_att_property = validator.validate_att_property(att_property)
                if validated_att_property == "read":
                    self.characteristic_value_attribute_properties |= att_utils.ATT_PROP_READ
                elif validated_att_property == "write":
                    self.characteristic_value_attribute_properties |= att_utils.ATT_PROP_WRITE

        if 'characteristic_value_attribute_read_permission' in characteristic_attributes:
            permission_dictionary = characteristic_dictionary['characteristic_value_attribute_read_permission']
            permission_keys = permission_dictionary.keys()
            if "security_mode" not in permission_keys:
                mode = None
            else:
                mode = permission_dictionary['security_mode']
            if "security_level" not in permission_keys:
                level = None
            else:
                level = permission_dictionary['security_level']

            mode, level = validator.validate_att_security_mode(mode, level)
            self.characteristic_value_attribute_read_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'characteristic_value_attribute_write_permission' in characteristic_attributes:
            permission_dictionary = characteristic_dictionary['characteristic_value_attribute_write_permission']
            permission_keys = permission_dictionary.keys()
            if "security_mode" not in permission_keys:
                mode = None
            else:
                mode = permission_dictionary['security_mode']
            if "security_level" not in permission_keys:
                level = None
            else:
                level = permission_dictionary['security_level']

            mode, level = validator.validate_att_security_mode(mode, level)
            self.characteristic_value_attribute_write_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'characteristic_value_attribute_require_authorization' in characteristic_attributes:
            require_auth = characteristic_dictionary['characteristic_value_attribute_require_authorization']
            if require_auth is not None:
                self.characteristic_value_attribute_require_authorization = require_auth

        if 'descriptors' in characteristic_attributes:
            descriptor_list = characteristic_dictionary['descriptors']
            for descriptor_dictionary in descriptor_list:
                # value_handle, handle, uuid, gatt_properties, service_uuid
                gatt_characteristic = BLEDescriptor(None, None)
                gatt_characteristic.import_descriptor_from_dictionary(descriptor_dictionary)
                self.descriptors.append(gatt_characteristic)

    def add_client_characteristic_configuration_descriptor(self, handle,
                                                           characteristic_descriptor_attribute_properties=att_utils.ATT_PROP_READ|att_utils.ATT_PROP_WRITE,
                                                           characteristic_descriptor_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                                           characteristic_descriptor_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                                           characteristic_descriptor_attribute_require_authorization=False):
        """
        Add a client characteristic configuration (CCC) descriptor to the characteristic class instance. This is required
        for characteristics configured to support indication or notification. Default value set to \x00\x00
        (notifications and indications disabled).

        :var handle: Handle of descriptor
        :var characteristic_descriptor_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ|blesuite.utils.att_utils.ATT_PROP_WRITE)
        :var characteristic_descriptor_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var characteristic_descriptor_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var characteristic_descriptor_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
        :type handle: int
        :type characteristic_descriptor_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type characteristic_descriptor_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_require_authorization: bool
        :return: CCC descriptor
        :rtype: blesuite.entities.gatt_descriptor
        """
        descriptor = BLEDescriptor(handle, "2902", "\x00\x00",
                                   characteristic_descriptor_attribute_properties,
                                   characteristic_descriptor_attribute_read_permission,
                                   characteristic_descriptor_attribute_write_permission,
                                   characteristic_descriptor_attribute_require_authorization)
        self.descriptors.append(descriptor)
        return descriptor

    def add_user_description_descriptor(self, handle, name,
                                        characteristic_descriptor_attribute_properties=att_utils.ATT_PROP_READ,
                                        characteristic_descriptor_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                        characteristic_descriptor_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                                        characteristic_descriptor_attribute_require_authorization=False):
        """
        Add a user description descriptor to the characteristic class instance.

        :var handle: Handle of descriptor
        :var name: Value stored in descriptor
        :var characteristic_descriptor_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ)
        :var characteristic_descriptor_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var characteristic_descriptor_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS)
        :var characteristic_descriptor_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
        :type handle: int
        :type name: str
        :type characteristic_descriptor_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type characteristic_descriptor_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_require_authorization: bool
        :return: User description descriptor
        :rtype: blesuite.entities.gatt_descriptor
        """
        descriptor = BLEDescriptor(handle, "2901", name,
                                   characteristic_descriptor_attribute_properties,
                                   characteristic_descriptor_attribute_read_permission,
                                   characteristic_descriptor_attribute_write_permission,
                                   characteristic_descriptor_attribute_require_authorization)
        self.descriptors.append(descriptor)
        return descriptor

    def add_descriptor_with_data(self, handle, uuid, data,
                                 characteristic_descriptor_attribute_properties=att_utils.ATT_PROP_READ|att_utils.ATT_PROP_WRITE,
                                 characteristic_descriptor_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                 characteristic_descriptor_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                                 characteristic_descriptor_attribute_require_authorization=False):
        """
        Create a descriptor object, set the object's lastReadValue, and
        add it to the descriptors list.

        :param handle: Handle of descriptor
        :param uuid: UUID of descriptor
        :param data: Data received after reading from descriptor handle
        :param characteristic_descriptor_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ)
        :param characteristic_descriptor_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :param characteristic_descriptor_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS)
        :param characteristic_descriptor_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
        :type handle: int - base 10
        :type uuid: str
        :type data: list of strings
        :type characteristic_descriptor_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type characteristic_descriptor_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type characteristic_descriptor_attribute_require_authorization: bool
        :return: Descriptor
        :rtype: blesuite.entities.gatt_descriptor
        """
        descriptor = BLEDescriptor(handle, uuid, data,
                                   characteristic_descriptor_attribute_properties,
                                   characteristic_descriptor_attribute_read_permission,
                                   characteristic_descriptor_attribute_write_permission,
                                   characteristic_descriptor_attribute_require_authorization)
        if self.value_handle == handle:
            descriptor.type_string = "Characteristic Value Declaration"
        self.descriptors.append(descriptor)
        return descriptor
