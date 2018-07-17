import blesuite.utils.att_utils as att_utils


class BLEInclude(object):
    """ BLEInclude is used to represent an included service located on a BTLE device

        :var handle: Handle of attribute. Type int
        :var included_service_att_handle: Start handle for included service. Type int
        :var included_service_end_group_handle: End handle for included service. Type int
        :var included_service_uuid: UUID of included service. Type str
        :var attribute_type: Attribute type UUID (default "2802" - include service), Type str
        :var include_definition_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ). Type: blesuite.utils.att_utils.ATT_PROP_*
        :var include_definition_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var include_definition_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :var include_definition_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
        :type handle: int
        :type included_service_att_handle: int
        :type included_service_end_group_handle: int
        :type included_service_uuid: str
        :type attribute_type: str
        :type include_definition_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type include_definition_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type include_definition_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type include_definition_attribute_require_authorization: bool

    """
    def __init__(self, handle, included_service_att_handle, included_service_end_group_handle, included_service_uuid,
                 attribute_type="2802",
                 include_definition_attribute_properties=att_utils.ATT_PROP_READ,
                 include_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 include_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                 include_definition_attribute_require_authorization=False):
        self.handle = handle
        self.included_service_att_handle = included_service_att_handle
        self.included_service_uuid = included_service_uuid
        self.included_service_end_group_handle = included_service_end_group_handle
        self.characteristics = []
        self.includes = []
        self.type = None
        self.type_string = ""
        self.attribute_type = attribute_type
        self.include_definition_attribute_properties = include_definition_attribute_properties
        self.include_definition_attribute_read_permission = include_definition_attribute_read_permission
        self.include_definition_attribute_write_permission = include_definition_attribute_write_permission
        self.include_definition_attribute_require_authorization = include_definition_attribute_require_authorization

        self.determine_type()

    def determine_type(self):
        """
        Used by blesuite.entities.gatt_include to populate gatt_include.type_string with a readable
        type based on the include's UUID. The defined include service types were pulled from
        https://www.bluetooth.com/specifications/gatt/characteristics

        :return:
        :rtype:
        """
        # Defined Services from  https://www.bluetooth.com/specifications/gatt/services
        # last updated dict on 1/12/18
        type_dict = {
            0x1800: "Generic Access",
            0x1811: "Alert Notification Service",
            0x1815: "Automation IO",
            0x180F: "Battery Service",
            0x1810: "Blood Pressure",
            0x181B: "Body Composition",
            0x181E: "Bond Management Service",
            0x181F: "Continuous Glucose Monitoring",
            0x1805: "Current Time Service",
            0x1818: "Cycling Power",
            0x1816: "Cycling Speed and Cadence",
            0x180A: "Device Information",
            0x181A: "Environmental Sensing",
            0x1826: "Fitness Machine",
            0x1801: "Generic Attribute",
            0x1808: "Glucose",
            0x1809: "Health Thermometer",
            0x180D: "Heart Rate",
            0x1823: "HTTP Proxy",
            0x1812: "Human Interface Device",
            0x1802: "Immediate Alert",
            0x1821: "Indoor Positioning",
            0x1820: "Internet Protocol Support Service",
            0x1803: "Link Loss",
            0x1819: "Location and Navigation",
            0x1827: "Mesh Provisioning Service",
            0x1828: "Mesh Proxy Service",
            0x1807: "Next DST Change Service",
            0x1825: "Object Transfer Service",
            0x180E: "Phone Alert Status Service",
            0x1822: "Pulse Oximeter Service",
            0x1806: "Reference Time Update Service",
            0x1814: "Running Speed and Cadence",
            0x1813: "Scan Parameters",
            0x1824: "Transport Discovery",
            0x1804: "Tx Power",
            0x181C: "User Data",
            0x181D: "Weight Scale",

        }
        if self.included_service_uuid is None:
            return
        type_int = int(self.included_service_uuid[:8], 16)
        self.type = type_int
        if type_int in type_dict.keys():
            self.type_string = type_dict[type_int]

    def get_type_string(self):
        """
        Returns readable type string of the included service.

        :return: Type of service
        :rtype: str
        """
        return self.type_string

    def export_include_to_dictionary(self):
        """
        Exports include service information to a dictionary for use by the BLEDevice export functionality.

        :return: Dictionary representation of include
        :rtype: dict
        """
        from collections import OrderedDict
        # ordered dictionary allows us to maintain the order we insert keys, this makes reading the resulting
        # dictionary easier
        include_dictionary = OrderedDict()

        include_dictionary['handle'] = self.handle
        include_dictionary['included_service_att_handle'] = self.included_service_att_handle
        include_dictionary['included_service_end_group_handle'] = self.included_service_end_group_handle
        include_dictionary['included_service_uuid'] = self.included_service_uuid
        # include_dictionary['attribute_type'] = self.attribute_type

        attribute_properties = []
        if self.include_definition_attribute_properties & att_utils.ATT_PROP_READ == att_utils.ATT_PROP_READ:
            attribute_properties.append("read")
        if self.include_definition_attribute_properties & att_utils.ATT_PROP_WRITE == att_utils.ATT_PROP_WRITE:
            attribute_properties.append("write")
            include_dictionary['include_definition_attribute_properties'] = attribute_properties

        attribute_read_permissions = {"security_mode": self.include_definition_attribute_read_permission.security_mode,
                                      "security_level": self.include_definition_attribute_read_permission.security_level
                                      }
        include_dictionary['include_definition_attribute_read_permission'] = attribute_read_permissions

        attribute_write_permissions = {
            "security_mode": self.include_definition_attribute_write_permission.security_mode,
            "security_level": self.include_definition_attribute_write_permission.security_level
            }
        include_dictionary['include_definition_attribute_write_permission'] = attribute_write_permissions

        include_dictionary['include_definition_attribute_require_authorization'] = self.include_definition_attribute_require_authorization

        return include_dictionary

    def import_include_from_dictionary(self, include_dictionary):
        """
        Populate include attributes from a dictionary containing included service information.
        This is complimentary to export_include_to_dictionary .

        :param include_dictionary: Dictionary containing include information
        :type include_dictionary: dict
        :return:
        :rtype:
        :raises blesuite.pybt.gatt.InvalidUUIDException: if the provided include dictionary contains an include with an invalid UUID
        :raises blesuite.utils.validators.InvalidATTHandle: if the provided include dictionary contains an include with an invalid handle
        :raises blesuite.utils.validators.InvalidATTProperty: if the provided include dictionary contains an include with an invalid attribute property
        :raises blesuite.utils.validators.InvalidATTSecurityMode: if the provided include dictionary contains an include with an invalid attribute permission
        """
        import blesuite.utils.validators as validator

        include_attributes = include_dictionary.keys()

        if 'included_service_uuid' in include_attributes:
            uuid = validator.validate_attribute_uuid(include_dictionary['included_service_uuid'])
            self.included_service_uuid = uuid
        else:
            raise validator.InvalidUUIDException(None)

        self.determine_type()

        if 'handle' in include_attributes:
            handle = validator.validate_int_att_handle(include_dictionary['handle'])
            self.handle = handle
        else:
            # This will allow us to disregard adding handles to our import JSON file and we can calculate during
            # the gatt_server creation that uses the BLEDevice (flag enabled by default)
            self.included_service_att_handle = 0x00

        if 'included_service_att_handle' in include_attributes:
            included_service_att_handle = validator.validate_int_att_handle(include_dictionary['included_service_att_handle'])
            self.included_service_att_handle = included_service_att_handle
        else:
            # This will allow us to disregard adding handles to our import JSON file and we can calculate during
            # the gatt_server creation that uses the BLEDevice (flag enabled by default)
            self.included_service_att_handle = 0x00

        if 'included_service_end_group_handle' in include_attributes:
            end = validator.validate_int_att_handle(include_dictionary['included_service_end_group_handle'])
            self.included_service_end_group_handle = end
        else:
            self.included_service_end_group_handle = 0x00

        if 'include_definition_attribute_properties' in include_attributes:
            att_properties = include_dictionary['include_definition_attribute_properties']

            for att_property in att_properties:
                self.include_definition_attribute_properties = 0
                validated_att_property = validator.validate_att_property(att_property)
                if validated_att_property == "read":
                    self.include_definition_attribute_properties |= att_utils.ATT_PROP_READ
                elif validated_att_property == "write":
                    self.include_definition_attribute_properties |= att_utils.ATT_PROP_WRITE

        if 'include_definition_attribute_read_permission' in include_attributes:
            permission_dictionary = include_dictionary['include_definition_attribute_read_permission']
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
            self.include_definition_attribute_read_permission = att_utils.get_att_security_mode_from_mode_and_level(
                mode, level)

        if 'include_definition_attribute_write_permission' in include_attributes:
            permission_dictionary = include_dictionary['include_definition_attribute_write_permission']
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
            self.include_definition_attribute_write_permission = att_utils.get_att_security_mode_from_mode_and_level(
                mode, level)

        if 'include_definition_attribute_require_authorization' in include_attributes:
            require_auth = include_dictionary['include_definition_attribute_require_authorization']
            if require_auth is not None:
                self.include_definition_attribute_require_authorization = require_auth
        return
