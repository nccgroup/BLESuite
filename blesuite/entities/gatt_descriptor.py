import blesuite.utils.att_utils as att_utils


class BLEDescriptor(object):
    """
    BLEDescriptor is used to represent a descriptor of a characteristic located on a BTLE device

    :var handle: Handle of descriptor. Type int
    :type handle: int
    :var uuid: UUID of descriptor. Type str
    :var value: Value stored in descriptor. Type str
    :var characteristic_descriptor_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ|blesuite.utils.att_utils.ATT_PROP_WRITE). Type: blesuite.utils.att_utils.ATT_PROP_*
    :var characteristic_descriptor_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :var characteristic_descriptor_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :var characteristic_descriptor_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
    :type uuid: str
    :type value: str
    :type characteristic_descriptor_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
    :type characteristic_descriptor_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :type characteristic_descriptor_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :type characteristic_descriptor_attribute_require_authorization: bool
    """
    def __init__(self, handle, uuid,
                 value="",
                 characteristic_descriptor_attribute_properties=att_utils.ATT_PROP_READ|att_utils.ATT_PROP_WRITE,
                 characteristic_descriptor_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 characteristic_descriptor_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 characteristic_descriptor_attribute_require_authorization=False
                 ):
        self.handle = handle
        self.uuid = uuid
        self.type = None
        self.type_string = ""
        self.determine_type()
        self.value = value
        self.characteristic_descriptor_attribute_properties = characteristic_descriptor_attribute_properties
        self.characteristic_descriptor_attribute_read_permission = characteristic_descriptor_attribute_read_permission
        self.characteristic_descriptor_attribute_write_permission = characteristic_descriptor_attribute_write_permission
        self.characteristic_descriptor_attribute_require_authorization = characteristic_descriptor_attribute_require_authorization

    def determine_type(self):
        """
        Used by blesuite.entities.gatt_descriptor to populate gatt_descriptor.type_string with a readable
        type based on the descriptor's UUID. The defined descriptor types were pulled from
        https://www.bluetooth.com/specifications/gatt/descriptors and
        BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part G pages 2235 - 2245

        :return:
        :rtype:
        """
        # descriptors defined in BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part G pages 2235 - 2245
        # Also here: https://www.bluetooth.com/specifications/gatt/descriptors (last updated this dictionary on 1/12/18)
        type_dict = {
            # Declarations
            0x2800: "Primary Service",
            0x2801: "Secondary Service",
            0x2802: "Include",
            0x2803: "Characteristic Declaration",
            # Descriptors
            0x2900: "Characteristic Extended Properties",
            0x2901: "Characteristic User Description",
            0x2902: "Client Characteristic Configuration",
            0x2903: "Server Characteristic Configuration",
            0x2904: "Characteristic Presentation Format",
            0x2905: "Characteristic Aggregate Format",
            0x2906: "Valid Range",
            0x2907: "External Report Reference",
            0x2908: "Report Reference",
            0x2909: "Number of Digitals",
            0x290a: "Value Trigger Settings",
            0x290b: "Environmental Sensing Configuration",
            0x290c: "Environmental Sensing Measurement",
            0x290d: "Environmental Sensing Trigger Setting",
            0x290e: "Time Trigger Setting"
        }
        if self.uuid is None:
            return
        type_int = int(self.uuid[:8], 16)
        self.type = type_int
        if type_int in type_dict.keys():
            self.type_string = type_dict[type_int]

        return

    def get_type_string(self):
        """
        Returns readable descriptor type string.

        :return: Type of descriptor
        :rtype: str
        """
        return self.type_string

    def export_descriptor_to_dictionary(self):
        """
        Exports descriptor information to a dictionary for use by the BLEDevice export functionality.

        :return: Dictionary representation of descriptor
        :rtype: dict
        """
        from collections import OrderedDict
        # ordered dictionary allows us to maintain the order we insert keys, this makes reading the resulting
        # dictionary easier
        descriptor_dict = OrderedDict()

        descriptor_dict['handle'] = self.handle
        descriptor_dict['uuid'] = self.uuid
        descriptor_dict['value'] = self.value

        attribute_properties = []
        if self.characteristic_descriptor_attribute_properties & att_utils.ATT_PROP_READ == att_utils.ATT_PROP_READ:
            attribute_properties.append("read")
        if self.characteristic_descriptor_attribute_properties & att_utils.ATT_PROP_WRITE == att_utils.ATT_PROP_WRITE:
            attribute_properties.append("write")
            descriptor_dict['characteristic_descriptor_attribute_properties'] = attribute_properties

        attribute_read_permissions = {
            "security_mode": self.characteristic_descriptor_attribute_read_permission.security_mode,
            "security_level": self.characteristic_descriptor_attribute_read_permission.security_level
            }
        descriptor_dict['characteristic_descriptor_attribute_read_permission'] = attribute_read_permissions

        attribute_write_permissions = {
            "security_mode": self.characteristic_descriptor_attribute_write_permission.security_mode,
            "security_level": self.characteristic_descriptor_attribute_write_permission.security_level
        }
        descriptor_dict['characteristic_descriptor_attribute_write_permission'] = attribute_write_permissions

        descriptor_dict[
            'characteristic_descriptor_attribute_require_authorization'] = self.characteristic_descriptor_attribute_require_authorization

        return descriptor_dict

    def import_descriptor_from_dictionary(self, descriptor_dictionary):
        """
        Populate descriptor attributes from a dictionary containing descriptor information.
        This is complimentary to export_descriptor_to_dictionary .

        :param descriptor_dictionary: Dictionary containing descriptor information
        :type descriptor_dictionary: dict
        :return:
        :rtype:
        :raises blesuite.pybt.gatt.InvalidUUIDException: if the provided descriptor dictionary contains a descriptor with an invalid UUID
        :raises blesuite.utils.validators.InvalidATTHandle: if the provided descriptor dictionary contains a descriptor with an invalid handle
        :raises blesuite.utils.validators.InvalidATTProperty: if the provided descriptor dictionary contains a descriptor with an invalid attribute property
        :raises blesuite.utils.validators.InvalidATTSecurityMode: if the provided descriptor dictionary contains a descriptor with an invalid attribute permission
        """
        import blesuite.utils.validators as validator

        descriptor_attributes = descriptor_dictionary.keys()

        if 'uuid' in descriptor_attributes:
            uuid = validator.validate_attribute_uuid(descriptor_dictionary['uuid'])
            self.uuid = uuid
        else:
            return validator.InvalidUUIDException(None)

        self.determine_type()

        if 'handle' in descriptor_attributes:
            handle = validator.validate_int_att_handle(descriptor_dictionary['handle'])
            self.handle = handle
        else:
            # This will allow us to disregard adding handles to our import JSON file and we can calculate during
            # the gatt_server creation that uses the BLEDevice (flag enabled by default)
            self.handle = 0x00

        if 'value' in descriptor_attributes:
            self.value = descriptor_dictionary['value']

        if 'characteristic_descriptor_attribute_properties' in descriptor_attributes:
            att_properties = descriptor_dictionary['characteristic_descriptor_attribute_properties']
            self.characteristic_descriptor_attribute_properties = 0
            for att_property in att_properties:

                validated_att_property = validator.validate_att_property(att_property)
                if validated_att_property == "read":
                    self.characteristic_descriptor_attribute_properties |= att_utils.ATT_PROP_READ
                elif validated_att_property == "write":
                    self.characteristic_descriptor_attribute_properties |= att_utils.ATT_PROP_WRITE

        if 'characteristic_descriptor_attribute_read_permission' in descriptor_attributes:
            permission_dictionary = descriptor_dictionary['characteristic_descriptor_attribute_read_permission']
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
            self.characteristic_descriptor_attribute_read_permission = att_utils.get_att_security_mode_from_mode_and_level(
                mode, level)

        if 'characteristic_descriptor_attribute_write_permission' in descriptor_attributes:
            permission_dictionary = descriptor_dictionary['characteristic_descriptor_attribute_write_permission']
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
            self.characteristic_descriptor_attribute_write_permission = att_utils.get_att_security_mode_from_mode_and_level(
                mode, level)

        if 'characteristic_descriptor_attribute_require_authorization' in descriptor_attributes:
            require_auth = descriptor_dictionary['characteristic_descriptor_attribute_require_authorization']
            if require_auth is not None:
                self.characteristic_descriptor_attribute_require_authorization = require_auth

        return
