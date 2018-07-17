from blesuite.entities.gatt_characteristic import BLECharacteristic
from blesuite.entities.gatt_include import BLEInclude
import blesuite.utils.att_utils as att_utils

# Contains information to create Service Declaration Descriptor


class BLEService(object):
    """
    BLEService is used to represent a service located on a BTLE device.

    :var start: Start handle for service. Type int
    :var end: End handle for service. Type int
    :var uuid: UUID of service. Type str
    :var attribute_type: Attribute type UUID (default "2800" - primary service). Type str
    :var service_definition_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ). Type: blesuite.utils.att_utils.ATT_PROP_*
    :var service_definition_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :var service_definition_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS). Type: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :var service_definition_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
    :type start: int - base 10
    :type end: int - base 10
    :type uuid: str
    :type attribute_type: str
    :type service_definition_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
    :type service_definition_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :type service_definition_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
    :type service_definition_attribute_require_authorization: bool
    """
    def __init__(self, start, end, uuid, attribute_type="2800",
                 service_definition_attribute_properties=att_utils.ATT_PROP_READ,
                 service_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                 service_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                 service_definition_attribute_require_authorization=False):
        self.uuid = uuid
        self.start = start
        self.end = end
        self.characteristics = []
        self.includes = []
        self.type = None
        self.type_string = ""
        self.attribute_type = attribute_type
        self.service_definition_attribute_properties = service_definition_attribute_properties
        self.service_definition_attribute_read_permission = service_definition_attribute_read_permission
        self.service_definition_attribute_write_permission = service_definition_attribute_write_permission
        self.service_definition_attribute_require_authorization = service_definition_attribute_require_authorization

        self.determine_type()

    def determine_type(self):
        """
        Used by blesuite.entities.gatt_service to populate gatt_service.type_string with a readable
        type based on the service's UUID. The defined service types were pulled from
        https://www.bluetooth.com/specifications/gatt/services

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
        if self.uuid is None:
            return
        type_int = int(self.uuid[:8], 16)
        self.type = type_int
        if type_int in type_dict.keys():
            self.type_string = type_dict[type_int]

    def get_type_string(self):
        """
        Returns readable service type string.

        :return: Type of service
        :rtype: str
        """
        return self.type_string

    def export_service_to_dictionary(self):
        """
        Exports service information to a dictionary for use by the BLEDevice export functionality.

        :return: Dictionary representation of service
        :rtype: dict
        """
        from collections import OrderedDict
        # ordered dictionary allows us to maintain the order we insert keys, this makes reading the resulting
        # dictionary easier
        service_dictionary = OrderedDict()

        service_dictionary['uuid'] = self.uuid
        service_dictionary['start_handle'] = self.start
        service_dictionary['end_handle'] = self.end
        service_dictionary['attribute_type'] = self.attribute_type

        attribute_properties = []
        if self.service_definition_attribute_properties & att_utils.ATT_PROP_READ == att_utils.ATT_PROP_READ:
            attribute_properties.append("read")
        if self.service_definition_attribute_properties & att_utils.ATT_PROP_WRITE == att_utils.ATT_PROP_WRITE:
            attribute_properties.append("write")
        service_dictionary['service_definition_attribute_properties'] = attribute_properties

        attribute_read_permissions = {"security_mode": self.service_definition_attribute_read_permission.security_mode,
                                      "security_level": self.service_definition_attribute_read_permission.security_level
                                      }
        service_dictionary['service_definition_attribute_read_permission'] = attribute_read_permissions

        attribute_write_permissions = {"security_mode": self.service_definition_attribute_write_permission.security_mode,
                                       "security_level": self.service_definition_attribute_write_permission.security_level
                                       }
        service_dictionary['service_definition_attribute_write_permission'] = attribute_write_permissions

        service_dictionary['service_definition_attribute_require_authorization'] = self.service_definition_attribute_require_authorization

        characteristics = []
        for characteristic in self.characteristics:
            characteristic_dict = characteristic.export_characteristic_to_dictionary()
            characteristics.append(characteristic_dict)
        service_dictionary['characteristics'] = characteristics

        includes = []
        for incl in self.includes:
            incl_dict = incl.export_include_to_dictionary()
            includes.append(incl_dict)
        service_dictionary['includes'] = includes

        return service_dictionary

    def import_service_from_dictionary(self, service_dictionary):
        """
        Populate service attributes from a dictionary containing service information. This is complimentary to
        export_service_to_dictionary .

        :param service_dictionary: Dictionary containing service information
        :type service_dictionary: dict
        :return:
        :rtype:
        :raises blesuite.pybt.gatt.InvalidUUIDException: if the provided service dictionary contains a service with an invalid UUID
        :raises blesuite.utils.validators.InvalidATTHandle: if the provided service dictionary contains a service with an invalid handle
        :raises blesuite.utils.validators.InvalidGATTProperty: if the provided service dictionary contains a service with an invalid GATT property
        :raises blesuite.utils.validators.InvalidATTProperty: if the provided service dictionary contains a service with an invalid attribute property
        :raises blesuite.utils.validators.InvalidATTSecurityMode: if the provided service dictionary contains a service with an invalid attribute permission
        """
        import blesuite.utils.validators as validator

        service_attributes = service_dictionary.keys()

        if 'uuid' in service_attributes:
            uuid = validator.validate_attribute_uuid(service_dictionary['uuid'])
            self.uuid = uuid
        else:
            raise validator.InvalidUUIDException(None)

        self.determine_type()

        if 'start_handle' in service_attributes:
            start = validator.validate_int_att_handle(service_dictionary['start_handle'])
            self.start = start
        else:
            # This will allow us to disregard adding handles to our import JSON file and we can calculate during
            # the gatt_server creation that uses the BLEDevice (flag enabled by default)
            self.start = 0x00

        if 'end_handle' in service_attributes:
            end = validator.validate_int_att_handle(service_dictionary['end_handle'])
            self.end = end
        else:
            self.end = 0x00

        if 'attribute_type' in service_attributes:
            att_type = validator.validate_attribute_uuid(service_dictionary['attribute_type'])
            self.attribute_type = att_type
            # If not present, it will default to a primary service

        if 'service_definition_attribute_properties' in service_attributes:
            att_properties = service_dictionary['service_definition_attribute_properties']
            self.service_definition_attribute_properties = 0
            for att_property in att_properties:

                validated_att_property = validator.validate_att_property(att_property)
                if validated_att_property == "read":
                    self.service_definition_attribute_properties |= att_utils.ATT_PROP_READ
                elif validated_att_property == "write":
                    self.service_definition_attribute_properties |= att_utils.ATT_PROP_WRITE

        if 'service_definition_attribute_read_permission' in service_attributes:
            permission_dictionary = service_dictionary['service_definition_attribute_read_permission']
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
            self.service_definition_attribute_read_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'service_definition_attribute_write_permission' in service_attributes:
            permission_dictionary = service_dictionary['service_definition_attribute_write_permission']
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
            self.service_definition_attribute_write_permission = att_utils.get_att_security_mode_from_mode_and_level(mode, level)

        if 'service_definition_attribute_require_authorization' in service_attributes:
            require_auth = service_dictionary['service_definition_attribute_require_authorization']
            if require_auth is not None:
                self.service_definition_attribute_require_authorization = require_auth

        if 'characteristics' in service_attributes:
            characteristic_list = service_dictionary['characteristics']
            for characteristic_dictionary in characteristic_list:
                # value_handle, handle, uuid, gatt_properties, service_uuid
                gatt_characteristic = BLECharacteristic(None, None, None, None, None)
                gatt_characteristic.import_characteristic_from_dictionary(characteristic_dictionary)
                self.characteristics.append(gatt_characteristic)

        if 'includes' in service_attributes:
            include_list = service_dictionary['includes']
            for include_dictionary in include_list:
                # handle, included_service_att_handle, end, uuid
                gatt_include = BLEInclude(None, None, None, None)
                gatt_include.import_include_from_dictionary(include_dictionary)
                self.includes.append(gatt_include)

    def get_characteristics(self):
        """
        Return list of blesuite.entities.gatt_characteristic objects defined within the service class instance

        :return: List of Characteristics
        :rtype: blesuite.entities.gatt_characteristic
        """
        return self.characteristics

    def get_includes(self):
        """
        Return list of blesuite.entities.gatt_include objects defined within the service class instance

        :return: List of Service Includes
        :rtype: blesuite.entities.gatt_include
        """
        return self.includes

    def add_characteristic(self, value_handle, handle, uuid, properties, value="",
                           characteristic_definition_attribute_properties=att_utils.ATT_PROP_READ,
                           characteristic_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                           characteristic_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                           characteristic_definition_attribute_require_authorization=False,
                           characteristic_value_attribute_properties=att_utils.ATT_PROP_READ|att_utils.ATT_PROP_WRITE,
                           characteristic_value_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                           characteristic_value_attribute_write_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                           characteristic_value_attribute_require_authorization=False
                           ):
        """
        Add a characteristic object to the service class instance.

        :param value_handle: Value handle of characteristic
        :param handle: Handle of characteristic
        :param uuid: UUID of characteristic
        :param properties: Properties value of characteristic
        :var value: Value held by characteristic
        :var characteristic_definition_attribute_properties: Characteristic definition attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ)
        :var characteristic_definition_attribute_read_permission: Required security mode to read Characteristic definition attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var characteristic_definition_attribute_write_permission: Required security mode to write to Characteristic definition attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS)
        :var characteristic_definition_attribute_require_authorization: Flag to indicate that access of the Characteristic definition attribute requires authorization (default False)
        :var characteristic_value_attribute_properties: Characteristic value attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ|blesuite.utils.att_utils.ATT_PROP_WRITE)
        :var characteristic_value_attribute_read_permission: Required security mode to read Characteristic value attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var characteristic_value_attribute_write_permission: Required security mode to Characteristic value write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
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
        :type properties: int - base 10
        :type value: str

        :return: Newly created characteristic
        :rtype: blesuite.entities.gatt_characteristic
        """
        characteristic = BLECharacteristic(value_handle, handle, uuid, properties, self.uuid,
                                           value,
                                           characteristic_definition_attribute_properties,
                                           characteristic_definition_attribute_read_permission,
                                           characteristic_definition_attribute_write_permission,
                                           characteristic_definition_attribute_require_authorization,
                                           characteristic_value_attribute_properties,
                                           characteristic_value_attribute_read_permission,
                                           characteristic_value_attribute_write_permission,
                                           characteristic_value_attribute_require_authorization
                                           )
        self.characteristics.append(characteristic)
        return characteristic

    def add_include(self, handle, included_service_att_handle, end, uuid, attribute_type="2802",
                    include_definition_attribute_properties=att_utils.ATT_PROP_READ,
                    include_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                    include_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                    include_definition_attribute_require_authorization=False):
        """
        Add a service include object to the service class instance.

        :var handle: Handle of attribute
        :var included_service_att_handle: Start handle for included service
        :var end: End handle for included service
        :var uuid: UUID of included service
        :var attribute_type: Attribute type UUID (default "2802" - include service)
        :var include_definition_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ)
        :var include_definition_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :var include_definition_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS)
        :var include_definition_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)
        :type handle: int
        :type included_service_att_handle: int
        :type end: int
        :type uuid: str
        :type attribute_type: str
        :type include_definition_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type include_definition_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type include_definition_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type include_definition_attribute_require_authorization: bool
        :return: Newly created service include
        :rtype: blesuite.entities.gatt_include
        """

        incl = BLEInclude(handle, included_service_att_handle, end, uuid, attribute_type,
                          include_definition_attribute_properties,
                          include_definition_attribute_read_permission,
                          include_definition_attribute_write_permission,
                          include_definition_attribute_require_authorization)
        self.includes.append(incl)

        return incl
