from blesuite.entities.gatt_service import BLEService
from blesuite.entities.gatt_characteristic import BLECharacteristic
from blesuite.entities.gatt_include import BLEInclude
from blesuite.utils.print_helper import print_data_and_hex
import blesuite.utils.att_utils as att_utils


class BLEDevice(object):
    """BLEDevice is used to represent a BLE device, holding its address and services.

        :param address: MAC address (BD_ADD) of BLE device
        :param address_type: Type of address (public, random)
        :param name: Name of device
        :type address: str
        :type address_type: str
        :type name: str

    """
    def __init__(self, address="00:00:00:00:00:00", address_type="public", name=""):
        self.address = address
        self.address_type = address_type
        self.name = name
        # list of service objects
        self.services = []
        self.device_information = []
        self.mtu = 23
        # list of characteristic objects can be accessed via parent service objects
        # self.characteristics = []

    def set_mtu(self, mtu):
        self.mtu = mtu

    # start and end values are provided by the BLE Primary Service Scan
    def add_service(self, start, end, uuid, attribute_type="2800",
                    service_definition_attribute_properties=att_utils.ATT_PROP_READ,
                    service_definition_attribute_read_permission=att_utils.ATT_SECURITY_MODE_OPEN,
                    service_definition_attribute_write_permission=att_utils.ATT_SECURITY_MODE_NO_ACCESS,
                    service_definition_attribute_require_authorization=False):
        """
        Add a service object to the device

        :param start: Start handle
        :param end: End handle
        :param uuid: UUID of service
        :param attribute_type: Attribute type UUID (default "2800" - primary service)
        :param service_definition_attribute_properties: Attribute properties (default blesuite.utils.att_utils.ATT_PROP_READ)
        :param service_definition_attribute_read_permission: Required security mode to read attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_OPEN)
        :param service_definition_attribute_write_permission: Required security mode to write to attribute (default blesuite.utils.att_utils.ATT_SECURITY_MODE_NO_ACCESS)
        :param service_definition_attribute_require_authorization: Flag to indicate that access of the attribute requires authorization (default False)

        :type start: int - base 10
        :type end: int - base 10
        :type uuid: str
        :type attribute_type: str
        :type service_definition_attribute_properties: blesuite.utils.att_utils.ATT_PROP_*
        :type service_definition_attribute_read_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type service_definition_attribute_write_permission: blesuite.utils.att_utils.ATT_SECURITY_MODE_*
        :type service_definition_attribute_require_authorization: bool
        :return:
        """
        # self.services.append(service)
        service = BLEService(start, end, uuid, attribute_type,
                             service_definition_attribute_properties,
                             service_definition_attribute_read_permission,
                             service_definition_attribute_write_permission,
                             service_definition_attribute_require_authorization
                             )
        self.services.append(service)
        return service

    def get_services(self):
        """
        Retrieve the list of services on the device.

        :return: List of services
        :rtype: list
        """
        return self.services

    def add_characteristic(self, value_handle, handle, uuid, properties):
        """
        Add a characteristic object to it's associated service on the device

        :param value_handle: Value handle of characteristic
        :param handle: Handle of characteristic
        :param uuid: UUID of characteristic
        :param properties: Properties value of characteristic
        :type value_handle: int - base 10
        :type handle: int - base 10
        :type uuid: str
        :type properties: int - base 10
        :return: New characteristic
        :rtype: blesuite.entities.gatt_characteristic
        """
        for service in self.services:
            start = service.start
            end = service.end
            if start <= handle <= end:
                characteristic = BLECharacteristic(value_handle, handle, uuid, properties, service.uuid)
                service.characteristics.append(characteristic)
                return characteristic
        return None

    def add_include(self, handle, included_service_att_handle, end_group_handle, uuid):
        """
        Add a include service object to it's associated service on the device

        :param handle: Handle of characteristic
        :param included_service_att_handle: Handle of included service definition
        :param end_group_handle: End group handle of included service
        :param uuid: UUID of characteristic
        :type handle: int
        :type included_service_att_handle: int
        :type end_group_handle: int
        :type uuid: str
        :return: New include service
        :rtype: blesuite.entities.gatt_include
        """

        for service in self.services:
            start = service.start
            end = service.end
            if start <= handle <= end:
                incl = BLEInclude(handle, included_service_att_handle, end_group_handle, uuid)
                service.includes.append(incl)

        return incl

    def add_device_info(self, name, uuid, handle, data):
        """
        Add basic device information to class instance.

        :param name: Name of device attribute
        :type name: str
        :param uuid: UUID of characteristic containing specified device information
        :type uuid: str
        :param handle: Handle of the characteristic containing specified device information
        :type handle: int
        :param data: Attribute data
        :type data: str
        :return:
        :rtype:
        """
        self.device_information.append((name, uuid, handle, data))
        return

    def does_service_contain_handle(self, handle):
        """ Check whether any services on the device contain the specified handle

        :param handle: Target handle
        :return: Existence of handle
        :rtype: bool
        """
        for service in self.services:
            for characteristic in service.characteristics:
                # print "handle base: ", characteristic.handle
                if characteristic.value_handle == handle:
                    return True
        return False

    def export_device_to_dictionary(self):
        """
        Exports BLEDevice class instance to an ordered dictionary. Enables import/export
        of a BLE device.

        :return: Dictionary representation of BLEDevice
        :rtype: dict
        """
        from collections import OrderedDict
        # ordered dictionary allows us to maintain the order we insert keys, this makes reading the resulting
        # dictionary easier
        device_dict = OrderedDict()

        device_dict['name'] = self.name
        device_dict['address'] = self.address
        device_dict['address_type'] = self.address_type
        services = []
        for service in self.services:
            service_dict = service.export_service_to_dictionary()
            services.append(service_dict)
        device_dict['services'] = services

        return device_dict

    def import_device_from_dictionary(self, device_dictionary):
        """
        Populates BLEDevice class instance by importing a dictionary containing BLEDevice attributes.
        This is a complimentary function to export_device_to_dictionary .

        :param device_dictionary: BLEDevice dictionary representation
        :type device_dictionary: dict
        :return:
        :rtype:
        :raises blesuite.utils.validators.InvalidBDADDRException: if the provided BLEDevice dictionary contains an invalid Bluetooth address
        :raises blesuite.utils.validators.InvalidAddressTypeByName: if the provided BLEDevice dictionary contains an invalid address type
        :raises blesuite.pybt.gatt.InvalidUUIDException: if the provided BLEDevice dictionary contains a entity with an invalid UUID
        :raises blesuite.utils.validators.InvalidATTHandle: if the provided BLEDevice dictionary contains a entity with an invalid handle
        :raises blesuite.utils.validators.InvalidGATTProperty: if the provided BLEDevice dictionary contains a entity with an invalid GATT property
        :raises blesuite.utils.validators.InvalidATTProperty: if the provided BLEDevice dictionary contains a entity with an invalid attribute property
        :raises blesuite.utils.validators.InvalidATTSecurityMode: if the provided BLEDevice dictionary contains a entity with an invalid attribute permission
        """
        import blesuite.utils.validators as validator

        device_attributes = device_dictionary.keys()
        if 'name' in device_attributes:
            self.name = device_dictionary['name']

        if 'address' in device_attributes:
            address = validator.validate_bluetooth_address(device_dictionary['address'])
            self.address = address

        if 'address_type' in device_attributes:
            address_type = validator.validate_address_type_name(device_dictionary['address_type'])
            self.address_type = address_type

        services = device_dictionary['services']
        for service in services:
            # We will update these service attributes in the service import function
            ble_service = BLEService(None, None, None)
            ble_service.import_service_from_dictionary(service)
            self.services.append(ble_service)
        return

    def print_device_structure(self):
        """ Print device information, maintaining hierarchy of device, services, characteristics.

        :return:
        """
        print "\nDevice"
        print "======="
        print self.address, "\n"
        print "\nDevice Details"
        print "==============="
        for info in self.device_information:
            print info[0].upper()+":"
            print "\tUUID:", info[1]
            if info[2] is not None:
                print "\tHandle:", "".join("{:02x}".format(ord(c)) for c in info[2])
            else:
                print "\tHandle:"
            for val in info[3]:
                print_data_and_hex(val, False, prefix="\t")
        print "Services and Characteristics"
        print "============================="
        for service in self.services:
            print service.uuid, " start:", format(service.start, '#8x'), " end:", format(service.end, '#8x'),\
                  "type: ", service.get_type_string()
            for incl in service.includes:
                print "\tIncluded Service - Handle:", incl.handle, "Handles of included service:", \
                    format(incl.included_service_att_handle, '#8x'),\
                    "end group handle:", format(incl.included_service_end_group_handle, '#8x'), " Service UUID:", \
                    incl.included_service_uuid, " type: ", incl.get_type_string()
            for characteristic in service.characteristics:
                print "\t", characteristic.uuid, " value_handle:", format(characteristic.value_handle, '#8x'),\
                    " declaration handle:", format(characteristic.handle, '#8x'), " properties:", \
                    format(characteristic.gatt_properties, '#4x'), " permissions:", \
                    characteristic.calculate_permission(), " type: ", characteristic.get_type_string()
                for descriptor in characteristic.descriptors:
                    print "\t\tUUID:", descriptor.uuid
                    if descriptor.type is None:
                        print "\t\t\tType:"
                    else:
                        print "\t\t\tType: " + descriptor.type_string
                    print "\t\t\thandle:", format(descriptor.handle, '#8x')
                    #print "Raw:", descriptor.lastReadValue
                    if descriptor.value is not None:
                        if isinstance(descriptor.value, list):
                            for val in descriptor.value:
                                print_data_and_hex(val, False, prefix="\t\t\t")
                        else:
                            print_data_and_hex(descriptor.value, False, prefix="\t\t\t")

            print ""
        print "=============================\n"

