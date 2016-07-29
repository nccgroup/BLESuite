from bleService import BLEService
from bleCharacteristic import BLECharacteristic
from bleSuite.utils.printHelper import printDataAndHex
import binascii

class BLEDevice(object):
    """BLEDevice is used to represent a BLE device, holding its address and services.

        :param address: MAC address (BD_ADD) of BLE device
        :type address: str
        :ivar address: initial value: address
        :ivar services: initial value: []
        :ivar deviceInformation: initial value: []

    """
    def __init__(self, address):
        self.address = address
        #list of service objects
        self.services = []
        self.deviceInformation = []
        #list of characteristic objects can be accessed via parent service objects
        #self.characteristics = []

    #start and end values are provided by the BLE Primary Service Scan
    def addService(self, start, end, uuid):
        """ Add a service object to the device

        :param start: Start handle
        :param end: End handle
        :param uuid: UUID of service
        :type start: int - base 10
        :type end: int - base 10
        :type uuid: str
        :return:
        """
        #self.services.append(service)
        service = BLEService(start, end, uuid)
        self.services.append(service)

    #value_handle and handle are provided by the BLE characteristic scan
    def addCharacteristic(self, valueHandle, handle, uuid, properties):
        """ Add a characteristic object to it's associated service on the device

        :param valueHandle: Value handle of characteristic
        :param handle: Handle of characteristic
        :param uuid: UUID of characteristic
        :param properties: Properties value of characteristic
        :type valueHandle: int - base 10
        :type handle: int - base 10
        :type uuid: str
        :type properties: int - base 10
        :return:
        """
        for service in self.services:
            start = service.start
            end = service.end
            if handle >= start and handle <= end:
                characteristic = BLECharacteristic(valueHandle, handle, uuid, properties, service.uuid)
                service.characteristics.append(characteristic)

    def addDeviceInfo(self, name, UUID, handles, data):
        self.deviceInformation.append((name, UUID, handles, data))
        return

    def serviceHasHandle(self, handle):
        """ Check whether any services on the device contain the specified handle

        :param handle: Target handle
        :return: Existence of handle
        :rtype: bool
        """
        for service in self.services:
            for characteristic in service.characteristics:
                #print "handle base: ", characteristic.handle
                if characteristic.valueHandle == handle:
                    return True
        return False




    def printDeviceStructure(self):
        """ Print device information, maintaining hierarchy of device, services, characteristics.

        :return:
        """
        print "\nDevice"
        print "======="
        print self.address, "\n"
        print "\nDevice Details"
        print "==============="
        for info in self.deviceInformation:
            print info[0].upper()+":"
            print "\tUUID:", info[1]
            if info[2] is not None:
                if isinstance(info[2], list):
                    h = ""
                    for i in info[2]:
                        h += "".join("{:02x}".format(ord(c)) for c in i) + " "
                    if len(info[2]) > 1:
                        print "\tHandles:", h
                    else:
                        print "\tHandle:", h
                else:
                    print "\tHandle:", "".join("{:02x}".format(ord(c)) for c in info[2])
            else:
                print "\tHandle:"
            printDataAndHex(info[3], False, prefix="\t")
        print "Services and Characteristics"
        print "============================="
        for service in self.services:
            print service.uuid, " start:", format(service.start, '#8x'), " end:", format(service.end, '#8x')
            for characteristic in service.characteristics:
                print "\t", characteristic.uuid, " value_handle:", format(characteristic.valueHandle, '#8x'),\
                    " handle:", format(characteristic.handle, '#8x'), " properties:", \
                    format(characteristic.properties, '#4x'), " permissions:", \
                    characteristic.calculatePermission()
                for descriptor in characteristic.descriptors:
                    print "\t\t", " handle:", format(descriptor.handle, '#8x')
                    #print "Raw:", descriptor.lastReadValue
                    printDataAndHex(descriptor.lastReadValue, False, prefix="\t\t\t")

            print ""
        print "=============================\n"

