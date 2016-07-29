from permissions import Permissions
from bleDescriptor import BLEDescriptor

class BLECharacteristic(object):
    """ BLECharacteristic is used to represent a characteristic of a service located on a BTLE device

        :var valueHandle: Start handle for service
        :var handle: End handle for service
        :var uuid: UUID of characteristic
        :var properties: Property value of characteristic
        :var serviceUuid: UUID of parent service
        :type valueHandle: int - base 10
        :type handle: int - base 10
        :type uuid: str
        :type properties: int - base 10
        :type serviceUuid: str
        :ivar valueHandle: initial value: valueHandle
        :ivar handle: initial value: handle
        :ivar uuid: initial value: uuid
        :ivar properties: initial value: properties
        :ivar parentServiceUuid: initial value: serviceUuid
        :ivar lastReadValue: initial value: None
        :ivar descriptors: initial value: []

    """
    def __init__(self, valueHandle, handle, uuid, properties, serviceUuid):
        self.uuid = uuid
        self.parentServiceUuid = serviceUuid
        self.valueHandle = valueHandle
        self.handle = handle
        #property is the permission set on a characteristic
        self.properties = properties
        self.lastReadValue = None
        self.descriptors = []

    def calculatePermission(self):
        """
        Calculate a printable string of permissions for a characteristic
        based on its properties

        :return: Permission String
        :rtype: str
        """
        permission = ""
        for perm in Permissions.permissionDict.keys():
            if self.properties & perm == perm:
                if len(permission) == 0:
                    permission += Permissions.permissionDict[perm]
                else:
                    permission += " / " + Permissions.permissionDict[perm]

        return permission

    def addDescriptorWithData(self, handle, data):
        """
        Create a descriptor object, set the object's lastReadValue, and
        add it to the descriptors list.

        :param handle: Handle of descriptor
        :param data: Data received after reading from descriptor handle
        :type handle: int - base 10
        :type data: list of strings
        :return:
        """
        descriptor = BLEDescriptor(handle)
        descriptor.lastReadValue = data
        self.descriptors.append(descriptor)
