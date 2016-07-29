from gattlib import GATTRequester, GATTResponse

class BLEConnectionManager(object):
    """BLEConnectionManager is used to manage a connection to a
    Bluetooth Low Energy device. This class allows us to connect,
    create a requester, create a response, and disconnect from
    a BLE device.

    :param address: MAC address (BD_ADDR) of target BTLE device
    :param adapter: BTLE adapter on host machine to use for connection (defaults to first found adapter). If an empty string is submitted, we connect to the host's default adapter.
    :param addressType: Type of address you want to connect to [public | random]
    :param securityLevel: Security level [low | medium | high]
    :param createRequester: When creating the connection manager, we can choose to create the requester or not. It can be helpful to set this to False when overriding methods in the GATTRequester class.
    :param psm: Specific PSM (default: 0)
    :param mtu: Specific MTU (default: 0)
    :type address: str
    :type adapter: str
    :type addressType: str
    :type securityLevel: str
    :type createRequester: bool
    :type psm: int
    :type mtu: int
    :ivar address: initial value: address
    :ivar adapter: initial value: adapter
    :ivar createRequester: initial value: createRequester
    :ivar requester: initial value: GATTRequester(address, False, adapter) if createRequester == True, else None
    :ivar responses: initial value: []

    """
    def __init__(self, address, adapter, addressType, securityLevel, createRequester=True, psm=0, mtu=0):
        self.address = address
        self.adapter = adapter
        self.requester = None
        self.responses = []
        self.responseCounter = 0
        self.addressType = addressType
        self.securityLevel = securityLevel
        self.psm = psm
        self.mtu = mtu
        if createRequester:
            self.createRequester()

    def __del__(self):
        if self.requester is not None and self.requester.is_connected():
            self.disconnect()

    def createRequester(self):
        """Create a GATTRequester for the BLEConnectionManager

        :return: Returns the newly created requester
        :rtype: GATTRequester

        """
        if self.adapter == "":
            self.requester = GATTRequester(self.address, False)
        else:
            self.requester = GATTRequester(self.address, False, self.adapter)
        return self.requester

    def setRequester(self, requester):
        """Sets the BLEConnectionManager's requester to
        the user-supplied GATTRequester

        :param requester: Custom GATTRequester
        :type requester: GATTRequester
        :return: None
        """
        self.requester = requester

    def setResponse(self, response):
        """Sets the BLEConnectionManager's response to
        the user-supplied GATTResponse

        :param response: Custom GATTResponse
        :type response: GATTResponse
        :return: None
        """
        self.response = response

    def createResponse(self, responseFunction=None):
        """Create a GATTResponse for the BLEConnectionManager.
        If a responseFunction is supplied, then the GATTResponse
        created will have an overridden on_response function.
        The responseFunction most only accept one parameter,
        which is the data contained in the response. The response
        is assigned an ID and stored in the response list.

        :param responseFunction: Function pointer called
        with a single parameter (data in response) when
        data is received. If not supplied, the GATTResponse
        function .received() can be called to access data (note: this
        function is not available if the responseFunction is specified)
        :type responseFunction: function pointer
        :return: Tuple with the response ID and response object
        :rtype: tuple (int, GATTResponse)
        """
        class BLECustomResponse(GATTResponse):
            def __init__(self, responseFunction):
                super(BLECustomResponse, self).__init__()
                self.responseFunction = responseFunction

            def on_response(self, data):
                if self.responseFunction is not None:
                    self.responseFunction(data)
        if responseFunction is not None:
            response = (self.responseCounter + 1, BLECustomResponse(responseFunction))
        else:
            response = (self.responseCounter + 1, GATTResponse())
        self.responses.append(response)
        self.responseCounter += 1
        return response


    def isConnected(self):
        """ Return whether the connection manager's requester is still connected to a device
        :return: Return requester connection status
        :rtype: bool
        """
        return self.requester.is_connected()

    def connect(self):
        """Connect to BLE device using BLEConnectionManager's requester

        :return:
        """
        if not self.requester.is_connected():
            self.requester.connect(True, self.addressType, self.securityLevel, self.psm, self.mtu)

    def disconnect(self):
        """Disconnect from BLE device using BLEConnectionManager's requester

        :return:
        """
        self.requester.disconnect()

