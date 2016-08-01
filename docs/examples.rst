Examples
========

Read By UUID Example
--------------------
.. code-block:: python

   from bleSuite import bleConnectionManager, bleServiceManager

   address = "BC:6A:29:AC:1F:2A"
   adapter = ""
   addressType = "public"
   securityLevel = "low"

   #create connection manager to establish and maintain our connection
   connectionManager = bleConnectionManager.BLEConnectionManager(address, adapter, addressType, securityLevel)

   #connect
   connectionManager.connect()

   #read UUID 2A00
   data = bleServiceManager.bleServiceReadByUUID(connectionManager, "2A00")
   

Asynchronous Communication
--------------------------
.. code-block:: python

   from bleSuite import bleConnectionManager, bleServiceManager
   import time

   def asyncCallback(data):
		print "Response1 Received Data:"
   print data

   address = "BC:6A:29:AC:1F:2A"
   adapter = ""
   addressType = "public"
   securityLevel = "low"
   handle = int("6c", 16)

   connectionManager = bleConnectionManager.BLEConnectionManager(address, adapter, addressType, securityLevel)

   connectionManager.connect()

   #async write that calls asyncCallback when response is received
   respID, resp = bleServiceManager.bleServiceReadByHandleAsync(connectionManager, handle, asyncCallback)

   #async write that has no callback
   respID2, resp2 = bleServiceManager.bleServiceReadByHandleAsync(connectionManager, handle)

   #attempt to get response from resp2 five times over five seconds
   tries = 0
   while tries < 5:
		if resp2.received():
		     print "Response 2 Received Data:"
		     print resp2.received()
		     break

		time.sleep(1)
		tries +=1

Notification Example
--------------------
.. code-block:: python

   from bleSuite import bleConnectionManager, bleServiceManager
   from gattlib import GATTRequester
   import logging
   import time

   #initiate logging
   logger = logging.getLogger(__name__)
   logger.addHandler(logging.NullHandler())
   logging.basicConfig(level=logging.DEBUG)

   #target address
   addr = 'BC:6A:29:AC:1F:2A'
   #target handle to write to
   handle = int('0d',16)
   #configuration handle for notifications
   ccHandle = int('0e', 16)
   #enable notification packet
   enableNotificationData = '\x01\x00'
   #some test data to send
   testData1 = '\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00\x01\x00'
   testData2 = '010001000100010001000100010001000100'.decode('hex')
   connectionManager = bleConnectionManager.BLEConnectionManager(addr, '', 'public', 'low', createRequester=False)
   newVal = ""
   receivedVals = []
   class Requester(GATTRequester):
	       def __init__(self, wakeup, receivedVals, *args):
	            global newVal, logger
		    GATTRequester.__init__(self, *args)
		    self.wakeup = wakeup
		    self.receivedVals = receivedVals
	       def on_notification(self, handle, data):
	            global newVal, logger
		    logger.debug("Got notification from handle: %s data: %s" % (handle, data))
		    logger.debug("Raw Bytes: %s" % (" ".join("{:02x}".format(ord(c)) for c in data)))
		    self.receivedVals.append(data)
		    self.wakeup.set()
		    
   class ReceiveNotification(object):
	       def __init__(self, connectionManager, received):
	            logger.debug("Initializing receiver")
		    self.connectionManager = connectionManager
		    self.received = received
		    self.wait_notification()
		    
	       def connect(self):
	            logger.debug("Connecting...")
		    sys.stdout.flush()
		    self.connectionManager.connect()
		    logger.debug("OK!")
		    def wait_notification(self):
		    logger.debug("Listening for communications")
		    self.received.wait()
		    
   received =  Event()
   connectionManager.setRequester(Requester(received, receivedVals, addr, False))
   connectionManager.connect()
   while True:
	       try:
	            if not connectionManager.isConnected():
		         connectionManager.connect()
		    bleServiceManager.bleServiceWriteToHandle(connectionManager, ccHandle, enableNotificationData)
		    bleServiceManager.bleServiceWriteToHandle(connectionManager, handle, testData1+testData2)
		    ReceiveNotification(connectionManager, received)
		    bleServiceManager.bleServiceWriteToHandle(connectionManager, handle, unlock)
		    connectionManager.disconnect()
		    
	       except RuntimeError as e:
	            continue


SmartScan Example
-----------------
.. code-block:: python

   from bleSuite import bleConnectionManager, bleSmartScan

   address = "BC:6A:29:AC:1F:2A"
   adapter = ""
   addressType = "public"
   securityLevel = "low"

   #create connection manager to establish and maintain our connection
   connectionManager = bleConnectionManager.BLEConnectionManager(address, adapter, addressType, securityLevel)

   #connect
   connectionManager.connect()

   #create our BLEDevice object that represents our target BLE device
   #this object stores all properties obtained from the device. Populate
   #with general device info, services, characteristics, and descriptors
   #with current values
   bleDevice = bleSmartScan.bleSmartScan(address, connectionManager)

   #print device representation
   bleDevice.printDeviceStructure()
