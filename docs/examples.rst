Examples
========

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
