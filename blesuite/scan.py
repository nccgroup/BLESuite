import time
import gevent
import logging
from blesuite.pybt.gap import GAP
from blesuite import connection_manager

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

"""
BLE Device scanning helper funcions.
"""
def blesuite_scan_main(timeout, adapter):
    """
    Scan for BTLE Devices and print out results

    :param timeout: Scan timeout (seconds)
    :param adapter: Host adapter to use for scanning (Use empty string to use host's default adapter)
    :type timeout: int
    :type adapter: str
    :return: Discovered devices ({<address>:(<addressType>, <data>)})
    :rtype: dict
    """
    from connection_manager import BLEConnectionManager
    if timeout < 0:
        raise Exception("%s is an invalid scan timeout value. The timeout must be a positive integer" % timeout)

    with BLEConnectionManager(adapter, "central") as connectionManager:
        connectionManager.start_scan()
        start = time.time() * 1000
        logger.debug("Starting sleep loop")
        while ((time.time() * 1000) - start) < (timeout * 1000):
            logger.debug("Scanning...")
            gevent.sleep(1)
            connectionManager.stop_scan()
        logger.debug("Done scanning!")
        discovered_devices = connectionManager.get_discovered_devices()

    return discovered_devices
