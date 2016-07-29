from gattlib import DiscoveryService


def bleScanMain(timeout, adapter):
    """
    Scan for BTLE Devices and print out results

    :param timeout: Scan timeout (seconds)
    :param adapter: Host adapter to use for scanning (Use empty string to use host's default adapter)
    :type timeout: int
    :type adapter: str
    :return: Tuple (deviceName, deviceAddress)
    :rtype: tuple (str, str)
    """
    if timeout < 0:
        raise Exception("%s is an invalid scan timeout value. The timeout must be a positive integer" % timeout)
    if adapter != "":
        service = DiscoveryService(adapter)
    else:
        service = DiscoveryService()
    devices = service.discover(timeout)
    return devices

