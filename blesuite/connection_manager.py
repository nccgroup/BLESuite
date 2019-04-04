from blesuite.pybt.roles import LECentral, LEPeripheral
from blesuite.pybt.core import Connection
from blesuite.pybt.gatt import UUID, AttributeDatabase, Server
from blesuite.pybt.gap import GAP

from blesuite.gatt_procedures import gatt_procedure_write_handle, gatt_procedure_write_handle_async, \
                                       gatt_procedure_read_handle, gatt_procedure_read_handle_async, \
                                       gatt_procedure_read_uuid, gatt_procedure_read_uuid_async, \
                                       gatt_procedure_discover_primary_services, \
                                       gatt_procedure_discover_secondary_services, \
                                       gatt_procedure_discover_characteristics, \
                                       gatt_procedure_discover_includes, \
                                       gatt_procedure_discover_descriptors, gatt_procedure_prepare_write_handle, \
                                       gatt_procedure_prepare_write_handle_async, gatt_procedure_execute_write, \
                                       gatt_procedure_execute_write_async, gatt_procedure_write_command_handle, \
                                       gatt_procedure_read_multiple_handles, \
                                       gatt_procedure_read_multiple_handles_async, \
                                       gatt_procedure_read_blob_handle, gatt_procedure_read_blob_handle_async

from blesuite.smart_scan import blesuite_smart_scan
from blesuite.entities.gatt_device import BLEDevice
from blesuite.event_handler import BTEventHandler
import logging
import gevent
import os

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ROLE_CENTRAL = 0x00
ROLE_PERIPHERAL = 0x01

PUBLIC_DEVICE_ADDRESS = 0x00
RANDOM_DEVICE_ADDRESS = 0x01


class BLEConnection(object):
    """
    BLEConnection is used to represent a connection between the BLEConnection manager
    and a BLE device. This object is commonly returned to the user to represent a connection and is passed
    to further BLEConnectionManager functions to interact with the connections.

    :param address: The address of the peer BLEDevice that the HCI device is connected to.
    :param address_type: The address type of the peer BLEDevice [Central = 0x00 | Peripheral = 0x01]
    :param connection_handle: The connection handle used to interact with the associated peer BLE device.
    :type address: str
    :type address_type: int
    :type connection_handle: int
    """
    def __init__(self, address, address_type, connection_handle=None):
        self.address = address
        self.address_type = address_type
        self.connection_handle = connection_handle
        self.interval_min = None
        self.interval_max = None
        self.mtu = 23  # default as per spec

    def __repr__(self):
        return '<{} address={}, type={}>'.format(
            self.__class__.__name__,
            self.address,
            {0: "random", 1: "public"}.get(self.address_type, "Unknown")
        )


class BLEConnectionManager(object):
    """
    BLEConnectionManager is used to manage connections to Bluetooth Low Energy Devices.
    The connection manager is associated with an HCI device, such as a Bluetooth USB adapter,
    and is responsible for creating the BLE stack and providing a user-friendly interface for
    interacting with the BLE stack in order to send and receive packets.

    :param adapter: BTLE adapter on host machine to use for connection (defaults to first found adapter). If left blank, the host's default adapter is used.
    :param role: Type of role to create for the HCI device [central | peripheral]
    :param our_address_type: Type of address for our Bluetooth Adapter. [public | random] (default: "public"). Note: We currently only support static random addresses, not resolvable or non-resolvable private addresses.
    :param random_address: If our address type is set to random, supply a random address or one will be randomly generated ("AA:BB:CC:DD:EE:FF") (default: None)
    :param psm: Specific PSM (default: 0)
    :param mtu: Specific MTU (default: 23 as per spec BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] 5.2.1)
    :param gatt_server: GATT Server from pybt. Used to assign a custom blesuite.pybt.gatt Server object as the server for a peripheral. Alternatively, by default if the peripheral role is configured, a GATT Server object will be created with no services or characteristics that the user can add to through BLEConnectionManager class methods.
    :param event_handler: BTEventHandler class instance that will be called when packets are received by the blesuite.pybt.core packet routing class (SocketHandler).
    :param att_operation_event_hook: ATT operation hook functions triggered when the ATT server receives an ATT request
    :param att_security_event_hook: ATT security hook functions triggered when the ATT server receives an ATT request and security checks are made
    :type att_security_event_hook: blesuite.event_handler.ATTSecurityHook
    :type att_operation_event_hook: blesuite.event_handler.ATTEventHook
    :type adapter: int
    :type role: str
    :type our_address_type: str
    :type random_address: str
    :type psm: int
    :type mtu: int
    :type gatt_server: Server
    :type event_handler: BTEventHandler

    """

    def __init__(self, adapter, role, our_address_type="public", random_address=None,
                 psm=0, mtu=23, gatt_server=None, event_handler=None, att_operation_event_hook=None,
                 att_security_event_hook=None):

        self.role_name = role
        self.adapter = adapter
        self.requester = None
        self.responses = []
        self.response_counter = 0
        self.psm = psm
        self.mtu = mtu
        self.gatt_server = gatt_server
        self.event_handler = event_handler
        self.att_operation_event_hook = att_operation_event_hook
        self.att_security_event_hook = att_security_event_hook
        self.address = None
        self.our_address_type_name = our_address_type
        if self.our_address_type_name.lower() == "random":
            self.our_address_type = RANDOM_DEVICE_ADDRESS
        else:
            self.our_address_type = PUBLIC_DEVICE_ADDRESS

        if self.our_address_type == RANDOM_DEVICE_ADDRESS and random_address is None:
            self.random_address = ':'.join(map(lambda x: x.encode('hex'), os.urandom(6)))
        elif self.our_address_type == RANDOM_DEVICE_ADDRESS:
            self.random_address = random_address
        else:
            self.random_address = None

        self.central = None
        self.stack_connection = None
        self.connections = []

        if role is 'central':
            logger.debug("creating central")
            self._create_central()
            logger.debug("creating PyBT connection")
            self._create_stack_connection(ROLE_CENTRAL)
            logger.debug("creating listeners")
            self._start_listeners()
        elif role is 'peripheral':
            logger.debug("creating peripheral role")
            self._create_peripheral()
            logger.debug("creating PyBT connection")
            self._create_stack_connection(ROLE_PERIPHERAL)
            logger.debug("creating listeners")
            self._start_listeners()
        else:
            logger.error("Unknown role: %s" % role)
            raise RuntimeError("Unknown role: %s" % role)
        self.address = self.role.stack.addr

    def __enter__(self):
        return self

    def __del__(self):
        if self.stack_connection is not None:
            for connection in self.connections:
                if self.stack_connection.is_connected(connection.connection_handle):
                    self.stack_connection.disconnect(connection.connection_handle, 0x16)
            self.stack_connection.destroy()
            self.stack_connection = None

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Exiting bleConnectionManager. exc_type:%s exc_val:%s exc_tb:%s" % (exc_type, exc_val, exc_tb))
        if self.stack_connection is not None:
            self.stack_connection.destroy()
            self.stack_connection = None
        if self.role is not None:
            self.role.destroy()
            self.role = None

    def _create_central(self):
        if self.adapter is None:
            self.role = LECentral(address_type=self.our_address_type, random=self.random_address,
                                  att_operation_event_hook=self.att_operation_event_hook)
        else:
            self.role = LECentral(adapter=self.adapter, address_type=self.our_address_type, random=self.random_address,
                                  att_operation_event_hook=self.att_operation_event_hook)

    def _create_peripheral(self):
        if self.gatt_server is None:
            self.attribute_db = AttributeDatabase(event_handler=self.att_security_event_hook)
            self.gatt_server = Server(self.attribute_db)
            self.gatt_server.set_mtu(self.mtu)
        if self.adapter is None:
            self.role = LEPeripheral(self.gatt_server, mtu=self.mtu, address_type=self.our_address_type,
                                     random=self.random_address,
                                     att_operation_event_hook=self.att_operation_event_hook)
        else:
            self.role = LEPeripheral(self.gatt_server, adapter=self.adapter, mtu=self.mtu,
                                     address_type=self.our_address_type, random=self.random_address,
                                     att_operation_event_hook=self.att_operation_event_hook)

    def _create_stack_connection(self, role_type):
        if self.event_handler is None:
            self.event_handler = BTEventHandler(self)
        self.stack_connection = Connection(self.role, role_type, self.event_handler)

    def _start_listeners(self):
        self.stack_connection.start()

    def get_address(self):
        """ Get the address of the HCI device represented by the BLEConnectionManager.

        :return: The HCI device address
        :rtype: str
        """
        return self.address

    def get_discovered_devices(self):
        """
        Get a dictionary of address seen during a scan and the associated advertising data.
        
        :return: Dictionary of seen addresses and advertising data
        :rtype: dict {"<address>":(<addressTypeInt>, "<advertisingData>")}
        """
        return self.stack_connection.seen

    def set_event_handler(self, event_class):
        """
        Set the BTEventHandler for the pybt.core.SocketHandler class that will trigger when a Bluetooth Event
        is received by the stack.
        
        :param event_class: Event handler class instance.
        :type event_class: BTEventHandler
        
        :return: Success state
        :rtype: bool
        """
        logger.debug("Trying to set event handler")
        self.event_handler = event_class
        if self.stack_connection.socket_handler is not None:
            logger.debug("Stack connection found, setting event handler")
            self.stack_connection.set_event_handler(event_class)
            return True
        return False

    def set_att_operation_hook(self, event_class):
        """
        Set the ATTEventHook for the pybt.att.AttributeProtocol class that will trigger when an ATT operation
        against the ATT database running locally is received.

        :param event_class: ATT event class hook instance.
        :type event_class: ATTEventHook

        :return: Success state
        :rtype: bool
        """
        logger.debug("Trying to set ATT operation hook")
        self.att_operation_event_hook = event_class
        self.role.att.event_handler = self.att_operation_event_hook
        return True

    def set_att_security_hook(self, event_class):
        """
        Set the ATTSecurityHook for the pybt.gatt.AttributeDatabase class that will trigger when a security
        check against an ATT operation acting on the ATT database occurs. These checks cover encryption,
        authentication, and authorization.

        :param event_class: ATT security event hook class instance.
        :type event_class: ATTSecurityHook

        :return: Success state
        :rtype: bool
        """
        logger.debug("Trying to set ATT security hook")
        self.att_security_event_hook = event_class
        if self.gatt_server is None:
            logger.debug("No GATT server running, setting security hook failed.")
            return False
        self.gatt_server.db.att_security_hooks = self.att_security_event_hook
        return True

    def is_connected(self, connection):
        """ Return whether the specified connection is connected to the peer device.
        
        :return: Return connection status
        :rtype: bool
        """
        return self.stack_connection.is_connected(connection.connection_handle)

    def init_connection(self, address, address_type):
        """
        Create BLEConnection object that represents the host's connection to a BLE peripheral.
        
        :param address: BD_ADDR of target BLE Peripheral
        :param address_type: Address type of target BLE Peripheral [public | random]

        :type address: string
        :type address_type: string
        
        :return: Return BLEConnection object that is used in any communication function.
        :rtype: BLEConnection
        """

        address = address.upper()
        if address_type == "public":
            address_type = PUBLIC_DEVICE_ADDRESS
        elif address_type == "private":
            address_type = RANDOM_DEVICE_ADDRESS

        ble_connection = BLEConnection(address, address_type)
        self.connections.append(ble_connection)
        return ble_connection

    def get_bleconnection_from_connection_handle(self, connection_handle):
        """
        Lookup a BLEConnection based on a supplied connection handle value.
        
        :param connection_handle: Connection handle used to look up an existing BLEConnection
        :type connection_handle: int
        
        :return: BLEConnection or None
        :rtype: BLEConnection or None
        """
        for connection in self.connections:
            if connection.connection_handle is not None and connection.connection_handle == connection_handle:
                return connection
        return None

    def connect(self, ble_connection, timeout=15):
        """
        Initiate a connection with a peer BLEDevice.
        
        :param ble_connection: BLEConnection that represents the connection between our HCI device and the peer
        :type ble_connection: BLEConnection
        :param timeout: Connection timeout in seconds (default: 15)
        :type timeout: int
        :return: Connected status
        :rtype: bool
        """
        import time

        start = time.time()
        if not self.stack_connection.is_connected(ble_connection.connection_handle):
            request = self.stack_connection.connect(ble_connection.connection_handle, ble_connection.address,
                                                    kind=ble_connection.address_type)
            while not request.has_response():
                if timeout is not None and time.time() - start >= timeout:
                    logger.debug("Connection failed: Connection timeout reached.")
                    return False
                logger.debug("Is not connected")
                gevent.sleep(1)

            ble_connection.connection_handle = request.response.conn_handle
            logger.debug("Connected")
            return True

    def disconnect(self, connection, reason=0x16):
        """
        Disconnect from a peer BLE device.
        
        :param connection: BLEConnection to disconnect
        :type connection: BLEConnection
        :param reason: The reason for the disconnection (default: 0x16 - Connection terminated by local host). Reasons defined in BLUETOOTH SPECIFICATION Version 5.0 | Vol 2, Part E page 777
        :type reason: int
        """
        self.stack_connection.disconnect(connection.connection_handle, reason)

    def pair(self, ble_connection, timeout=15):
        """
        Initiate pairing with a peer BLE device. This method is blocking and will wait
        until a paired connection is received, pairing fails, or the timeout is reached.
        If custom pairing request parameters are required, configure
        the parameters prior to calling this function.
        
        :param ble_connection: The BLEConnection to initiate pairing on
        :type ble_connection: BLEConnection
        :param timeout: Pairing timeout in seconds (default: 15)
        :type timeout: int
        :return: Pairing status
        :rtype: bool
        """
        import time

        self.initiate_pairing(ble_connection)
        start = time.time()

        while not self.role.smp.get_connection_encryption_status(ble_connection.connection_handle):
            if self.role.smp.did_pairing_fail(ble_connection.address):
                logger.debug("Pairing Failed")
                return False
            if timeout is not None and time.time() - start >= timeout:
                return False
            logger.debug("Pairing in progress. Pairing Failed: %s " % self.role.smp.did_pairing_fail(ble_connection.address))
            gevent.sleep(1)
        logger.debug("Paired")
        return True

    def initiate_pairing(self, ble_connection):
        """
        Send pairing request to peer device. This is meant as an asynchronous way for a user to initiate pairing
        and manage the connection while waiting for the pairing process to complete. Use BLEConnectionManager.pair
        for a synchronous pairing procedure.
        
        :param ble_connection: The BLEConnection to initiate pairing on
        :type ble_connection: BLEConnection
        :return:
        :rtype:
        """
        if not self.is_connected(ble_connection):
            self.connect(ble_connection)
        self.role.smp.send_pairing_request(ble_connection.address, ble_connection.connection_handle)

    def is_pairing_in_progress(self, ble_connection):
        """
        Retrieve pairing status of BLEConnection
        
        :param ble_connection: The BLEConnection to view the pairing status of
        :type ble_connection: BLEConnection
        :return: Status of BLE pairing
        :rtype: bool
        """
        return self.role.smp.is_pairing_in_progress(ble_connection.address)

    def did_pairing_fail(self, ble_connection):
        """
        Lookup whether a pairing failed status was triggered
        
        :param ble_connection: The BLEConnection to check for a pairing failure
        :type ble_connection: BLEConnection
        :return: Pairing failure status (True means failure was triggered)
        :rtype: bool
        """
        return self.role.smp.did_pairing_fail(ble_connection.address)

    def is_connection_encrypted(self, ble_connection):
        """
        Retrieve BLEConnection encryption status
        
        :param ble_connection: The BLEConnection to check the encryption status of
        :type ble_connection: BLEConnection
        :return: Encryption status
        :rtype: bool
        """
        return self.role.smp.get_connection_encryption_status(ble_connection.connection_handle)

    def resume_connection_encryption(self, ble_connection):
        """
        Initiate BLEConnection encryption with encryption keys present in the Security Manager's LongTermKeyDatabase.
        Encryption key look-up is done based on the address of the peer device's address.
        
        :param ble_connection: The BLEConnection to resume encryption on
        :type ble_connection: BLEConnection
        :return: Result of encryption initiation with existing keys (True if encryption initiation was successfully start, False if encryption keys were not found)
        :rtype: bool
        """
        result = self.role.smp.initiate_encryption_with_existing_keys(ble_connection.address,
                                                                      ble_connection.address_type,
                                                                      ble_connection.connection_handle, self.address,
                                                                      self.our_address_type, self.role)

        return result

    def get_security_manager_long_term_key_database(self):
        """
        Retrieve the LongTermKeyDatabase from the Security Manager
        
        :return: LongTermKeyDatabase from the Security Manager
        :rtype: blesuite.pybt.sm.LongTermKeyDatabase
        """
        return self.role.smp.long_term_key_db

    def add_key_to_security_manager_long_term_key_database(self, address, address_type, ltk, ediv, rand, irk, csrk, security_mode,
                                                          security_level):
        """
        Add an entry to the LongTermKeyDatabase that will be used for encryption key lookups when encryption
        on a BLEConnection is initiated
        
        :param address: Address of peer device (byte form, big-endian)
        :type address: str
        :param address_type: Address type of peer device
        :type address_type: int
        :param ltk: Long term key for peer (big-endian)
        :type ltk: str
        :param ediv: EDIV for peer. Required for LE Legacy encryption resumption
        :type ediv: int
        :param rand: Encryption Random for peer  (big-endian). Required for LE Legacy encryption resumption
        :type rand: str
        :param irk: IRK for peer (big-endian)
        :type irk: str
        :param csrk: CSRK for peer
        :type csrk: str
        :param security_mode: Security mode associated with encryption keys. This mode will be applied to a connection encrypted with these keys.
        :type security_mode: int
        :param security_level: Security level associated with encryption keys. This level will be applied to a connection encrypted with these keys.
        :type security_level: int
        :return:
        :rtype:
        """
        self.role.smp.long_term_key_db.add_long_term_key_entry(address, address_type,
                                                               ltk, ediv, rand, irk, csrk, security_mode,
                                                               security_level)

    def export_security_manager_long_term_key_database_for_storage(self):
        """
        Export Security Manager LongTermKeyDatabase as a list of dictionary containing BLE
        encryption properties (LTK, EDIV, random,
        CSRK, IRK, security mode, security level) with integers and hex encoded strings
        
        :return: LongTermKeyDatabase as a list of dictionaries with integers and hex encoded strings (user-friendly exportable version)
        :rtype: dict
        """
        ltk_db = self.role.smp.long_term_key_db.get_long_term_key_database()

        for entry in ltk_db:
            temp = entry['address']
            if temp is not None:
                temp = temp.encode('hex')
            entry['address'] = temp
            temp = entry['ltk']
            if temp is not None:
                temp = temp.encode('hex')
            entry['ltk'] = temp
            temp = entry['rand']
            if temp is not None:
                temp = temp.encode('hex')
            entry['rand'] = temp
            temp = entry['irk']
            if temp is not None:
                temp = temp.encode('hex')
            entry['irk'] = temp
            temp = entry['csrk']
            if temp is not None:
                temp = temp.encode('hex')
            entry['csrk'] = temp

        return ltk_db

    def import_long_term_key_database_to_security_manager(self, long_term_key_database):
        """
        Import LongTermKeyDatabase and apply it to the Security Manager. Import database format is identical
        to the LongTermKeyDatabase export format with integers and hex encoded strings. The function will perform
        some input validation to ensure proper encoding and value types.
        
        :param long_term_key_database: List of dictionaries of LongTermKeyDatabase entries with integers and hex encoded strings
        :type long_term_key_database: list of dict
        :return:
        :rtype:
        """
        import blesuite.utils.validators as validator
        for entry in long_term_key_database:
            keys = entry.keys()
            if 'address' in keys:
                peer_address = entry['address'].decode('hex')
            else:
                peer_address = "00" * 6

            if 'address_type' in keys:
                peer_address_type = entry['address_type']
            else:
                peer_address_type = 0

            if 'ltk' in keys:
                ltk = validator.validate_ltk(entry['ltk']).decode('hex')
            else:
                raise validator.InvalidSMLTK(None)

            if 'ediv' in keys:
                ediv = entry['ediv']
            else:
                ediv = 0

            if 'rand' in keys:
                rand = validator.validate_rand(entry['rand']).decode('hex')
            else:
                rand = '\x00' * 8

            if 'irk' in keys:
                irk = validator.validate_irk(entry['irk']).decode('hex')
            else:
                irk = '\x00' * 16

            if 'csrk' in keys:
                csrk = validator.validate_csrk(entry['csrk']).decode('hex')
            else:
                csrk = '\x00' * 16

            if 'security_mode' in keys:
                mode = entry['security_mode']
            else:
                mode = 1
            if 'security_level' in keys:
                level = entry['security_level']
            else:
                level = 1

            mode, level = validator.validate_att_security_mode(mode, level)

            self.role.smp.long_term_key_db.add_long_term_key_entry(peer_address, peer_address_type, ltk, ediv, rand,
                                                                   irk, csrk, mode, level)

    def get_security_manager_protocol_default_pairing_parameters(self):
        """
        Get the default pairing parameters that will be applied to Security Managers by default.
        The pairing parameters are used by the devices to determine the type of pairing to use, the temporary key
        sharing method (association model), and which keys will be exchanged when pairing is complete (if any).
        See BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part H
        page 2340 - 2342 for more details.
        (Security Managers are created per BLE connection and can be modified independently)


        :return: {io_cap, oob, mitm, bond, lesc, keypress, ct2, rfu, max_key_size, initiator_key_distribution, responder_key_distribution}
        :rtype: dict
        """
        return self.role.smp.get_default_pairing_parameters()

    def set_security_manager_protocol_default_pairing_parameters(self, default_io_cap=0x03, default_oob=0x00,
                                                                 default_mitm=0x00,
                                                                 default_bond=0x01, default_lesc=0x00,
                                                                 default_keypress=0x00,
                                                                 default_ct2=0x01, default_rfu=0x00,
                                                                 default_max_key_size=16,
                                                                 default_initiator_key_distribution=0x01,
                                                                 default_responder_key_distribution=0x01):
        """
        Set the default pairing parameters that will be applied to Security Managers by default.
        The pairing parameters are used by the devices to determine the type of pairing to use, the temporary key
        sharing method (association model), and which keys will be exchanged when pairing is complete (if any).
        See BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part H
        page 2340 - 2342 for more details.
        (Security Managers are created per BLE connection and can be modified independently)
        
        :param default_io_cap: IO Capabilities (default: 0x03 - No Input, No Output)
        :type default_io_cap: int
        :param default_oob: Out-of-band Data present and available (default: 0x00)
        :type default_oob: int
        :param default_mitm: Request man-in-the-middle pairing protections (default: 0x01)
        :type default_mitm: int
        :param default_bond: Request bonding (default: 0x01)
        :type default_bond: int
        :param default_lesc: LE Secure Connections supported (default: 0x00)
        :type default_lesc: int
        :param default_keypress: Keypress notifications (default: 0x00)
        :type default_keypress: int
        :param default_ct2: CT2 (default: 0x01)
        :type default_ct2: int
        :param default_rfu: Reserved for future use bits (default: 0x00)
        :type default_rfu: int
        :param default_max_key_size: Max encryption key size (default: 16)
        :type default_max_key_size: int
        :param default_initiator_key_distribution: Requested keys to be sent by the initiator (central) (default: 0x01)
        :type default_initiator_key_distribution: int
        :param default_responder_key_distribution: Requested keys to be sent by the responder (peripheral) (default: 0x01)
        :type default_responder_key_distribution: int
        :return:
        :rtype:
        """
        self.role.smp.set_default_pairing_parameters(default_io_cap, default_oob, default_mitm, default_bond,
                                                     default_lesc, default_keypress, default_ct2, default_rfu,
                                                     default_max_key_size, default_initiator_key_distribution,
                                                     default_responder_key_distribution)

    def get_security_manager_protocol_pairing_parameters_for_connection(self, ble_connection):
        """
        Get the default pairing parameters for the Security Manager associated with a BLEConnection (based on the
        peer address).
        The pairing parameters are used by the devices to determine the type of pairing to use, the temporary key
        sharing method (association model), and which keys will be exchanged when pairing is complete (if any).
        See BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part H
        page 2340 - 2342 for more details.

        :param ble_connection: BLEConnection to modify Security Manager pairing parameters of
        :type ble_connection: BLEConnection
        :return: {io_cap, oob, mitm, bond, lesc, keypress, ct2, rfu, max_key_size, initiator_key_distribution, responder_key_distribution}
        :rtype: dict
        """
        return self.role.smp.get_pairing_parameters_for_connection(ble_connection.address)

    def set_security_manager_protocol_pairing_parameters_for_connection(self, ble_connection, io_cap=0x03, oob=0x00,
                                                                        mitm=0x00,
                                                                        bond=0x01, lesc=0x00, keypress=0x0, ct2=0x01,
                                                                        rfu=0x00, max_key_size=16,
                                                                        initiator_key_distribution=0x01,
                                                                        responder_key_distribution=0x01):
        """
        Set the default pairing parameters for the Security Manager associated with a BLEConnection (based on the
        peer address).
        The pairing parameters are used by the devices to determine the type of pairing to use, the temporary key
        sharing method (association model), and which keys will be exchanged when pairing is complete (if any).
        See BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part H
        page 2340 - 2342 for more details.
        
        :param ble_connection: BLEConnection to modify Security Manager pairing parameters of
        :type ble_connection: BLEConnection
        :param io_cap: IO Capabilities (default: 0x03 - No Input, No Output)
        :type io_cap: int
        :param oob: Out-of-band Data present and available (default: 0x00)
        :type oob: int
        :param mitm: Request man-in-the-middle pairing protections (default: 0x01)
        :type mitm: int
        :param bond: Request bonding (default: 0x01)
        :type bond: int
        :param lesc: LE Secure Connections supported (default: 0x00)
        :type lesc: int
        :param keypress: Keypress notifications (default: 0x00)
        :type keypress: int
        :param ct2: CT2 (default: 0x01)
        :type ct2: int
        :param rfu: Reserved for future use bits (default: 0x00)
        :type rfu: int
        :param max_key_size: Max encryption key size (default: 16)
        :type max_key_size: int
        :param initiator_key_distribution: Requested keys to be sent by the initiator (central) (default: 0x01)
        :type initiator_key_distribution: int
        :param responder_key_distribution: Requested keys to be sent by the responder (peripheral) (default: 0x01)
        :type responder_key_distribution: int
        :return: Success status of pairing parameter configuration (False is returned if BLEConnection does not have a valid connection or a security manager set)
        :rtype: bool
        """
        return self.role.smp.set_pairing_parameters_for_connection(ble_connection.address, io_cap, oob, mitm,
                                                                   bond, lesc, keypress, ct2, rfu, max_key_size,
                                                                   initiator_key_distribution,
                                                                   responder_key_distribution)

    def decode_gap_data(self, data):
        """
        Decode GAP data into GAP class object
        
        :param data: GAP binary data
        :type data: str
        :return: GAP object containing the GAP data that has been parsed
        :rtype: blesuite.pybt.gap.GAP
        """
        gap = GAP()
        try:
            gap.decode(data)
        except Exception as e:
            if "Data too short" in str(e):
                logger.debug("Data too short, leaving off malformed data")
            else:
                raise e

        return gap

    def generate_gap_data_dict(self, gap):
        """
        Generates a dictionary of user-friendly strings that describe the GAP data in the supplied GAP object.
        
        :param gap: GAP object to retrieve data from
        :type gap: blesuite.pybt.gap.GAP
        :return: Dictionary of readable strings that represent the GAP data stored in the object
        :rtype: dict
        """
        return gap.gap_dict()

    # Scanning/Discovery Functions

    def scan(self, timeout):
        """
        Carry-out BLE scan for the specified timeout and return discovered devices.
        
        :param timeout: Scan timeout in seconds
        :type timeout: int
        :return: Discovered devices
        :rtype: dict
        """
        import time

        self.start_scan()
        start = time.time() * 1000
        logger.debug("Starting sleep loop")
        # comparing time in ms
        while ((time.time() * 1000) - start) < timeout:
            logger.debug("Scanning...")
            gevent.sleep(1)

        self.stop_scan()
        logger.debug("Done scanning!")
        discovered_devices = self.get_discovered_devices()

        return discovered_devices

    def start_scan(self):
        """
        Enable scanning on HCI device.
        
        :return:
        :rtype:
        """
        self.stack_connection.scan("on")

    def stop_scan(self):
        """
        Stop scanning on HCI device
        
        :return:
        :rtype:
        """
        self.stack_connection.scan("off")

    def advertise_and_wait_for_connection(self):
        """
        Begin advertising with the HCI device and wait for a connection to be established.
        
        :return: Status of connection with a peer device and the BLEConnection
        :rtype: tuple - bool, (BLEConnection | None)
        """
        self.start_advertising()
        while self.is_advertising():
            gevent.sleep(1)
        if len(self.stack_connection.connection_statuses.keys()) > 0:
            connection_handle = self.stack_connection.connection_statuses.keys()[0]
            peer_address = self.stack_connection.peer_addresses_by_connection_handle[connection_handle]
            peer_address_type = self.stack_connection.connected_addr_type_by_connection_handle[connection_handle]
            return True, BLEConnection(peer_address, peer_address_type, connection_handle=connection_handle)
        else:
            logger.error("Advertising stopped and no connections are present. Something went wrong.")
            return False, None

    def start_advertising(self):
        """
        Enable advertising on HCI device.
        
        :return:
        :rtype:
        """
        self.stack_connection.start_advertising()

    def stop_advertising(self):
        """
        Disable advertising on HCI device.
        
        :return:
        :rtype:
        """
        self.stack_connection.stop_advertising()

    def is_advertising(self):
        """
        Retrieve advertising status of HCI device.
        
        :return: Status of advertising
        :rtype: bool
        """
        return self.stack_connection.is_advertising()

    def set_advertising_data(self, data):
        """
        Set advertising data.
        
        :param data: Data to include in advertising packets
        :type data: str
        :return:
        :rtype:
        """
        self.stack_connection.set_advertising_data(data)

    def set_scan_response_data(self, data):
        """
        Set scan response data.
        
        :param data: Data to return when a scan packet is received.
        :type data: str
        :return:
        :rtype:
        """
        self.stack_connection.set_scan_response_data(data)

    def set_advertising_parameters(self, advertisement_type, channel_map, interval_min, interval_max,
                                   destination_addr, destination_addr_type):
        """
        Set advertising parameters. See: BLUETOOTH SPECIFICATION Version 5.0 | Vol 2, Part E page 1251
        
        :param advertisement_type: Advertising packet type (see blesuite.utils.GAP_ADV_TYPES)
        :type advertisement_type:  int
        :param channel_map: Bit field that indicates the advertising channels to use. (Channel 37 - 0x01, Channel 38 - 0x02, Channel 39 - 0x04, all channels - 0x07)
        :type channel_map: int
        :param interval_min: Minimum advertising interval for undirected and low duty cycle directed advertising. (Range 0x00020 - 0x4000, default 0x0800 or 1.28 seconds. Time conversion = interval * 0.625ms)
        :type interval_min: int
        :param interval_max: Maximum advertising interval for undirected and low duty cycle directed advertising. (Range 0x00020 - 0x4000, default 0x0800 or 1.28 seconds. Time conversion = interval * 0.625ms)
        :type interval_max: int
        :param destination_addr: Destination address for directed advertising (set to 00:00:00:00:00:00 if using undirected advertising)
        :type destination_addr: str
        :param destination_addr_type: Destination address type (set to 0x00 if using undirected advertising)
        :type destination_addr_type: int
        :return:
        :rtype:
        """
        self.stack_connection.set_advertising_parameters(advertisement_type, channel_map, interval_min, interval_max,
                                                         destination_addr, destination_addr_type)

    def set_local_name(self, name, enforce_null_termination=True):
        """
        Set the local name of the HCI device. (Bluetooth Spec says the value needs to be null terminated. If it is
        intended to write a string that is not null terminated, then set the enforcement flag to False).
        
        :param name: Local name to write to HCI device
        :type name: str
        :param enforce_null_termination: Flag to enforce null termination (default: True)
        :type enforce_null_termination: bool
        :return:
        :rtype:
        """
        if enforce_null_termination:
            if len(name) != 248:
                padding = 248 - len(name)
                name = name + ('\0' * padding)
        self.stack_connection.set_local_name(name)

    def get_gatt_server(self):
        """
        Retrieve the GATT server for the BLEConnectionManager instance.
        
        :return: GATT Server
        :rtype: blesuite.pybt.gatt.Server
        """
        return self.gatt_server

    def set_server_mtu(self, mtu):
        """
        Configures the MTU (max transmission unit) on the GATT server and ATT class instance. MTU is used
        to restrict the size of data the stack returns in ATT packets. Note: The MTU used by the class
        is determined by the MTUs exchanged by both connected BLE devices (uses the minimum value of the
        exchanged MTUs).
        
        :param mtu: MTU size in bytes (Bluetooth Spec default is 23 bytes)
        :type mtu: int
        :return:
        :rtype:
        """
        self.mtu = mtu
        self.role.att.set_mtu(mtu)

    def get_server_mtu(self):
        """
        Returns the MTU size from the GATT server.
        
        :return: GATT server MTU (bytes)
        :rtype: int
        """
        if self.role.att.gatt_server is not None:
            return self.role.att.gatt_server.mtu

    def initialize_gatt_server_from_ble_device(self, ble_device, use_handles_from_ble_device=False):
        """
        Initializes the GATT server based on a supplied BLEDevice entity. All services, includes, characteristics,
        and descriptors are retrieved from the BLEDevice entity and added to the GATT server using the
        properties and permissions configured in the BLEDevice object.
        
        :param ble_device: BLEDevice object to replicate with the GATT server
        :type ble_device: BLEDevice
        :param use_handles_from_ble_device: Flag to indicate that the GATT server should use the attribute handles specified in each BLE entity withhin the BLEDevice. If set to false (default), then the GATT server will automatically assign handles in the order that entites are added to the server.
        :type use_handles_from_ble_device: bool
        :return:
        :rtype:
        """
        from pybt.gatt import GATTService, GATTCharacteristic, GATTCharacteristicDescriptorDeclaration,\
                              GATTInclude, UUID

        if self.gatt_server is None:
            att_db = AttributeDatabase()
            self.gatt_server = Server(att_db)
            self.gatt_server.set_mtu(self.mtu)

        for service in ble_device.get_services():
            gatt_service = GATTService(UUID(service.attribute_type), UUID(service.uuid))
            gatt_service.start = service.start
            gatt_service.end = service.end
            gatt_service.handle = service.start
            for incl in service.get_includes():
                include_1 = GATTInclude(incl.included_service_att_handle, incl.included_service_end_group_handle,
                                        UUID(incl.included_service_uuid),
                                        incl.include_definition_attribute_properties,
                                        incl.include_definition_attribute_read_permission,
                                        incl.include_definition_attribute_write_permission,
                                        incl.include_definition_attribute_require_authorization)
                include_1.handle = incl.handle
                gatt_service.add_include(include_1)
            for characteristic in service.get_characteristics():
                # create general characteristic (note: this method doesn't apply permissions and properties to the
                # characteristic declaration descriptor)
                characteristic_1 = GATTCharacteristic(characteristic.value, characteristic.gatt_properties,
                                                      UUID(characteristic.uuid),
                                                      characteristic.characteristic_value_attribute_properties,
                                                      characteristic.characteristic_value_attribute_read_permission,
                                                      characteristic.characteristic_value_attribute_write_permission,
                                                      characteristic.characteristic_value_attribute_require_authorization)
                # update characteristic declaration descriptor with configured permissions and authz
                characteristic_1.declaration.attribute_properties = characteristic.characteristic_definition_attribute_properties
                characteristic_1.declaration.attribute_read_permission = characteristic.characteristic_definition_attribute_read_permission
                characteristic_1.declaration.attribute_write_permission = characteristic.characteristic_definition_attribute_write_permission
                characteristic_1.declaration.require_authorization = characteristic.characteristic_definition_attribute_require_authorization

                characteristic_1.declaration.handle = characteristic.handle
                characteristic_1.declaration.value_attribute_handle = characteristic.value_handle
                characteristic_1.value_declaration.handle = characteristic.value_handle
                for descriptor in characteristic.get_descriptors():
                    # characteristic declaration is already created when we created the characteristic attribute
                    if descriptor.type == 0x2803:
                        pass
                    descriptor_1 = GATTCharacteristicDescriptorDeclaration(UUID(descriptor.uuid),
                                                                           descriptor.value,
                                                                           descriptor.characteristic_descriptor_attribute_properties,
                                                                           descriptor.characteristic_descriptor_attribute_read_permission,
                                                                           descriptor.characteristic_descriptor_attribute_write_permission,
                                                                           descriptor.characteristic_descriptor_attribute_require_authorization)
                    descriptor_1.handle = descriptor.handle
                    characteristic_1.add_descriptor(descriptor_1)
                gatt_service.add_characteristic(characteristic_1)
            self.gatt_server.add_service(gatt_service)
        self.gatt_server.refresh_database(calculate_handles=(not use_handles_from_ble_device))

    def set_extended_inquiry_response(self, fec_required=0, formatted_eir_data=None):
        """
        Set the extended inquiry response on the HCI device.
        
        :param fec_required: FEC required (default: 0)
        :type fec_required: 0
        :param formatted_eir_data: Formatted extended inquiry response data (default: None)
        :type formatted_eir_data: str
        :return:
        :rtype:
        """
        self.stack_connection.set_eir_response(fec_required=fec_required, formatted_eir_data=formatted_eir_data)

    def read_remote_used_features(self, connection):
        """
        Issues a read remote used features command to the connected peer device.
        
        :param connection: BLEConnection of target connection
        :type connection: BLEConnection
        :return:
        :rtype:
        """
        self.stack_connection.read_remote_used_features(connection.connection_handle)
        return

    # ATT Packets / GATT Procedures

    def exchange_mtu(self, connection, mtu, timeout=15 * 1000):
        """
        Sends Exchange MTU packet using the supplied BLEConnection object
        and returns a GATTRequest object containing the request or any received errors.
        Synchronous method. Note: Sending this packet as a peripheral will not
        change the MTU configured on the GATT server.

        :param connection: BLEConnection with connection to target device
        :param mtu: Desired MTU (bytes)
        :param timeout: Timeout for exhange MTU response (in milliseconds)
        :type connection: BLEConnection
        :type mtu: int
        :rtype: blesuite.pybt.core.GATTRequest
        """
        request = self.stack_connection.exchange_mtu_sync(mtu, connection.connection_handle, timeout=timeout)
        if request.has_error():
            logger.debug("Exchange MTU Response Error")
        else:
            logger.debug("Exchange MTU Response Data(str): %s" % request.response.data)

        if not request.has_error() and request.has_response():
            connection.mtu = mtu
        return request

    def gatt_discover_primary_services(self, connection, device=None):
        """
        Discover primary GATT services of a peer GATT server and populate (or generate) a BLEDevice object
        with the discovered entities.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        if device is None:
            device = BLEDevice(connection.address)
        return gatt_procedure_discover_primary_services(self, connection, device)

    def gatt_discover_secondary_services(self, connection, device=None):
        """
        Discover secondary GATT services of a peer GATT server and populate (or generate) a BLEDevice object
        with the discovered entities.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        if device is None:
            device = BLEDevice(connection.address)
        return gatt_procedure_discover_secondary_services(self, connection, device)

    def gatt_discover_characteristics(self, connection, device=None):
        """
        Discover GATT characteristics of a peer GATT server and populate (or generate) a BLEDevice object
        with the discovered entities.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        if device is None:
            device = BLEDevice(connection.address)
        return gatt_procedure_discover_characteristics(self, connection, device)

    def gatt_discover_includes(self, connection, device=None):
        """
        Discover GATT service includes of a peer GATT server and populate (or generate) a BLEDevice object
        with the discovered entities.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        if device is None:
            device = BLEDevice(connection.address)
        return gatt_procedure_discover_includes(self, connection, device)

    def gatt_discover_descriptors(self, connection, device):
        """
        Discover GATT characteristic descriptors of a peer GATT server and populate (or generate) a BLEDevice object
        with the discovered entities.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        return gatt_procedure_discover_descriptors(self, connection, device)

    def smart_scan(self, connection, device=None, look_for_device_info=True, attempt_desc_read=False,
                   timeout=15 * 1000):
        """
        Initiate a BLE Smart Scan, which is an all inclusive way to scan a BLE peripheral for all
        services, includes, characteristics, and descriptors. The scan can also attempt to reach from each
        attribute handle discovered during the scan (regardless of GATT properties returned by the server) in
        order to quickly view data exposed by the device.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param device: BLEDevice to populate. If None is supplied (default) a new BLEDevice object with the discovered entities will be added.
        :type device: BLEDevice
        :param look_for_device_info: Flag to indicate the scan should scan for several basic types of information based on UUIDs defined by the Bluetooth Special Interest Group (default: True)
        :type look_for_device_info: bool
        :param attempt_desc_read: Flag to indicate the scan should attempt to read from each attribute discovered during the scan (default: False). Note: This may significantly slow down the scan. If the target peripheral disconnects, the scan will attempt to reconnect to the server.
        :type attempt_desc_read: bool
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: Populated BLEDevice
        :rtype: BLEDevice
        """
        if device is None:
            device = BLEDevice(connection.address)

        return blesuite_smart_scan(self, connection, device, look_for_device_info=look_for_device_info,
                                   attempt_desc_read=attempt_desc_read, timeout=timeout)

    def gatt_write_handle(self, connection, handle, data, timeout=15 * 1000):
        """
        Send an ATT Write request to the peer device associated with the supplied BLEConnection, attribute
        handle, and data. This is a synchronous call that will wait for either a successful response, error response,
        or the specified timeout (milliseconds) to be reached.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param data: Data to place in ATT write request.
        :type data: str
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_write_handle(self.stack_connection, connection.connection_handle, handle,
                                           data, timeout=timeout)

    def gatt_write_handle_async(self, connection, handle, data, timeout=15 * 1000):
        """
        Send an ATT Write request to the peer device associated with the supplied BLEConnection, attribute
        handle, and data. This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param data: Data to place in ATT write request.
        :type data: str
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_write_handle_async(self.stack_connection, connection.connection_handle, handle, data,
                                                 timeout=timeout)

    def gatt_write_command_handle(self, connection, handle, data):
        """
        Send an ATT Write Command request to the peer device associated with the supplied BLEConnection, attribute
        handle, and data. This is an asynchronous call that will send the request to the peer device. No GATTRequest
        will be generated since this command should not ever receive a response from the peer.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param data: Data to place in ATT write request.
        :type data: str
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        """
        gatt_procedure_write_command_handle(self.stack_connection, connection.connection_handle, handle, data)

    def gatt_prepare_write_handle(self, connection, handle, data, offset, timeout=15 * 1000):
        """
        Send an ATT Prepare Write request to the peer device associated with the supplied BLEConnection, attribute
        handle, offset, and data. This is a synchronous call that will wait for either a successful response,
        error response,
        or the specified timeout (milliseconds) to be reached.
        Note: Prepare write is used in conjunction with execute write to write a large set of data.
        The user will send a series of prepare
        write requests with data and the correct offsets to set a large value for a write operation. An execute
        write request will then be issued to carry out the write. (Permission / Auth checks should happen on the
        prepare write request).
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param data: Data to place in ATT write request.
        :type data: str
        :param offset: Offset to write the data
        :type offset: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_prepare_write_handle(self.stack_connection, connection.connection_handle, handle,
                                                   data, offset, timeout=timeout)

    def gatt_prepare_write_handle_async(self, connection, handle, data, offset, timeout=15 * 1000):
        """
        Send an ATT Prepare Write request to the peer device associated with the supplied BLEConnection, attribute
        handle, offset, and data. This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).
        Note: Prepare write is used in conjunction with execute write to write a large set of data.
        The user will send a series of prepare
        write requests with data and the correct offsets to set a large value for a write operation. An execute
        write request will then be issued to carry out the write. (Permission / Auth checks should happen on the
        prepare write request).
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param data: Data to place in ATT write request.
        :type data: str
        :param offset: Offset to write the data
        :type offset: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_prepare_write_handle_async(self.stack_connection, connection.connection_handle,
                                                         handle, data, offset, timeout=timeout)

    def gatt_execute_write(self, connection, flags, timeout=15 * 1000):
        """
        Send an ATT Execute Write request to the peer device associated with the supplied BLEConnection and flag.
        This is a synchronous call that will wait for either a successful response, error response,
        or the specified timeout (milliseconds) to be reached.
        Note: Execute write is used in conjunction with prepare write
        to write a large set of data. The user will send a series of prepare
        write requests with data and the correct offsets to set a large value for a write operation. An execute
        write request will then be issued to carry out the write. (Permission / Auth checks should happen on the
        prepare write request).
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param flags: Specifies which execute write operation should be performed (0x00 - Cancel all prepared writes, 0x01 - Immediately write all pending prepared values.
        :type flags: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_execute_write(self.stack_connection, connection.connection_handle, flags, timeout=timeout)

    def gatt_execute_write_async(self, connection, flags, timeout=15 * 1000):
        """
        Send an ATT Execute Write request to the peer device associated with the supplied BLEConnection and flag.
        This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).
        Note: Execute write is used in conjunction with prepare write
        to write a large set of data. The user will send a series of prepare
        write requests with data and the correct offsets to set a large value for a write operation. An execute
        write request will then be issued to carry out the write. (Permission / Auth checks should happen on the
        prepare write request).
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param flags: Specifies which execute write operation should be performed (0x00 - Cancel all prepared writes, 0x01 - Immediately write all pending prepared values.
        :type flags: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_execute_write_async(self.stack_connection, connection.connection_handle, flags,
                                                  timeout=timeout)

    def gatt_read_handle(self, connection, handle, timeout=15 * 1000):
        """
        Send an ATT Read request to the peer device associated with the supplied BLEConnection and attribute
        handle. This is a synchronous call that will wait for either a successful response, error response,
        or the specified timeout (milliseconds) to be reached.
        
        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_handle(self.stack_connection, connection.connection_handle, handle, timeout=timeout)

    def gatt_read_handle_async(self, connection, handle, timeout=15 * 1000):
        """
        Send an ATT Read request to the peer device associated with the supplied BLEConnection and attribute
        handle. This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_handle_async(self.stack_connection, connection.connection_handle, handle,
                                                timeout=timeout)

    def gatt_read_multiple_handles(self, connection, handles, timeout=15 * 1000):
        """
        Send an ATT Read Multiple request to the peer device associated with the supplied BLEConnection and
        a set of attribute handles.
        This is a synchronous call that will wait for either a successful response, error response,
        or the specified timeout (milliseconds) to be reached.

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handles: A list of attribute handles for target attributes (0x01 - 0xFFFF)
        :type handles: list of int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_multiple_handles(self.stack_connection, connection.connection_handle,
                                                    handles, timeout=timeout)

    def gatt_read_multiple_handles_async(self, connection, handles, timeout=15 * 1000):
        """
        Send an ATT Read Multiple request to the peer device associated with the supplied BLEConnection and
        a set of attribute handles.
        This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitorged for a GATTResponse or GATTError (either through a valid
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handles: A list of attribute handles for target attributes (0x01 - 0xFFFF)
        :type handles: list of int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_multiple_handles_async(self.stack_connection, connection.connection_handle, handles,
                                                          timeout=timeout)

    def gatt_read_blob_handle(self, connection, handle, offset, timeout=15 * 1000):
        """
        Send an ATT Blob Read request to the peer device associated with the supplied BLEConnection, attribute
        handle, and an offset. This is a synchronous call that will wait for either a successful response,
        error response,
        or the specified timeout (milliseconds) to be reached.

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param offset: Offset to begin reading attribute value
        :type offset: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_blob_handle(self.stack_connection, connection.connection_handle, handle, offset,
                                               timeout=timeout)

    def gatt_read_blob_handle_async(self, connection, handle, offset, timeout=15 * 1000):
        """
        Send an ATT Blob Read request to the peer device associated with the supplied BLEConnection, attribute
        handle, and an offset. This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param handle: Attribute handle of target attribute (0x01 - 0xFFFF)
        :type handle: int
        :param offset: Offset to begin reading attribute value
        :type offset: int
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_blob_handle_async(self.stack_connection, connection.connection_handle, handle,
                                                     offset, timeout=timeout)

    def gatt_read_uuid(self, connection, uuid, timeout=15 * 1000):
        """
        Send an ATT Read request to the peer device associated with the supplied BLEConnection and GATT UUID.
        This is a synchronous call that will wait for either a successful response, error response,
        or the specified timeout (milliseconds) to be reached.

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param uuid: UUID of target GATT entity (16-bit and 128-bit UUIDs are accepted)
        :type uuid: str
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_uuid(self.stack_connection, connection.connection_handle, UUID(uuid),
                                        timeout=timeout)

    def gatt_read_uuid_async(self, connection, uuid, timeout=15 * 1000):
        """
        Send an ATT Read request to the peer device associated with the supplied BLEConnection and GATT UUID.
        This is an asynchronous call that will send the request to the peer device and
        return a GATTRequest object that can be monitored for a GATTResponse or GATTError (either through a valid
        peer response, peer error response, or timeout error triggering).

        :param connection: BLEConnection with the connected GATT server
        :type connection: BLEConnection
        :param uuid: UUID of target GATT entity (16-bit and 128-bit UUIDs are accepted)
        :type uuid: str
        :param timeout: Request timeout (milliseconds)
        :type timeout: int
        :return: GATTRequest that contains the GATTResponse or GATTError result
        :rtype: blesuite.pybt.core.GATTRequest
        """
        return gatt_procedure_read_uuid_async(self.stack_connection, connection.connection_handle, UUID(uuid),
                                              timeout=timeout)

    def att_send_raw(self, connection, body):
        """
        Sends a raw ATT packet using the supplied BLEConnection object
        and data supplied. The function does not apply a standard ATT header the supplied body, but L2CAP
        and HCI encapsulation is handled.
        Note: Valid ATT packets can be constructed using
        packets defined in scapy.layers.bluetooth
        or using random data for fuzzing.
        
        :param connection: BLEConnection to target device
        :param body: ATT request body
        :rtype: GATTRequest
        """
        request = self.stack_connection.send_raw_att(body, connection.connection_handle)
        
        return request

    def l2cap_send_raw(self, connection, body):
        """
        Sends a raw L2CAP packet using the supplied BLEConnection object
        and data supplied. The function does not apply a standard L2CAP header to the user supplied value,
        but HCI encapsulation is applied.
        Note: Valid L2CAP packets can be constructed using packets defined in scapy.layers.bluetooth
        or using random data for fuzzing.

        :param connection: BLEConnection to target device
        :param body: L2CAP request body
        :rtype: GATTRequest
        """
        request = self.stack_connection.send_raw_l2cap(body, connection.connection_handle)
        
        return request



