from fcntl import ioctl
import logging
import socket as s
from scapy.layers.bluetooth import *
import ctypes
import struct
import os
import sys

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

PUBLIC_DEVICE_ADDRESS = 0x00
RANDOM_DEVICE_ADDRESS = 0x01


class hci_dev_stat(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('err_rx', ctypes.c_uint32),
        ('err_tx', ctypes.c_uint32),
        ('cmd_tx', ctypes.c_uint32),
        ('evt_rx', ctypes.c_uint32),
        ('acl_tx', ctypes.c_uint32),
        ('acl_rx', ctypes.c_uint32),
        ('sco_tx', ctypes.c_uint32),
        ('sco_rx', ctypes.c_uint32),
        ('byte_rx', ctypes.c_uint32),
        ('byte_tx', ctypes.c_uint32),
    ]


class hci_dev_info(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('dev_id', ctypes.c_uint16),
        ('name', ctypes.c_char * 8),
        ('bdaddr', ctypes.c_ubyte * 6),
        ('flags', ctypes.c_uint32),
        ('type', ctypes.c_ubyte),
        ('features', ctypes.c_ubyte * 8),
        ('pkt_type', ctypes.c_uint32),
        ('link_policy', ctypes.c_uint32),
        ('link_mode', ctypes.c_uint32),
        ('acl_mtu', ctypes.c_uint16),
        ('acl_pkts', ctypes.c_uint16),
        ('sco_mtu', ctypes.c_uint16),
        ('sco_pkts', ctypes.c_uint16),
        ('stat', hci_dev_stat),
    ]


class HCIConfig(object):
    PF_BLUETOOTH = 31

    BTPROTO_HCI = 1

    # IOCTL
    HCIDEVUP = 0x400448c9
    HCIDEVDOWN = 0x400448ca
    HCIDEVRESET = 0x400448cb
    HCIGETDEVINFO = 0x800448d3

    @staticmethod
    def down(iface):
        sock = s.socket(
            HCIConfig.PF_BLUETOOTH,
            s.SOCK_RAW,
            HCIConfig.BTPROTO_HCI)
        ioctl(sock.fileno(), HCIConfig.HCIDEVDOWN, iface)
        sock.close()
        return True

    @staticmethod
    def up(iface):
        sock = s.socket(
            HCIConfig.PF_BLUETOOTH,
            s.SOCK_RAW,
            HCIConfig.BTPROTO_HCI)
        ioctl(sock.fileno(), HCIConfig.HCIDEVUP, iface)
        sock.close()
        return False

    @staticmethod
    def reset(iface):
        sock = s.socket(
            HCIConfig.PF_BLUETOOTH,
            s.SOCK_RAW,
            HCIConfig.BTPROTO_HCI)
        ioctl(sock.fileno(), HCIConfig.HCIDEVRESET, iface)
        ioctl(sock.fileno(), HCIConfig.HCIDEVDOWN, iface)
        ioctl(sock.fileno(), HCIConfig.HCIDEVUP, iface)
        sock.close()
        return True

    @staticmethod
    def get_devinfo(iface):
        di = hci_dev_info(dev_id=iface)
        sock = s.socket(
            HCIConfig.PF_BLUETOOTH,
            s.SOCK_RAW,
            HCIConfig.BTPROTO_HCI)
        try:
            rv = ioctl(sock.fileno(), HCIConfig.HCIGETDEVINFO, di, True)
        except IOError:
            rv = None
        finally:
            sock.close()
        if rv:
            return None
        return di

    @staticmethod
    def get_bdaddr(iface):
        di = HCIConfig.get_devinfo(iface)
        if not di:
            return None
        return ':'.join(["%02X" % b for b in di.bdaddr[::-1]])


class BTStack:

    def __init__(self, adapter=0):
        # self.interval_min = None
        # self.interval_max = None
        self.s = None
        self.addr = None
        self.rand_addr = None
        self.address_type = PUBLIC_DEVICE_ADDRESS

        self.s = self.get_socket(adapter)
        log.debug("Trying to set reuseaddr")
        # self.s.ins.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        if self.s.ins != self.s.outs:
            if self.s.outs and self.s.outs.fileno() != -1:
                log.debug("Setting outs reuse")
                self.s.outs.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)
        if self.s.ins and self.s.ins.fileno() != -1:
            log.debug("Settings ins reuse")
            self.s.ins.setsockopt(s.SOL_SOCKET, s.SO_REUSEADDR, 1)

        # set up device
        # get BD ADDR
        r = self.command(HCI_Cmd_Read_BD_Addr())
        self.addr = str(r[HCI_Cmd_Complete_Read_BD_Addr])[::-1]

        self.command(HCI_Cmd_Set_Event_Filter())
        self.command(HCI_Cmd_Connect_Accept_Timeout())
        self.command(HCI_Cmd_Set_Event_Mask())
        self.command(HCI_Cmd_LE_Host_Supported())

        self.command(HCI_Cmd_LE_Read_Buffer_Size())

    def get_socket(self, adapter):
        try:
            return BluetoothUserSocket(adapter)
        except BluetoothSocketError as e:

            log.debug("[!] Creating socket failed: %s\n" % (repr(e)))
            if os.getuid() > 0:
                log.error("[!] Are you definitely root? detected uid: %d\n" % (os.getuid()))
                log.debug("[+] attempting to take iface down anyways as non-root user\n")
                HCIConfig.down(adapter)
                try:
                    return BluetoothUserSocket(adapter)
                except BluetoothSocketError as e:
                    log.error("[!] Failed to create socket: %s" % repr(e))
                    log.error("[!] Giving up.\n")
            else:
                log.debug("[+] have root, attempting to take iface down\n")
                HCIConfig.down(adapter)
                try:
                    return BluetoothUserSocket(adapter)
                except BluetoothSocketError as e:
                    log.error("[!] Failed to create socket: %s" % repr(e))
                    log.error("[!] Giving up.\n")
        sys.exit(1)

    def destroy(self):
        log.debug("Destroying PyBT, closing HCI device")
        if self.s is not None:
            log.debug("Stop advertising")
            try:
                self.set_advertising_enable(0)
            except BluetoothCommandError as e:
                log.debug("Stop advertising command failed. Maybe we weren't advertising")
            log.debug("Stop Scanning")
            try:
                self.scan_stop()
            except BluetoothCommandError as e:
                log.debug("Stop scanning command failed. Maybe we weren't scanning")
            log.debug("Flushing socket")
            self.s.flush()
            self.s.close()
        self.s = None

    # hack to make this select-able
    def fileno(self):
        return self.s.ins.fileno()

    def write_local_name(self, name):
        self.command(HCI_Cmd_Write_Local_Name(name=name))

    def write_extended_inquiry_response_command(self, fec_required=0, formatted_eir_data=None):
        if formatted_eir_data is None:
            self.command(HCI_Cmd_Write_Extended_Inquiry_Response(fec_required=fec_required))
        else:
            self.command(HCI_Cmd_Write_Extended_Inquiry_Response(fec_required=fec_required,
                                                                 eir_data=formatted_eir_data))

    def read_remote_used_features(self, conn_handle):
        # self.command(HCI_Cmd_LE_Set_Random_Address(conn_handle=conHandle))
        self.s.send(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Set_Random_Address(conn_handle=conn_handle))
        # can't use send_command() on this guy because we don't get a command status (0x0e) and do get
        # command complete (0x0f)
        while True:
            p = self.s.recv()
            if p.code == 0x0f:
                if p.status == 0:
                    break
                else:
                    raise Exception("Problem getting read remote used feature response")

    def set_random_address(self, random_addr):
        self.rand_addr = random_addr
        self.address_type = RANDOM_DEVICE_ADDRESS
        self.command(HCI_Cmd_LE_Set_Random_Address(address=random_addr))

    def set_advertising_data(self, data):
        self.command(HCI_Cmd_LE_Set_Advertising_Data(data=data))

    def set_scan_response_data(self, data):
        self.command(HCI_Cmd_LE_Set_Scan_Response_Data(data=data))

    def set_advertising_params(self, adv_type=0, channel_map=0, interval_min=0x0800, interval_max=0x0800,
                               destination_addr='00:00:00:00:00:00', destination_addr_type=0):
        command = HCI_Cmd_LE_Set_Advertising_Parameters(adv_type=adv_type, channel_map=channel_map,
                                                        interval_min=interval_min, interval_max=interval_max,
                                                        daddr=destination_addr, datype=destination_addr_type,
                                                        oatype=self.address_type)
        self.command(command)

    def set_advertising_enable(self, enable):
        self.command(HCI_Cmd_LE_Set_Advertise_Enable(enable=enable))

    def update_connection_params(self, handle, interval_min, interval_max, latency, timeout, min_ce, max_ce):
        # can't use send_command because send_command requires a response with command
        # complete (0xe) to signify success,
        # whereas this command results in a command status (0xf)
        self.s.send(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Connection_Update(handle=handle,
                                                                                 min_interval=interval_min,
                                                                                 max_interval=interval_max,
                                                                                 latency=latency,
                                                                                 timeout=timeout,
                                                                                 min_ce=min_ce,
                                                                                 max_ce=max_ce))
        while True:
            p = self.s.recv()
            if p.type == 0x04 and p.code == 0x0f and p.opcode == 0x2013:
                if p.status == 0:
                    break
                else:
                    log.error("Error updating connection parameters. Status: %s" % p.status)
                    raise Exception("Problem updating connection parameters")

    def set_encryption(self, handle, rand, ediv, ltk):
        # can't use send_command because send_command requires a response with command complete
        # (0xe) to signify success,
        # whereas this command results in a command status (0xf)
        log.debug("About to set encryption")
        log.debug("Handle: %s rand: %s ediv: %s ltk: %s" % (handle, rand, ediv, ltk))
        self.s.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_LE_Start_Encryption_Request(handle=handle, rand=rand,
                                                                                    ediv=ediv, ltk=ltk))
        log.debug("Set encryption packet sent")

    def send_ltk_reply(self, ltk, handle):
        self.command(HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=handle, ltk=ltk))

    def send_ltk_nak(self, handle):
        self.command(HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(handle=handle))

    def handle_data(self):
        p = self.s.recv()

        if p.type == 0x2:  # HCI ACL Data (BLUETOOTH SPECIFICATION Version 5.0 | Vol 4, Part D page 2447)
            try:
                if p.cid == 0x4:  # ATT CID (BLUETOOTH SPECIFICATION Version 5.0 | Vol 3, Part A page 1728)
                    return BTEvent(BTEvent.ATT_DATA, (p[HCI_ACL_Hdr].handle, p[ATT_Hdr]))
                elif p.cid == 0x05:
                    return BTEvent(BTEvent.L2CAP_DATA, (p[HCI_ACL_Hdr].handle, p[L2CAP_Hdr]))
                elif p.cid == 0x6:
                    return BTEvent(BTEvent.SM_DATA, (p[HCI_ACL_Hdr].handle, p[SM_Hdr]))
            except Exception as e:
                log.warn("unknown ACL data: %s" % e)
                pass
        elif p.type == 0x4:  # HCI Event
            if p.code == 0x3e:  # LE Meta Event
                if p.event == 1:
                    # glorious scapy hack # removed [5:11] and str conversion
                    meta = p[HCI_LE_Meta_Connection_Complete]
                    return BTEvent(BTEvent.CONNECTED, (p.status, p.handle, meta, p.paddr, p.patype))
                if p.event == 2:
                    return BTEvent(BTEvent.SCAN_DATA, (p.reports[0].addr, p.reports[0].atype, p.reports[0].data))
                # LE Read Remote Used Features Complete
                if p.event == 4:
                    meta = p[HCI_LE_Meta_Connection_Complete]
                    return BTEvent(BTEvent.META_DATA, (p.status, p.handle, meta, p.addr, p.event))
                if p.event == 5:
                    meta = p[HCI_LE_Meta_Long_Term_Key_Request]
                    return BTEvent(BTEvent.LTK_REQUEST, (p.handle, meta, p.event))
            elif p.code == 0x5:
                return BTEvent(BTEvent.DISCONNECTED, (p.handle, p.reason))
            elif p.code == 0x8:
                return BTEvent(BTEvent.ENCRYPTION_CHANGE, (p.status, p.handle, p[HCI_Event_Encryption_Change]))

        else:
            log.warn("Don't know how to handle %s" % p)
        return BTEvent(BTEvent.NONE, p)

    def scan(self):
        # start scanning
        self.command(HCI_Cmd_LE_Set_Scan_Parameters())
        self.command(HCI_Cmd_LE_Set_Scan_Enable())

    def scan_stop(self):
        self.command(HCI_Cmd_LE_Set_Scan_Enable(enable=0))

    def connect(self, addr, addr_type, interval_min=None, interval_max=None):
        if interval_min is not None and interval_max is not None:
            self.s.send(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Create_Connection(paddr=addr, patype=addr_type,
                                                                                     min_interval=interval_min,
                                                                                     max_interval=interval_max,
                                                                                     atype=self.address_type))
        else:
            self.s.send(HCI_Hdr() / HCI_Command_Hdr() / HCI_Cmd_LE_Create_Connection(paddr=addr, patype=addr_type,
                                                                                     atype=self.address_type))
        # can't use send_command() on this guy because we don't get a command status (0x0e) and do get
        # command complete (0x0f)
        while True:
            p = self.s.recv()
            if p.code == 0x0f:
                if p.status == 0:
                    break
                else:
                    raise Exception("Problem establishing connection. Code: %s Status %s:" % (p.code, p.status))

    def connect_sync(self, addr, addr_type):
        self.connect(addr, addr_type)
        while True:
            p = self.s.recv()
            if p.code == 0x3e and p.event == 0x01:
                if p.status == 0:
                    break
                else:
                    raise Exception("Problem establishing connection. Code: %s Status: %s:" % (p.code, p.status))

    def disconnect(self, handle, reason=0x16):
        self.s.send(HCI_Hdr()/HCI_Command_Hdr()/HCI_Cmd_Disconnect(handle=handle, reason=reason))
        # wait for disconnect to be acknowledged (status and complete)
        while True:
            p = self.s.recv()
            if p.code == 0x0f:
                if p.status == 0:
                    continue
                else:
                    raise Exception("Problem establishing connection. Code: %s Status %s:" % (p.code, p.status))
            elif p.code == 0x05:
                if p.status == 0:
                    break
                else:
                    raise Exception("Problem establishing connection. Code: %s Status %s:" % (p.code, p.status))

    def command(self, cmd):
        try:
            return self.s.send_command(HCI_Hdr()/HCI_Command_Hdr()/cmd)
        except BluetoothCommandError as e:
            log.error("[!] Controller error for command: %s Error: %s\n" % (cmd.name, e))

    def raw_att(self, data, conn_handle, length=None):
        self.s.send(HCI_Hdr() / HCI_ACL_Hdr(handle=conn_handle) / L2CAP_Hdr(len=length, cid=4) / data)

    def raw_smp(self, data, conn_handle, length=None):
        self.s.send(HCI_Hdr() / HCI_ACL_Hdr(handle=conn_handle) / L2CAP_Hdr(len=length, cid=6) / data)

    def raw_l2cap(self, data, conn_handle=64):
        self.s.send(HCI_Hdr() / HCI_ACL_Hdr(handle=conn_handle) / data)


class BTEvent:
    NONE = 0
    SCAN_DATA = 1
    CONNECTED = 2
    DISCONNECTED = 3
    ATT_DATA = 4
    SM_DATA = 5
    L2CAP_DATA = 6
    META_DATA = 7
    LTK_REQUEST = 8
    ENCRYPTION_CHANGE = 9

    _type_string = {
        NONE: "NONE",
        SCAN_DATA: "SCAN_DATA",
        CONNECTED: "CONNECTED",
        DISCONNECTED: "DISCONNECTED",
        ATT_DATA: "ATT_DATA",
        SM_DATA: "SM_DATA",
        L2CAP_DATA: "L2CAP_DATA",
        META_DATA: "META_DATA",
        LTK_REQUEST: "LTK_REQUEST",
        ENCRYPTION_CHANGE: "ENCRYPTION_CHANGE"
    }

    data = None
    event_type = None

    def __init__(self, event_type, data=None):
        self.event_type = event_type
        self.data = data

    def __repr__(self):
        return "BTEvent(%s, %s)" % (self._type_string[self.event_type], repr(self.data))
