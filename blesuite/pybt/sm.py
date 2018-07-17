from Crypto.Cipher import AES
from scapy.layers.bluetooth import *
from scapy.all import hexdump
import logging
import os
import gevent
import struct

log = logging.getLogger(__name__)

IO_CAPABILITY_DISPLAY_ONLY = 0x00
IO_CAPABILITY_DISPLAY_YES_NO = 0x01
IO_CAPABILITY_KEYBOARD_ONLY = 0x02
IO_CAPABILITY_NO_INPUT_NO_OUTPUT = 0x03
IO_CAPABILITY_KEYBOARD_DISPLAY = 0x04

SMP_PAIRING_REQUEST = 0x01
SMP_PAIRING_RESPONSE = 0x02
SMP_PAIRING_CONFIRM = 0x03
SMP_PAIRING_RANDOM = 0x04
SMP_PAIRING_FAILED = 0x05
SMP_ENCRYPTION_INFORMATION = 0x06
SMP_MASTER_IDENTIFICATION = 0x07
SMP_IDENTITY_INFORMATION = 0x08
SMP_IDENTITY_ADDRESS_INFORMATION = 0x09
SMP_SIGNING_INFORMATION = 0x0a
SMP_SECURITY_REQUEST = 0x0b
SMP_PAIRING_PUBLIC_KEY = 0x0c
SMP_PAIRING_DHKEY_CHECK = 0x0d
SMP_PAIRING_KEYPRESS_NOTIFICATION = 0x0e

SMP_KEY_DISTRIBUTION_TYPE_LTK = 0x01
SMP_KEY_DISTRIBUTION_TYPE_IRK = 0x02
SMP_KEY_DISTRIBUTION_TYPE_CSRK = 0x04
SMP_KEY_DISTRIBUTION_TYPE_EDIV = 0x08
SMP_KEY_DISTRIBUTION_TYPE_RAND = 0x10
SMP_KEY_DISTRIBUTION_TYPE_ADDRESS = 0x20

PUBLIC_DEVICE_ADDRESS = 0x00
RANDOM_DEVICE_ADDRESS = 0x01

ROLE_TYPE_CENTRAL = 0x00
ROLE_TYPE_PERIPHERAL = 0x01


class SecurityMode:
    def __init__(self, security_mode=0, security_level=0):
        self.security_mode = security_mode
        self.security_level = security_level


class LongTermKeyDatabase:
    # FIXME: Look-ups are currently based on ediv and rand. With LE SC, we'll need to find a different way
    # to do the lookup.
    def __init__(self):
        self.long_term_keys = []

    def add_long_term_key_entry(self, received_address, received_address_type,
                                ltk, ediv, rand, irk, csrk, security_mode, security_level):
        self.long_term_keys.append({"address": received_address, "address_type": received_address_type,
                                        "ltk": ltk, "ediv": ediv, "rand": rand, "irk": irk, "csrk": csrk,
                                       "security_mode": security_mode, "security_level": security_level})

    def is_ltk_in_db(self, address, ediv, rand):
        log.debug("LTK Lookup: Address: %s, ediv: %s, rand:%s" % (address, ediv, rand))
        print self.long_term_keys
        # HACK: When we support full SM and SMP, we will be able to handle private addresses that change,
        # but for now we can do a look-up based on the ediv and rand for LE Legacy pairing
        for entry in self.long_term_keys:
            if entry["ediv"] == ediv and entry["rand"] == rand:
                return True
            if entry["address"] == address.replace(":", "").decode('hex'):
                return True
        return False

    def get_ltk_from_ediv_and_rand(self, ediv, rand):
        for entry in self.long_term_keys:
            if entry["ediv"] == ediv and entry["rand"] == rand:
                return entry["ltk"]
        return None

    def get_entry_for_address(self, address):
        for entry in self.long_term_keys:
            if entry[address] == address.replace(":",""):
                return entry
        return None

    def get_ltk_security_properties_from_ediv_and_rand(self, ediv, rand):
        for entry in self.long_term_keys:
            if entry["ediv"] == ediv and entry["rand"] == rand:
                return entry["security_mode"], entry["security_level"]
        return None, None

    def get_long_term_key_database(self):
        return self.long_term_keys


class SM:

    def __init__(self, io_cap=0x03, oob=0x0, mitm=0x00, bond=0x01, lesc=0x0, keypress=0x0, ct2=0x01, rfu=0x0,
                 max_key_size=16,
                 initiator_key_distribution=0x01, responder_key_distribution=0x01):

        self.tk = '\x00' * 16
        self.rrnd = '\x00' * 16

        # CONFIGURABLE GAP PROPERTIES
        self.io_cap = io_cap
        self.oob = oob
        self.mitm = mitm
        self.bond = bond
        self.lesc = lesc
        self.keypress = keypress
        self.ct2 = ct2
        self.rfu = rfu
        self.max_key_size = max_key_size

        # calculating auth_req pairing request/response field
        bond_temp = format(self.bond, '02b')
        mitm_temp = format(self.mitm, '01b')
        sc_temp = format(self.lesc, '01b')
        keypress_temp = format(self.keypress, '01b')
        ct2_temp = format(self.ct2, '01b')
        rfu_temp= format(self.rfu, '02b')

        self.auth_request = int((rfu_temp + ct2_temp + keypress_temp + sc_temp + mitm_temp + bond_temp), 2)

        # Internal information and statuses
        self.our_role = None
        self.pairing_failed = False
        self.pairing_initiated = False

        self.ltk_received = False
        self.rand_received = False
        self.ediv_received = False
        self.irk_received = False
        self.addr_received = False
        self.csrk_received = False

        self.peer_auth_request = None
        self.peer_io_cap = None
        self.peer_oob = None
        self.peer_mitm = None
        self.peer_bond = None
        self.peer_lesc = None
        self.peer_keypress = None
        self.peer_ct2 = None
        self.peer_rfu = None
        # crypto params
        self.ia = None
        self.ia_type = None
        self.ra = None
        self.ra_type = None
        self.tk = None
        self.prnd = None
        self.rrnd = None
        self.pcnf = None
        self.preq = None
        self.prsp = None
        self.ltk = None
        self.stk = None
        self.ediv = None
        self.rand = None
        self.initiator_key_distribution = initiator_key_distribution
        self.responder_key_distribution = responder_key_distribution

        # Values that can be sent by slave after encryption enabled
        self.rCSRK = None
        self.rLtk = None
        self.rEDIV = None
        self.rRand = None
        self.rIRK = None
        self.rAddr = None
        self.rAType = None

        self.distribution_keys_sent = False
        self.distribution_keys_received = False

        # By default our connection has no security, Security Mode 1 Level 1
        self.connection_security_mode = SecurityMode(1, 1)

    def set_iocapability_property(self, io_cap):
        self.io_cap = io_cap

    def get_iocapability_property(self):
        return self.io_cap

    def set_oob_property(self, oob):
        self.oob = oob

    def get_oob_property(self):
        return self.oob

    def set_mitm_property(self, mitm):
        self.mitm = mitm

    def get_mitm_property(self):
        return self.mitm

    def set_bond_property(self, bond):
        self.bond = bond

    def get_bond_property(self):
        return self.bond

    def set_lesc_property(self, lesc):
        self.lesc = lesc

    def get_lesc_property(self):
        return self.lesc

    def set_keypress_property(self, keypress):
        self.keypress = keypress

    def get_keypress_property(self):
        return self.keypress

    def set_ct2_property(self, ct2):
        self.ct2 = ct2

    def get_ct2_property(self):
        return self.ct2

    def set_rfu_property(self, rfu):
        self.rfu = rfu

    def get_rfu_property(self):
        return self.rfu

    def set_security_mode_level(self, level):
        self.connection_security_mode.level = level

    def get_security_mode_level(self):
        return self.connection_security_mode.level

    def set_security_mode_mode(self, mode):
        self.connection_security_mode.mode = mode

    def get_security_mode_mode(self):
        return self.connection_security_mode.mode

    def set_initiator_address(self, address):
        self.ia = address

    def get_initiator_address(self):
        return self.ia

    def set_initiator_address_type(self, address_type):
        self.ia_type = address_type

    def get_initiator_address_type(self):
        return self.ia_type

    def set_receiver_address(self, address):
        self.ra = address

    def get_receiver_address(self):
        return self.ra

    def set_receiver_address_type(self, address):
        self.ra_type = address

    def get_receiver_address_type(self):
        return self.ra_type

    def calculate_stk(self):

        #s1(tk, srand, mrand)
        #r1 = r1[8:]
        #r2 = r2[8:]
        r1 = self.rrnd[8:]
        r2 = self.prnd[8:]
        log.debug("Calculating stk srand: %s mrand: %s tk: %s" % (
            r1, r2, self.tk
        ))
        log.debug("Calculating stk srand: %s mrand: %s tk: %s" % (
            r1.encode('hex'), r2.encode('hex'), self.tk.encode('hex')
        ))
        #r = r1 || r2
        r = ''.join((r1, r2))
        return bt_crypto_e(self.tk, r)

    # calculates a confirm
    def calculate_confirm(self, master=0):
        if master:
            rand = self.prnd
        else:
            rand = self.rrnd

        log.debug("Calculating confirm. Parameters: %s" % self)

        return ''.join(bt_crypto_c1(self.tk, rand, self.prsp, self.preq, self.ia_type, self.ia, self.ra_type, self.ra))

    def verify_random(self, verify_peripherals_random=False):
        log.debug("Verifying received confirm value based peer's random value")
        if not verify_peripherals_random:
            confirm = self.calculate_confirm(1)
        else:
            confirm = self.calculate_confirm(0)
        log.debug("Calculated confirm: %s (Hex Version): %s" % (confirm, confirm.encode('hex')))
        if self.pcnf != confirm:
            return False
        self.ltk = bt_crypto_s1(self.tk, self.prnd, self.rrnd)
        return True

    def __repr__(self):
        val = ""
        val += self._dump('ia')
        val += "\ns.ia_type = " + str(self.ia_type)
        val += "\n" + self._dump('ra')
        val += "\ns.ra_type = " + str(self.ra_type)
        val += "\n" + self._dump('prnd')
        val += "\n" + self._dump('rrnd')
        val += "\n" + self._dump('pcnf')
        val += "\n" + self._dump('prsp')
        val += "\n" + self._dump('preq')
        return val

    def _dump(self, label):
        try:
            if self.__dict__[label] is None:
                return "s.%s = None" % label
            return "s.%s = '%s'" % (label, ''.join("\\x{:02x}".format(ord(c)) for c in self.__dict__[label]))
        except KeyError:
            return "s.%s = KeyError" % label


def u128_xor(a1, a2):
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(a1, a2))


def bt_crypto_e(key, plaintext):
    aes = AES.new(key)
    return aes.encrypt(plaintext)


def bt_crypto_c1(k, r, pres, preq, iat, ia, rat, ra):
    p1 = ''.join((pres, preq, chr(rat), chr(iat)))
    p2 = ''.join(("\x00\x00\x00\x00", ia, ra))
    res = u128_xor(r, p1)
    res = bt_crypto_e(k, res)
    res = u128_xor(res, p2)
    return bt_crypto_e(k, res)


def bt_crypto_s1(k, r1, r2):
    res = ''.join((r2[8:16], r1[8:16]))
    return bt_crypto_e(k, res)


class SecurityManagerProtocol:

    def __init__(self, stack, long_term_key_db=None, default_io_cap=0x03, default_oob=0x0,
                 default_mitm=0x00, default_bond=0x01,
                 default_lesc=0x00, default_keypress=0x00, default_ct2=0x01, default_rfu=0x00,
                 default_max_key_size=16,
                 default_initiator_key_distribution=0x01, default_responder_key_distribution=0x01):
        self.stack = stack
        self.security_managers = {}  # hold security manager for each connection handle
        self.encrypted_connections = {}
        self.default_io_cap = default_io_cap
        self.default_oob = default_oob
        self.default_mitm = default_mitm
        self.default_bond = default_bond
        self.default_lesc = default_lesc
        self.default_keypress = default_keypress
        self.default_ct2 = default_ct2
        self.default_rfu = default_rfu
        self.default_max_key_size = default_max_key_size
        self.default_initiator_key_distribution = default_initiator_key_distribution
        self.default_responder_key_distribution = default_responder_key_distribution
        if long_term_key_db is None:
            self.long_term_key_db = LongTermKeyDatabase()
        else:
            self.long_term_key_db = long_term_key_db

    def get_default_pairing_parameters(self):
        return {"io_cap": self.default_io_cap, "oob": self.default_oob, "mitm": self.default_mitm,
                "bond": self.default_bond,
                "lesc": self.default_lesc, "keypress": self.default_keypress, "ct2": self.default_ct2,
                "rfu": self.default_rfu,
                "max_key_size": self.default_max_key_size,
                "initiator_key_distribution": self.default_initiator_key_distribution,
                "responder_key_distribution":self.default_responder_key_distribution}

    def set_default_pairing_parameters(self, default_io_cap, default_oob, default_mitm, default_bond,
                                       default_lesc, default_keypress, default_ct2, default_rfu,
                                       default_max_key_size, default_initiator_key_distribution,
                                       default_responder_key_distribution):
        self.default_io_cap = default_io_cap
        self.default_oob = default_oob
        self.default_mitm = default_mitm
        self.default_bond = default_bond
        self.default_lesc = default_lesc
        self.default_keypress = default_keypress
        self.default_ct2 = default_ct2
        self.default_rfu = default_rfu
        self.default_max_key_size = default_max_key_size
        self.default_initiator_key_distribution = default_initiator_key_distribution
        self.default_responder_key_distribution = default_responder_key_distribution

    def get_pairing_parameters_for_connection(self, peer_address):
        peer_address_lower = peer_address.lower()
        log.debug("Getting pairing parameters for connection with %s" % peer_address_lower)
        if peer_address_lower in self.security_managers.keys():
            sm = self.security_managers[peer_address_lower]
            io_cap = sm.io_cap
            oob = sm.oob
            mitm = sm.mitm
            bond = sm.bond
            lesc = sm.lesc
            keypress = sm.keypress
            ct2 = sm.ct2
            rfu = sm.rfu
            max_key_size = sm.max_key_size
            initiator_key_distribution = sm.initiator_key_distribution
            responder_key_distribution = sm.responder_key_distribution
        else:
            io_cap = None
            oob = None
            mitm = None
            bond = None
            lesc = None
            keypress = None
            ct2 = None
            rfu = None
            max_key_size = None
            initiator_key_distribution = None
            responder_key_distribution = None

        return {"io_cap": io_cap, "oob": oob, "mitm": mitm,
                "bond": bond,
                "lesc": lesc, "keypress": keypress, "ct2": ct2,
                "rfu": rfu,
                "max_key_size": max_key_size,
                "initiator_key_distribution": initiator_key_distribution,
                "responder_key_distribution": responder_key_distribution}

    def set_pairing_parameters_for_connection(self, peer_address, io_cap, oob, mitm,
                                              bond, lesc, keypress, ct2, rfu, max_key_size,
                                              initiator_key_distribution, responder_key_distribution):
        peer_address_lower = peer_address.lower()
        if peer_address_lower in self.security_managers.keys():
            sm = self.security_managers[peer_address_lower]
            sm.io_cap = io_cap
            sm.oob = oob
            sm.mitm = mitm
            sm.bond = bond
            sm.lesc = lesc
            sm.keypress = keypress
            sm.ct2 = ct2
            sm.rfu = rfu
            sm.max_key_size = max_key_size
            sm.initiator_key_distribution = initiator_key_distribution
            sm.responder_key_distribution = responder_key_distribution
            return True
        else:
            return False

    def send(self, body, conn_handle, length=None):
        self.stack.raw_smp(SM_Hdr() / body, conn_handle, length=length)

    def marshall_command(self, connection_handle, packet, peer_address):

        # SMP_PAIRING_REQUEST = 0x01
        # SMP_PAIRING_RESPONSE = 0x02
        # SMP_PAIRING_CONFIRM = 0x03
        # SMP_PAIRING_RANDOM = 0x04
        # SMP_PAIRING_FAILED = 0x05
        # SMP_ENCRYPTION_INFORMATION = 0x06
        # SMP_MASTER_IDENTIFICATION = 0x07
        # SMP_IDENTITY_INFORMATION = 0x08
        # SMP_IDENTITY_ADDRESS_INFORMATION = 0x09
        # SMP_SIGNING_INFORMATION = 0x0a
        # SMP_SECURITY_REQUEST = 0x0b
        # SMP_PAIRING_PUBLIC_KEY = 0x0c
        # SMP_PAIRING_DHKEY_CHECK = 0x0d
        # SMP_PAIRING_KEYPRESS_NOTIFICATION = 0x0e

        code = packet.sm_command
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]
        # pairing request
        if code == SMP_PAIRING_REQUEST:
            sm.pairing_initiated = True
            sm.pairing_failed = False
            # save the pairing request, reversed
            sm.preq = str(packet[SM_Hdr])[::-1]

            sm.peer_initiator_key_distribution = packet.initiator_key_distribution
            sm.peer_responder_key_distribution = packet.responder_key_distribution
            sm.peer_io_cap = packet.iocap
            sm.peer_oob = packet.oob
            peer_auth_request = packet.authentication
            sm.peer_auth_request = peer_auth_request
            sm.peer_mitm = (peer_auth_request & 4 == 4)
            sm.peer_bond = peer_auth_request & 3
            sm.peer_lesc = (peer_auth_request & 8 == 8)
            sm.peer_keypress = (peer_auth_request & 16 == 16)
            sm.peer_ct2 = (peer_auth_request & 32 == 32)
            sm.peer_rfu = peer_auth_request >> 6

            log.debug("Received SMP Pairing request.")
            log.debug("Peer parameters: IOCap: %d OOB: %d AuthReq: %d Bond: %d "
                      "Mitm: %d LESC: %d Keypress: %d CT2: %d RFU:%d" % (sm.peer_io_cap, sm.peer_oob,
                                                                         sm.peer_auth_request, sm.peer_bond,
                                                                         sm.peer_mitm, sm.peer_lesc, sm.peer_keypress,
                                                                         sm.peer_ct2, sm.peer_rfu))

            bond = format(sm.bond, '02b')
            mitm = format(sm.mitm, '01b')
            sc = format(sm.lesc, '01b')
            keypress = format(sm.keypress, '01b')
            ct2 = format(sm.ct2, '01b')
            rfu = format(sm.rfu, '02b')

            auth = int((rfu + ct2 + keypress + sc + mitm + bond), 2)

            log.debug("Our parameters: IOCap: %d OOB: %d AuthReq: %d Bond: %d "
                      "Mitm: %d LESC: %d Keypress: %d CT2: %d RFU:%d" % (sm.io_cap, sm.oob,
                                                                         auth, sm.bond,
                                                                         sm.mitm, sm.lesc, sm.keypress,
                                                                         sm.ct2, sm.rfu))
            # Generate our 16 bytes of random data for random
            sm.rrnd = os.urandom(16)
            # For now we are only supporting JustWorks, so TK is 16 bytes of 0x00
            # TODO: Insert additional methods for handling TK with different assocation models
            # TODO: Insert procedures for LESC pairing
            sm.tk = '\x00' * 16
            sm.set_security_mode_mode(1)
            sm.set_security_mode_level(2)



            (init_ltk, init_irk, init_csrk, resp_ltk,
             resp_irk, resp_csrk) = self.determine_distribution_keys(sm.initiator_key_distribution,
                                                                     sm.responder_key_distribution,
                                                                     sm.peer_initiator_key_distribution,
                                                                     sm.peer_responder_key_distribution
                                                                     )
            if not resp_ltk and not resp_irk and not resp_csrk:
                sm.distribution_keys_sent = True

            # If initiator is going to send keys, we mark them as not received, else we mark them as received
            sm.ltk_received = not init_ltk
            sm.rand_received = not init_ltk
            sm.ediv_received = not init_ltk
            sm.irk_received = not init_irk
            sm.addr_received = not init_irk
            sm.csrk_received = not init_csrk




            packet = SM_Hdr()/SM_Pairing_Response(iocap=sm.io_cap, oob=sm.oob,
                                                  authentication=auth,
                                                  initiator_key_distribution=sm.initiator_key_distribution,
                                                  responder_key_distribution=sm.responder_key_distribution)

            # save the response, reversed
            sm.prsp = str(packet[SM_Hdr])[::-1]

            self.send(packet[SM_Pairing_Response], connection_handle)

        elif code == SMP_PAIRING_RESPONSE:
            log.debug("Received pairing response")
            sm.peer_initiator_key_distribution = packet.initiator_key_distribution
            sm.peer_responder_key_distribution = packet.responder_key_distribution
            sm.peer_max_key_size = packet.max_key_size
            sm.peer_auth_request = packet.authentication
            sm.peer_oob = packet.oob
            sm.peer_io_cap = packet.iocap
            peer_auth_request = packet.authentication
            sm.peer_mitm = (peer_auth_request & 4 == 4)
            sm.peer_bond = peer_auth_request & 3
            sm.peer_lesc = (peer_auth_request & 8 == 8)
            sm.peer_keypress = (peer_auth_request & 16 == 16)
            sm.peer_ct2 = (peer_auth_request & 32 == 32)
            sm.peer_rfu = peer_auth_request >> 6
            log.debug("Peer parameters: IOCap: %d OOB: %d AuthReq: %d Bond: %d "
                      "Mitm: %d LESC: %d Keypress: %d CT2: %d RFU:%d" % (sm.peer_io_cap, sm.peer_oob,
                                                                         sm.peer_auth_request, sm.peer_bond,
                                                                         sm.peer_mitm, sm.peer_lesc, sm.peer_keypress,
                                                                         sm.peer_ct2, sm.peer_rfu))



            (init_ltk, init_irk, init_csrk, resp_ltk,
             resp_irk, resp_csrk) = self.determine_distribution_keys(sm.initiator_key_distribution,
                                                                     sm.responder_key_distribution,
                                                                     sm.peer_initiator_key_distribution,
                                                                     sm.peer_responder_key_distribution
                                                                     )
            log.debug("Checking distribution keys to send: ltk: %d, irk: %d csrk: %d" % (init_ltk, init_irk,
                                                                                         init_csrk))
            if not init_ltk and not init_irk and not init_csrk:
                sm.distribution_keys_sent = True

            # If responder is going to send keys, we mark them as not received, else we mark them as received
            sm.ltk_received = not resp_ltk
            sm.rand_received = not resp_ltk
            sm.ediv_received = not resp_ltk
            sm.irk_received = not resp_irk
            sm.addr_received = not resp_irk
            sm.csrk_received = not resp_csrk

            sm.prsp = str(packet[SM_Hdr])[::-1]
            sm.prnd = os.urandom(16)

            # TODO: Insert additional methods for handling non-LE Legacy JustWorks pairing
            sm.tk = '\x00' * 16

            log.debug("Calculating confirm with SM: %s" % sm)
            confirm_value = sm.calculate_confirm(1)
            # send confirm (send pub)
            log.debug("Sending confirm")
            self.send(SM_Confirm(confirm=confirm_value[::-1]), connection_handle)

        # pairing confirm
        elif code == SMP_PAIRING_CONFIRM:
            if sm.our_role == ROLE_TYPE_PERIPHERAL:
                # save the confirm
                sm.pcnf = str(packet[SM_Confirm])[::-1]
                log.debug("Received Pairing Confirm: %s" % sm.pcnf)
                # calculate and send our own confirm
                confirm = sm.calculate_confirm()

                self.send(SM_Confirm(confirm=confirm[::-1]), connection_handle)
            elif sm.our_role == ROLE_TYPE_CENTRAL:
                sm.pcnf = str(packet[SM_Confirm])[::-1]
                log.debug("Received Pairing Confirm: %s" % sm.pcnf)
                self.send(SM_Random(random=sm.prnd[::-1]), connection_handle)

        # pairing random
        elif code == SMP_PAIRING_RANDOM:
            if sm.our_role == ROLE_TYPE_PERIPHERAL:
                sm.prnd = packet.random[::-1]
                log.debug("Received Pairing Random: %s" % sm.prnd)
                log.debug("Received Pairing Random (hex): %s" % sm.prnd.encode('hex'))
                res = sm.verify_random()
                if not res:
                    raise Exception("pairing error")
                # send random
                self.send(SM_Random(random=sm.rrnd[::-1]), connection_handle)

                # For legacy we encrypt link with STK generated.
                # If no pairing failed response is received, we should start sending keys
                gevent.sleep(1)
                if sm.pairing_failed:
                    sm.pairing_failed = False
                    log.debug("In SMP Pairing Random received function. Waited 1 second and found pairing failure."
                              "Halting STK generation")
                    return
                log.debug("Calculating STK")
                sm.stk = sm.calculate_stk()
                log.debug("Calculated STK: %s", sm.stk)

                # TODO: LESC bonding -- Key exchange, we don't send LTK, since we've already established this value

                sm.ltk = sm.stk
                # TODO: Lock in how to generate irk and csrk
                sm.irk = '\x00' * 16
                sm.csrk = '\x00' * 16
                sm.ediv = struct.unpack(">H", os.urandom(2))[0]
                sm.randomVal = os.urandom(8)




                # TODO: Handle pairing failed
                # TODO: Handle LE Secure Connections where we encrypt
                # with the LTK
            elif sm.our_role == ROLE_TYPE_CENTRAL:
                sm.rrnd = packet.random[::-1]
                log.debug("Received Pairing Random: %s" % sm.rrnd)
                log.debug("Received Pairing Random (hex): %s" % sm.rrnd.encode('hex'))
                res = sm.verify_random(verify_peripherals_random=True)
                if not res:
                    raise Exception("pairing error")

                sm.stk = sm.calculate_stk()
                log.debug("Calculated STK: %s", sm.stk)
                log.debug("Calculated STK (hex): %s", sm.stk.encode('hex'))
                # since this is legacy, we now start encryption with STK

                # These should be set to 0 when SC is used
                #sm.ediv = struct.unpack(">H", os.urandom(2))[0]
                #sm.randomVal = os.urandom(8)
                sm.ediv = 0
                sm.randomVal = "\x00" * 8
                log.debug(
                    "Legacy Pairing: Initiating encryption with STK: Connection Handle=%s, STK=%s, EDIV=%s, Random=%s"
                    % (connection_handle, sm.stk, sm.ediv, sm.randomVal))
                log.debug("Legacy Pairing: Initiating encryption with STK: Connection Handle=%s, STK=%s, EDIV=%s, Random=%s"
                    % (hex(connection_handle), sm.stk.encode('hex'), sm.ediv, sm.randomVal.encode('hex')))
                self.stack.set_encryption(connection_handle, sm.randomVal[::-1], sm.ediv, sm.stk[::-1])

                sm.ltk = os.urandom(16)
                sm.irk = os.urandom(16)
                sm.csrk = os.urandom(16)

        elif code == SMP_PAIRING_FAILED:
            log.debug("Received Pairing Failed.")
            sm.pairing_failed = True

        elif packet.sm_command == SMP_ENCRYPTION_INFORMATION:
            log.debug("Got LTK: %s" % packet.ltk[::-1])
            log.debug("Got LTK: %s" % packet.ltk[::-1].encode("hex"))
            sm.ltk_received = True

            self.handle_distribution_key_storage(peer_address, packet.ltk[::-1], SMP_KEY_DISTRIBUTION_TYPE_LTK)
            if self.check_send_distribution_keys(peer_address):
                self.send_distribution_keys(peer_address, connection_handle)
        elif packet.sm_command == SMP_MASTER_IDENTIFICATION:
            log.debug("Got EDIV: %s and RAND: %s" % (packet.ediv, packet.rand[::-1]))
            log.debug("Got EDIV: %s and RAND: %s" % (packet.ediv, packet.rand[::-1].encode("hex")))
            sm.ediv_received = True
            sm.rand_received = True

            self.handle_distribution_key_storage(peer_address, packet.ediv, SMP_KEY_DISTRIBUTION_TYPE_EDIV)
            self.handle_distribution_key_storage(peer_address, packet.rand[::-1], SMP_KEY_DISTRIBUTION_TYPE_RAND)

            if self.check_send_distribution_keys(peer_address):
                self.send_distribution_keys(peer_address, connection_handle)
        elif packet.sm_command == SMP_IDENTITY_INFORMATION:
            log.debug("Got IRK: %s" % packet.irk[::-1])
            log.debug("Got IRK: %s" % packet.irk[::-1].encode("hex"))
            sm.irk_received = True

            self.handle_distribution_key_storage(peer_address, packet.irk[::-1], SMP_KEY_DISTRIBUTION_TYPE_IRK)
            if self.check_send_distribution_keys(peer_address):
                self.send_distribution_keys(peer_address, connection_handle)
        elif packet.sm_command == SMP_IDENTITY_ADDRESS_INFORMATION:
            log.debug("Got address information: Type: %d Address: %s (hex encode): %s" % (packet.atype,
                                                                                          packet.address[::-1],
                                                                                          packet.address[::-1].encode('hex')
                                                                                          ))
            sm.addr_received = True

            self.handle_distribution_key_storage(peer_address, (packet.atype, packet.address[::-1]),
                                                 SMP_KEY_DISTRIBUTION_TYPE_ADDRESS)
            if self.check_send_distribution_keys(peer_address):
                self.send_distribution_keys(peer_address, connection_handle)
        elif packet.sm_command == SMP_SIGNING_INFORMATION:
            log.debug("Got CSRK: %s" % packet[::-1].csrk)
            log.debug("Got CSRK: %s" % packet[::-1].csrk.encode("hex"))
            sm.csrk_received = True

            self.handle_distribution_key_storage(peer_address, packet.csrk[::-1], SMP_KEY_DISTRIBUTION_TYPE_CSRK)
            if self.check_send_distribution_keys(peer_address):
                self.send_distribution_keys(peer_address, connection_handle)
        else:
            log.debug("Got SM packet of unknown or unimplemented type: %s" % packet.sm_command)

        if sm.pairing_initiated and sm.distribution_keys_sent and sm.distribution_keys_received and not sm.pairing_failed:
            self.set_pairing_complete(peer_address, 0x00)

    def initiate_security_manager_for_connection(self, peer_addr, peer_addr_type, our_address, our_address_type,
                                                 our_role):
        peer_addr = peer_addr.lower()
        keys = self.security_managers.keys()
        if peer_addr not in keys:
            sm = SM(self.default_io_cap, self.default_oob, self.default_mitm, self.default_bond,
                    self.default_lesc, self.default_keypress, self.default_ct2, self.default_rfu,
                    self.default_max_key_size, self.default_initiator_key_distribution,
                    self.default_responder_key_distribution)
        else:
            sm = self.security_managers[peer_addr]
        sm.set_security_mode_mode(1)
        sm.set_security_mode_level(1)
        sm.our_role = our_role
        sm.rAddr = peer_addr.replace(":","").decode('hex')
        sm.rAType = peer_addr_type
        if our_role == ROLE_TYPE_CENTRAL:
            sm.ra = peer_addr.replace(":", "").decode('hex')
            sm.ra_type = peer_addr_type
            sm.ia = our_address
            sm.ia_type = our_address_type
            self.security_managers[peer_addr] = sm
        else:
            sm.ia = peer_addr.replace(":", "").decode('hex')
            sm.ia_type = peer_addr_type
            sm.ra = our_address
            sm.ra_type = our_address_type
            self.security_managers[peer_addr] = sm

    def initiate_encryption_with_existing_keys(self, address, address_type, connection_handle,
                                               our_address, our_address_type, our_role):
        address = address.lower()
        keys = self.security_managers.keys()
        if address not in keys:
            self.initiate_security_manager_for_connection(address, address_type, our_address, our_address_type,
                                                          our_role)
        sm = self.security_managers[address]

        long_term_key_entry = self.long_term_key_db.get_entry_for_address(address)
        if long_term_key_entry is None:
            return False

        sm.set_security_mode_level(long_term_key_entry['security_mode'])
        sm.set_security_mode_level(long_term_key_entry['security_level'])
        sm.rLtk = long_term_key_entry['ltk']
        sm.rEDIV = long_term_key_entry['ediv']
        sm.rRand = long_term_key_entry['rand']
        sm.rIRK = long_term_key_entry['irk']
        sm.rCSRK = long_term_key_entry['csrk']
        self.stack.set_encryption(connection_handle, long_term_key_entry['rand'], long_term_key_entry['ediv'],
                                  long_term_key_entry['ltk'])
        return True

    def set_encryption_keys_for_connection(self, addr, addr_type, conn_handle, rand, ediv, ltk, security_mode,
                                           security_level):
        addr = addr.lower()
        keys = self.security_managers.keys()
        if addr not in keys:
            #create new sm object
            sm = SM(self.default_io_cap, self.default_oob, self.default_mitm, self.default_bond,
                    self.default_lesc, self.default_keypress, self.default_ct2, self.default_rfu,
                    self.default_max_key_size, self.default_initiator_key_distribution,
                    self.default_responder_key_distribution)
            sm.rAddr = addr
            sm.rAType = addr_type
            self.security_managers[addr] = sm
        sm.set_security_mode_level(security_mode)
        sm.set_security_mode_level(security_level)
        self.long_term_key_db.add_long_term_key_entry(addr, addr_type, ltk, ediv,
                                                      rand, None, None, security_mode, security_level)
        log.debug("Initiating encryption with provided keys: Connection Handle=%s, LTK=%s, EDIV=%s, Random=%s"
                  % (conn_handle, ltk, ediv, random))

        self.stack.set_encryption(conn_handle, random, ediv, ltk)

    def has_encryption_ltk_for_address(self, peer_address):
        return ((peer_address.lower() in self.security_managers.keys()) and
                self.security_managers[peer_address].rLtk is not None)

    def send_ltk(self, connection_handle, rand, ediv, peer_address):
        # TODO This needs to be updates to support Secure COnnections where encryption only requires LTK and not
        # EDIV and RAND
        peer_address = peer_address.lower()
        rand = rand[::-1]
        log.debug("Send LTK invoked for address: %s ediv: %s rand: %s" % (peer_address, hex(ediv),
                                                                          rand.encode('hex')))
        sm = self.security_managers[peer_address]
        if self.long_term_key_db.is_ltk_in_db(peer_address, ediv, rand):
            log.debug("LTK found in LongTermKeyDatabase")
            ltk = self.long_term_key_db.get_ltk_from_ediv_and_rand(ediv, rand)

            sm.rEDIV = ediv
            sm.rRand = rand
            sm.rLtk = ltk
            mode, level = self.long_term_key_db.get_ltk_security_properties_from_ediv_and_rand(ediv, rand)
            sm.set_security_mode_mode(mode)
            sm.set_security_mode_level(level)

            self.stack.command(HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=connection_handle, ltk=sm.rLtk[::-1]))
        elif sm.ltk is not None:
            log.debug("Using ltk stored in SecurityManager. This should only be called when initial pairing has occured")
            # Handle case where our periph role is responding to the central enabling encryption
            # (With LE Legacy, this is our STK). We only will use the exchanged ltk in the key distributions
            # on a reconnection
            self.stack.command(HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=connection_handle, ltk=sm.ltk[::-1]))
        else:
            log.debug("LTK not found")
            self.stack.command(HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(handle=connection_handle))

    def set_connection_encryption_status(self, peer_address, connection_handle, status):
        self.encrypted_connections[connection_handle] = status
        if not status:
            peer_address = peer_address.lower()
            sm = self.security_managers[peer_address]
            sm.set_security_mode_level(1)
            sm.set_security_mode_mode(1)

    def get_connection_encryption_status(self, connection_handle):
        if connection_handle in self.encrypted_connections.keys():
            return self.encrypted_connections[connection_handle]
        return False

    def save_long_term_keys(self, peer_address):
        sm = self.security_managers[peer_address.lower()]
        self.long_term_key_db.add_long_term_key_entry(sm.rAddr, sm.rAType,
                                                      sm.rLtk, sm.rEDIV, sm.rRand, sm.rIRK, sm.rCSRK,
                                                      sm.get_security_mode_mode(), sm.get_security_mode_level())

    def check_wait_for_distribution_keys(self, peer_address):
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]
        if sm.pairing_initiated and sm.our_role == ROLE_TYPE_CENTRAL:
            return True
        return False

    def check_send_distribution_keys(self, peer_address):
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]
        log.debug("Check send distribution keys function called. Role: %d Pairing initiated: %d Keys already sent: %d" % (
            sm.our_role, sm.pairing_initiated, sm.distribution_keys_sent
        ))
        # If we haven't yet sent our keys as a peripheral, send now
        if sm.pairing_initiated and sm.our_role == ROLE_TYPE_PERIPHERAL and not sm.distribution_keys_sent:
            return True
        # If we've sent our keys, we need to check to make sure we've received our keys
        if sm.pairing_initiated and sm.our_role == ROLE_TYPE_PERIPHERAL and sm.distribution_keys_sent:
            sm.distribution_keys_received = (sm.ltk_received and sm.rand_received and sm.ediv_received
                                             and sm.irk_received and sm.addr_received and sm.csrk_received)
            return False
        # As central, check if we've received all the peripheral's keys. If so, begin sending ours
        if sm.pairing_initiated and sm.our_role == ROLE_TYPE_CENTRAL and not sm.distribution_keys_sent:
            sm.distribution_keys_received = (sm.ltk_received and sm.rand_received and sm.ediv_received
                                             and sm.irk_received and sm.addr_received and sm.csrk_received)
            return sm.ltk_received and sm.rand_received and sm.ediv_received and sm.irk_received and sm.addr_received and sm.csrk_received
        return False

    def send_distribution_keys(self, peer_address, connection_handle):
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]
        (init_ltk, init_irk, init_csrk, resp_ltk,
         resp_irk, resp_csrk) = self.determine_distribution_keys(sm.initiator_key_distribution,
                                                               sm.responder_key_distribution,
                                                               sm.peer_initiator_key_distribution,
                                                               sm.peer_responder_key_distribution
                                                               )
        if sm.our_role == ROLE_TYPE_PERIPHERAL:
            ltk = resp_ltk
            irk = resp_irk
            csrk = resp_csrk
        if sm.our_role == ROLE_TYPE_CENTRAL:
            ltk = init_ltk
            irk = init_irk
            csrk = init_csrk
        log.debug("Sending distribution keys")
        if ltk:
            log.debug("Sending LTK")
            # send ltk
            self.send(SM_Encryption_Information(ltk=sm.ltk[::-1]), connection_handle)
            # send ediv and rand (Tied to LTK)
            log.debug("Sending EDIV and Rand")
            self.send(SM_Master_Identification(ediv=sm.ediv, rand=sm.randomVal[::-1]), connection_handle)
        if irk:
            log.debug("Sending IRK")
            # send irk
            self.send(SM_Identity_Information(irk=sm.irk[::-1]), connection_handle)
            log.debug("Sending Addr")
            # send BD_ADD (reqd? Must be tied to irk)
            if sm.our_role == ROLE_TYPE_PERIPHERAL:
                self.send(SM_Identity_Address_Information(atype=sm.ra_type, addr=sm.ra), connection_handle)
            else:
                self.send(SM_Identity_Address_Information(atype=sm.ia_type, addr=sm.ia), connection_handle)
        if csrk:
            log.debug("Sending CSRK")
            # send csrk
            self.send(SM_Signing_Information(csrk=sm.csrk[::-1]), connection_handle)
        sm.distribution_keys_sent = True
        # if our role is peripheral, we send our keys, then wait for the central's keys

    def determine_distribution_keys(self, initiator_key_distribution, responder_key_distribution,
                                    peer_initiator_key_distribution, peer_responder_key_distribution):
        init_ltk = False
        init_irk = False
        init_csrk = False
        resp_ltk = False
        resp_irk = False
        resp_csrk = False
        peer_init_ltk = False
        peer_init_irk = False
        peer_init_csrk = False
        peer_resp_ltk = False
        peer_resp_irk = False
        peer_resp_csrk = False
        if (initiator_key_distribution & 0x1) == 0x1:
            init_ltk = True
        if (initiator_key_distribution & 0x2) == 0x2:
            init_irk = True
        if (initiator_key_distribution & 0x4) == 0x4:
            init_csrk = True

        if (responder_key_distribution & 0x1) == 0x1:
            resp_ltk = True
        if (responder_key_distribution & 0x2) == 0x2:
            resp_irk = True
        if (responder_key_distribution & 0x4) == 0x4:
            resp_csrk = True

        if (peer_initiator_key_distribution & 0x1) == 0x1:
            peer_init_ltk = True
        if (peer_initiator_key_distribution & 0x2) == 0x2:
            peer_init_irk = True
        if (peer_initiator_key_distribution & 0x4) == 0x4:
            peer_init_csrk = True

        if (peer_responder_key_distribution & 0x1) == 0x1:
            peer_resp_ltk = True
        if (peer_responder_key_distribution & 0x2) == 0x2:
            peer_resp_irk = True
        if (peer_responder_key_distribution & 0x4) == 0x4:
            peer_resp_csrk = True

        return ((init_ltk & peer_init_ltk), (init_irk & peer_init_irk), (init_csrk & peer_init_csrk),
                (resp_ltk & peer_resp_ltk), (resp_irk & peer_resp_irk), (resp_csrk & peer_resp_csrk))

    def handle_distribution_key_storage(self, peer_address, value, value_type):
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]

        (init_ltk, init_irk, init_csrk, resp_ltk,
         resp_irk, resp_csrk) = self.determine_distribution_keys(sm.initiator_key_distribution,
                                                                 sm.responder_key_distribution,
                                                                 sm.peer_initiator_key_distribution,
                                                                 sm.peer_responder_key_distribution
                                                                 )
        if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
            init_val = init_ltk
            resp_val = resp_ltk
        if value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
            init_val = init_ltk
            resp_val = resp_ltk
        if value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
            init_val = init_ltk
            resp_val = resp_ltk
        elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK or value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
            init_val = init_irk
            resp_val = resp_irk
        elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
            init_val = init_csrk
            resp_val = resp_csrk

        if value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
            log.debug("In Handle distribution key storage. Value type: %s value: %s Value_type: %d init_val: %d resp_val: %d" % (
                value[0], value[1].encode('hex'), value_type, init_val, resp_val
            ))
        elif value_type != SMP_KEY_DISTRIBUTION_TYPE_EDIV:
            log.debug("In Handle distribution key storage. Value: %s Value_type: %d init_val: %d resp_val: %d" % (
                value.encode('hex'), value_type, init_val, resp_val
            ))
        else:
            log.debug("In Handle distribution key storage. Value: %s Value_type: %d init_val: %d resp_val: %d" % (
                value, value_type, init_val, resp_val
            ))
        log.debug("Role Values -- Peripheral: %d Central: %d Our Role: %d" % (ROLE_TYPE_PERIPHERAL, ROLE_TYPE_CENTRAL,
                                                                              sm.our_role))
        # if either side agreed to send this value, then we should decide to store, otherwise ignore
        if init_val or resp_val:
            if sm.our_role == ROLE_TYPE_CENTRAL:
                if init_val and resp_val:
                    # We will always take the peripherals stored LTK over our own
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
                        sm.rRand = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = value[1]
                        sm.rAType = value[0]
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = value
                elif init_val:
                    # If just the initator (us) has this flag set, we keep ours
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = sm.ltk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = sm.ediv
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
                        sm.rRand = sm.randomVal
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = sm.irk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = sm.ra
                        sm.rAType = sm.ra_type
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = sm.csrk
                elif resp_val:
                    # If just the responder has this flag set, we accept theirs
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = value[1]
                        sm.rAType = value[0]
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = value
            if sm.our_role == ROLE_TYPE_PERIPHERAL:
                if init_val and resp_val:
                    # We will always store the peripherals stored LTK over the central's
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = sm.ltk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = sm.ediv
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
                        sm.rRand = sm.randomVal
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = sm.irk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = sm.ia
                        sm.rAType = sm.ia_type
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = sm.csrk
                elif init_val:
                    # If just the initator (them) has this flag set, we accept theirs
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = value[1]
                        sm.rAType = value[0]
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
                        sm.rRand = value
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = value
                elif resp_val:
                    # If just the responder (us) has this flag set, we keep ours
                    if value_type == SMP_KEY_DISTRIBUTION_TYPE_LTK:
                        sm.rLtk = sm.ltk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_EDIV:
                        sm.rEDIV = sm.ediv
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_RAND:
                        sm.rRand = sm.randomVal
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_IRK:
                        sm.rIRK = sm.irk
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_ADDRESS:
                        sm.rAddr = sm.ia
                        sm.rAType = sm.ia_type
                    elif value_type == SMP_KEY_DISTRIBUTION_TYPE_CSRK:
                        sm.CSRK = sm.csrk

    def send_pairing_request(self, destination_address, connection_handle):
        destination_address = destination_address.lower()
        sm = self.security_managers[destination_address]
        sm.pairing_failed = False
        sm.pairing_initiated = True
        sm.ltk_received = False
        sm.rand_received = False
        sm.ediv_received = False
        sm.irk_received = False
        sm.addr_received = False
        sm.csrk_received = False
        packet = SM_Hdr() / SM_Pairing_Request(iocap=sm.io_cap, oob=sm.oob, authentication=sm.auth_request,
                                                max_key_size=sm.max_key_size,
                                                initiator_key_distribution=sm.initiator_key_distribution,
                                                responder_key_distribution=sm.responder_key_distribution)
        sm.preq = str(packet[SM_Hdr])[::-1]

        self.send(packet[SMP_PAIRING_REQUEST], connection_handle)

    def is_pairing_in_progress(self, peer_address):
        peer_address = peer_address.lower()
        if peer_address not in self.security_managers.keys():
            return False
        return self.security_managers[peer_address].pairing_initiated

    def set_pairing_failed(self, peer_address, status):
        sm = self.security_managers[peer_address.lower()]
        sm.pairing_failed = status
        sm.ltk_received = False
        sm.rand_received = False
        sm.ediv_received = False
        sm.irk_received = False
        sm.addr_received = False
        sm.csrk_received = False

    def did_pairing_fail(self, peer_address):
        sm = self.security_managers[peer_address.lower()]
        return sm.pairing_failed

    def on_device_disconnect(self, peer_address, connection_handle):
        sm = self.security_managers[peer_address.lower()]
        sm.pairing_initiated = False
        sm.ltk_received = False
        sm.rand_received = False
        sm.ediv_received = False
        sm.irk_received = False
        sm.addr_received = False
        sm.csrk_received = False
        self.set_connection_encryption_status(peer_address, connection_handle, False)

    def set_pairing_complete(self, peer_address, status):
        peer_address = peer_address.lower()
        sm = self.security_managers[peer_address]
        sm.pairing_initiated = False
        sm.pairing_failed = (status == 0)
        self.save_long_term_keys(peer_address)
