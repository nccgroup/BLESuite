"""
  Parse btsnoop_hci.log binary data (similar to wireshark)
  usage:
     ./parse.py <filename>
"""
import datetime
import sys
import struct


"""
Record flags conform to:
    - bit 0         0 = sent, 1 = received
    - bit 1         0 = data, 1 = command/event
    - bit 2-31      reserved

Direction is relative to host / DTE. i.e. for Bluetooth controllers,
Send is Host->Controller, Receive is Controller->Host
"""
BTSNOOP_FLAGS = {
        0 : ("host", "controller", "data"),
        1 : ("controller", "host", "data"),
        2 : ("host", "controller", "command"),
        3 : ("controller", "host", "event")
    }


def parse(filename):
    """ 
    Parse a Btsnoop packet capture file.

    Btsnoop packet capture file is structured as:
    
    -----------------------
    | header              |
    -----------------------
    | packet record nbr 1 |
    -----------------------
    | packet record nbr 2 |
    -----------------------
    | ...                 |
    -----------------------
    | packet record nbr n |
    -----------------------
    
    References can be found here:
    * http://tools.ietf.org/html/rfc1761
    * http://www.fte.com/webhelp/NFC/Content/Technical_Information/BT_Snoop_File_Format.htm

    Return a list of records, each holding a tuple of:
    * sequence nbr
    * record length (in bytes)
    * flags
    * timestamp
    * data
    """
    with open(filename, "rb") as f:
    
        # Validate file header
        (identification, version, type) = _read_file_header(f)
        _validate_file_header(identification, version, type)

        # Not using the following data:
        # record[1] - original length
        # record[4] - cumulative drops
        return map(lambda record: 
            (record[0], record[2], record[3], _parse_time(record[5]), record[6]),
            _read_packet_records(f))


def _read_file_header(f):
    """
    Header should conform to the following format
    
    ----------------------------------------
    | identification pattern|
    | 8 bytes                              |
    ----------------------------------------
    | version number                   |
    | 4 bytes                              |
    ----------------------------------------
    | data link type = HCI UART (H4)       |
    | 4 bytes                              |
    ----------------------------------------

    All integer values are stored in "big-endian" order, with the high-order bits first.
    """
    ident = f.read(8)
    version, data_link_type = struct.unpack( ">II", f.read(4 + 4) )
    return (ident, version, data_link_type)


def _validate_file_header(identification, version, data_link_type):
    """
    The identification pattern should be:
        'btsnoop\0' 
    
    The version number should be:
        1
    
    The data link type can be:
        - Reserved	0 - 1000
        - Un-encapsulated HCI (H1)	1001
        - HCI UART (H4)	1002
        - HCI BSCP	1003
        - HCI Serial (H5)	1004
        - Unassigned	1005 - 4294967295
        
    For SWAP, data link type should be:
        HCI UART (H4)	1002
    """
    assert identification == "btsnoop\0"
    assert version == 1
    assert data_link_type == 1002
    print "Btsnoop capture file version {0}, type {1}".format(version, data_link_type)


def _read_packet_records(f):
    """
    A record should confirm to the following format
    
    --------------------------
    | original length        |
    | 4 bytes   
    --------------------------
    | included length        |
    | 4 bytes   
    --------------------------
    | packet flags           |
    | 4 bytes   
    --------------------------
    | cumulative drops       |
    | 4 bytes   
    --------------------------
    | timestamp microseconds |
    | 8 bytes
    --------------------------
    | packet data            |
    --------------------------
    
    All integer values are stored in "big-endian" order, with the high-order bits first.
    """
    seq_nbr = 1
    while True:
        pkt_hdr = f.read(4 + 4 + 4 + 4 + 8)
        if not pkt_hdr or len(pkt_hdr) != 24:
            # EOF
            break
    
        orig_len, inc_len, flags, drops, time64 = struct.unpack( ">IIIIq", pkt_hdr)
        assert orig_len == inc_len
        
        data = f.read(inc_len)
        assert len(data) == inc_len
    
        yield ( seq_nbr, orig_len, inc_len, flags, drops, time64, data )
        seq_nbr += 1


def _parse_time(time):
    """
    Record time is a 64-bit signed integer representing the time of packet arrival, 
    in microseconds since midnight, January 1st, 0 AD nominal Gregorian.

    In order to avoid leap-day ambiguity in calculations, note that an equivalent 
    epoch may be used of midnight, January 1st 2000 AD, which is represented in 
    this field as 0x00E03AB44A676000.
    """
    time_betw_0_and_2000_ad = int("0x00E03AB44A676000", 16)
    time_since_2000_epoch = datetime.timedelta(microseconds=time) - datetime.timedelta(microseconds=time_betw_0_and_2000_ad)
    return datetime.datetime(2000, 1, 1) + time_since_2000_epoch


def flags_to_str(flags):
    """
    Returns a tuple of (src, dst, type)
    """
    assert flags in [0,1,2,3]
    return BTSNOOP_FLAGS[flags]


def print_hdr():
    """
    Print the script header
    """
    print ""
    print "##############################"
    print "#                            #"
    print "#    btsnoop parser v0.1     #"
    print "#                            #"
    print "##############################"
    print ""


def main(filename):
    records = parse(filename)
    print records
    return 0

    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print __doc__
        sys.exit(1)
        
    print_hdr()
    sys.exit(main(sys.argv[1]))