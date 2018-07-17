btsnoop
=======

Parsing module for BtSnoop packet capture files and encapsulated Bluetooth packets

Documentation
-------------

Specifications
- BtSnoop format
	- http://tools.ietf.org/html/rfc1761
	- http://www.fte.com/webhelp/NFC/Content/Technical_Information/BT_Snoop_File_Format.htm
- Bluetooth specification
	- https://www.bluetooth.org/en-us/specification/adopted-specifications

Module overview
---------------

The `btsnoop` module contains three submodules; `android`, `bt` and `btsnoop`.

The `android` submodule contains functionality for connecting to, and fetching data from, an Android device. It requires an installation of the Android `adb` tool available in `PATH`.

The `btsnoop` submodule contains functionality for parsing a btsnoop file.

The `bt` submodule contains functionality for parsing the Bluetooth data parsed from the btsnoop file.

Usage
-----

### android

Getting the btsnoop log from an android device

```python
>>> import os
>>> from btsnoop.android.snoopphone import SnoopPhone
>>>
>>> phone = SnoopPhone()
>>> filename = phone.pull_btsnoop()
>>>
>>> print filename
/tmp/tmp7t971D/btsnoop_hci.log
```

You can also specify the output file

```python
>>> import os
>>> from btsnoop.android.snoopphone import SnoopPhone
>>>
>>> phone = SnoopPhone()
>>> home = os.path.expanduser("~")
>>> dst = os.path.join(home, 'tmp', 'mysnoop.log')
>>> filename = phone.pull_btsnoop(dst)
>>>
>>> print filename
/home/joekickass/tmp/mysnoop.log
```

### btsnoop

Parsing a btsnoop capture file

```python
>>> import os
>>> import btsnoop.btsnoop.btsnoop as bts
>>>
>>> home = os.path.expanduser("~")
>>> filename = os.path.join(home, 'tmp', 'mysnoop.log')
>>>
>>> records = bts.parse(filename)
>>>
>>> print len(records)
24246
>>> print records[0]
(1, 4, 2, datetime.datetime(2015, 4, 2, 6, 29, 25, 914577), '\x01\x03\x0c\x00')
>>> print records[24245]
(24246, 8, 3, datetime.datetime(2015, 4, 2, 9, 9, 57, 655656), '\x04\x13\x05\x01@\x00\x01\x00')
```

Some of the information in a record can be printed as human readable strings

```python
>>> import btsnoop.btsnoop.btsnoop as bts
...
>>> print len(records)
24246
>>> print records[0]
(1, 4, 2, datetime.datetime(2015, 4, 2, 6, 29, 25, 914577), '\x01\x03\x0c\x00')
>>> record = records[0]
>>> seq_nbr = record[0]
>>> pkt_len = record[1]
>>> flags = bts.flags_to_str(record[2])
>>> timestamp = record[3]
>>> data = record[4]
>>> print seq_nbr
1
>>> print pkt_len
4
>>> print flags
('host', 'controller', 'command')
>>> print timestamp
2015-04-02 06:29:25.914577
>>> print data
'\x01\x03\x0c\x00'
```

### bt

This is the fun stuff. The data contained in a btsnoop record can be parsed using the `bt` submodule.

Parse HCI UART type. This is the first byte of the payload. It tells us what type of HCI packet that is contained in the record.

```python
>>> import btsnoop.bt.hci_uart as hci_uart
>>> import btsnoop.bt.hci as hci
>>>
>>> rec_data = '\x01\x03\x0c\x00'
>>>
>>> hci_type, data = hci_uart.parse(rec_data)
>>>
>>> print hci_type
1
>>> print data
'\x03\x0c\x00'
>>> print hci_uart.type_to_str(hci_type)
HCI_CMD
```

Parse a HCI command packet. We need to specify HCI type as described in the HCI UART  example.

```python
>>> import btsnoop.bt.hci as hci
>>> import btsnoop.bt.hci_cmd as hci_cmd
>>>
>>> hci_type = 1
>>> hci_data = '\x03\x0c\x00'
>>>
>>> opcode, length, data = hci.parse(hci_type, hci_data)
>>> 
>>> print opcode
3075
>>> print length
0
>>> print data

>>> print hci_cmd.cmd_to_str(opcode)
COMND Reset
```

Parse a HCI event packet. We need to specify HCI type as described in the HCI UART example.

```python
>>> import btsnoop.bt.hci as hci
>>> import btsnoop.bt.hci_evt as hci_evt
>>>
>>> hci_type = 4
>>> hci_data = '\x13\x05\x01@\x00\x01\x00'
>>>
>>> ret = hci.parse(hci_type, hci_data)
>>> print len(ret)
3
>>> 
>>> evtcode, length, data = ret
>>> print evtcode
19
>>> print length
5
>>> print data
'\x01@\x00\x01\x00'
>>> print hci_evt.evt_to_str(evtcode)
EVENT Number_Of_Completed_Packets
```

Parse a HCI ACL packet. We need to specify HCI type as described in the HCI UART example.

```python
>>> import btsnoop.bt.hci as hci
>>> import btsnoop.bt.hci_acl as hci_acl
>>>
>>> hci_type = 2
>>> hci_data = '@ \x07\x00\x03\x00\x04\x00\x0b@\x04'
>>>
>>> ret = hci.parse(hci_type, hci_data)
>>> print len(ret)
5
>>>
>>> handle, pb, bc, length, data = ret
>>> print handle
64
>>> print pb
2
>>> print data
'\x00\x03\x00\x04\x00\x0b@\x04'
>>> print hci_acl.pb_to_str(pb)
ACL_PB START_AUTO_L2CAP_PDU
```

### More complex samples

```python
import sys
import binascii
import string
from prettytable import PrettyTable

import btsnoop.btsnoop.btsnoop as btsnoop
import btsnoop.bt.hci_uart as hci_uart
import btsnoop.bt.hci_cmd as hci_cmd
import btsnoop.bt.hci_evt as hci_evt
import btsnoop.bt.hci_acl as hci_acl
import btsnoop.bt.l2cap as l2cap
import btsnoop.bt.att as att
import btsnoop.bt.smp as smp

def get_rows(records):

    rows = []
    for record in records:

        seq_nbr = record[0]
        time = record[3].strftime("%b-%d %H:%M:%S.%f")

        hci_pkt_type, hci_pkt_data = hci_uart.parse(record[4])
        hci = hci_uart.type_to_str(hci_pkt_type)

        if hci_pkt_type == hci_uart.HCI_CMD:
            
            opcode, length, data = hci_cmd.parse(hci_pkt_data)
            cmd_evt_l2cap = hci_cmd.cmd_to_str(opcode)

        elif hci_pkt_type == hci_uart.HCI_EVT:
            
            hci_data = hci_evt.parse(hci_pkt_data)
            evtcode, data = hci_data[0], hci_data[-1]
            cmd_evt_l2cap = hci_evt.evt_to_str(evtcode)

        elif hci_pkt_type == hci_uart.ACL_DATA:
            
            hci_data = hci_acl.parse(hci_pkt_data)
            l2cap_length, l2cap_cid, l2cap_data = l2cap.parse(hci_data[2], hci_data[4])

            if l2cap_cid == l2cap.L2CAP_CID_ATT:

                att_opcode, att_data = att.parse(l2cap_data)
                cmd_evt_l2cap = att.opcode_to_str(att_opcode)
                data = att_data

            elif l2cap_cid == l2cap.L2CAP_CID_SMP:

                smp_code, smp_data = smp.parse(l2cap_data)
                cmd_evt_l2cap = smp.code_to_str(smp_code)
                data = smp_data

            elif l2cap_cid == l2cap.L2CAP_CID_SCH or l2cap_cid == l2cap.L2CAP_CID_LE_SCH:

                sch_code, sch_id, sch_length, sch_data = l2cap.parse_sch(l2cap_data)
                cmd_evt_l2cap = l2cap.sch_code_to_str(sch_code)
                data = sch_data

        data = binascii.hexlify(data)
        data = len(data) > 30 and data[:30] + "..." or data  

        rows.append([seq_nbr, time, hci, cmd_evt_l2cap, data])

    return rows


def main(filename):
    """
    Parse a btsnoop log and print relevant data in a table

    Note: Using an old version of PrettyTable.
    """

    table = PrettyTable(['No.', 'Time', 'HCI', 'CMD/EVT/L2CAP', 'Data'])
    table.aligns[3] = 'l'
    table.aligns[4] = 'l'
    
    records = btsnoop.parse(filename)
    rows = get_rows(records)
    [table.add_row(r) for r in rows]

    print table


if __name__ == "__main__":
    if len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        sys.exit(-1)
```
