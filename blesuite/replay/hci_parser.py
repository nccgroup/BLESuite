from blesuite.replay.btsnoop.android.snoopphone import SnoopPhone
import binascii
import util
import blesuite.replay.btsnoop.btsnoop.btsnoop as bts
import blesuite.replay.btsnoop.bt.hci_uart as hci_uart
import blesuite.replay.btsnoop.bt.hci_acl as hci_acl
import blesuite.replay.btsnoop.bt.l2cap as l2cap
import blesuite.replay.btsnoop.bt.att as att
import pyshark
import datetime


class ATTWriteParser:
    """HCI log fetching/parsing component that uses btsnoop"""

    def __init__(self):
        self.snoop_file = None
        self.att_writes = []
        self.records = []
        self.pcap_file = None
        self._opcodeList = [int("0x12", 16), int("0x52",
                                                 16), ]  ## only covers write and writecmd (writecmd not tested)
                                                         # ## TODO ADD READ AND ALL OTHER COMMANDS WE WANT TO SUPPORT

    def fetch_from_phone(self, output_filename=None):
        """Fetch btsnoop file from connected Android device
        adb required, don't pass a filename if you don't
        want to store the log locally
        """
        phone = SnoopPhone()
        try:
            self.snoop_file = phone.pull_btsnoop(output_filename)
        except ValueError:
            print "connect an Android device..."
            raise
        except Exception as e:
            print e.message

    def load_file(self, input_filename=None, pcap_format=False):
        """Load a btsnoop file from disk"""
        if input_filename:
            print "loading file"
            if not pcap_format:
                self.snoop_file = input_filename
            else:
                self.pcap_file = input_filename
        else:
            raise ValueError("Must specify a valid filename for load_file")

    def get_records(self):
        """Parse the btsnoop file into a dictionary of records"""
        if self.snoop_file is None and self.pcap_file is None:
            raise ValueError("Must load a btsnoop or PCAP file to get records")
            return

        if self.snoop_file is not None:
            try:
                records = bts.parse(self.snoop_file)
            except Exception as e:
                print "Error: "
                print e.message
                return None
        elif self.pcap_file is not None:
            py_cap = pyshark.FileCapture(self.pcap_file)
            records = []
            for packet in py_cap:
                records.append(packet)
        self.records = records
        return records

    def parse_att_writes(self):
        """Get a list of ATT write requests in the log"""
        self.att_writes = []
        self.get_records()
        for record in self.records:
            if self.snoop_file is not None:
                seq_nbr = record[0]
                hci_pkt_type, hci_pkt_data = hci_uart.parse(record[4])

                if hci_pkt_type == hci_uart.ACL_DATA:

                    hci_data = hci_acl.parse(hci_pkt_data)
                    l2cap_length, l2cap_cid, l2cap_data = l2cap.parse(hci_data[2],
                                                                      hci_data[4])

                    if l2cap_cid == l2cap.L2CAP_CID_ATT:

                        att_opcode, att_data = att.parse(l2cap_data)
                        cmd_evt_l2cap = att.opcode_to_str(att_opcode)

                        if 'Write_Request' in cmd_evt_l2cap:
                            data = binascii.hexlify(att_data)
                            handle = data[2:4] + data[0:2]
                            self.att_writes.append([seq_nbr, record[3], handle,
                                                    data[4:]])
            elif self.pcap_file is not None:
                # seq_nbr, datetime.datetime, handle, data
                try:
                    if record.btl2cap.get('cid').main_field.int_value == 400:
                        if int(record.btatt.get_field_value('opcode', raw=True), 16) in self._opcodeList:
                            try:
                                handle = record.btatt.get_field_value('handle')[2:]
                                data = record.btatt.get_field_value('value', raw=True)
                                seq = record.btle.get_field_value('l2cap_index')
                                # TODO: I wasn't able to find a timestamp in the PCAP for each entry,
                                # maybe I'm just not calling pyshark correctly for the info...
                                self.att_writes.append([seq, datetime.datetime.now(), handle, data])
                            except Exception as p:
                                print "Error:", p
                except Exception as e:
                    continue

        return self.att_writes

    def write_to_file(self, output_filename=None):
        """Write the data to a file for manual modification before replay"""
        if not output_filename:
            raise ValueError("Must specify an output filename")

        util.replay_file_write(self.att_writes, output_filename)

    def pretty_print(self):
        """Pretty print the data to standard out"""
        try:
            from prettytable import PrettyTable
        except:
            print "prettytable required for this feature"
            return

        table = PrettyTable(['No.', 'Time', 'Handle', 'Data'])
        table.align["Handle"] = 'l'
        table.align["Data"] = 'l'

        for r in self.att_writes:
            data = len(r[3]) > 30 and r[3][:30] + "..." or r[3]
            time = r[1].strftime("%b-%d %H:%M:%S.%f")
            table.add_row([r[0], time, r[2], data])

        print table
