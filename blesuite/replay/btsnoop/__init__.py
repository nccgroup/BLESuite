#
# btsnoop module
#
# TODO: Move stuff here to their corresponding modules
#
import binascii
import btsnoop.btsnoop as bts
import bt.hci_cmd as hci_cmd
import bt.hci_uart as hci_uart

from android.snoopphone import SnoopPhone


def get_ltk(path=None):
	"""
	Get the Long Term Key
	"""
	records = get_records(path=path)
	cmds = get_cmds(records)
	start_enc_cmds = filter(lambda (opcode, length, data): opcode == 0x2019, cmds)
	ltks = map(lambda (opcode, length, data): binascii.hexlify(data)[-32:], start_enc_cmds)
	last_ltk = len(ltks) != 0 and ltks[-1] or ""
	return "".join(map(str.__add__, last_ltk[1::2] ,last_ltk[0::2]))


def get_rand_addr(path=None):
	"""
	Get the Host Private Random Address
	"""
	records = get_records(path=path)
	cmds = get_cmds(records)
	set_rand_addr = filter(lambda (opcode, length, data): opcode == 0x2005, cmds)
	addrs = map(lambda (opcode, length, data): binascii.hexlify(data)[-12:], set_rand_addr)
	last_addr = len(addrs) != 0 and addrs[-1] or ""
	return "".join(map(str.__add__, last_addr[1::2], last_addr[0::2]))


def get_records(path=None):
	if not path:
		path = _pull_log()
	return bts.parse(path)


def get_cmds(records):
	hci_uarts = map(lambda record: hci_uart.parse(record[4]), records)
	hci_cmds = filter(lambda (hci_type, hci_data): hci_type == hci_uart.HCI_CMD, hci_uarts)
	return map(lambda (hci_type, hci_data): hci_cmd.parse(hci_data), hci_cmds)


def _pull_log():
	"""
	Pull the btsnoop log from a connected phone
	"""
	phone = SnoopPhone()
	return phone.pull_btsnoop()