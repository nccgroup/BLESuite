import json
import binascii
import random
from blesuite.connection_manager import BLEConnectionManager
import gevent


def replay_file_write(rows, filename):
    with open(filename, "w") as f:
        for row in rows:
            seq_nbr, time, handle, message = row
            file_row = handle, message, [], 1
            f.write("%s\n" % json.dumps(file_row))


def gatt_writes(dev, addr, addrType, rows, mtu=23, wait=False):
    '''Set up the BLE connection and write data'''
    with BLEConnectionManager(dev, 'central') as connection_manager:
        conn = connection_manager.init_connection(addr, addrType)
        connection_manager.connect(conn)
        if mtu is not None:
            connection_manager.exchange_mtu(conn, mtu)
        for row in rows:
            handle, message, fuzz_positions, num_iterations = row
            handle_base10 = binascii.unhexlify(handle)
            gatt_write(connection_manager, conn, handle_base10, message, fuzz_positions,
                       num_iterations)
        if wait:
            print "Replay finished. Will continue to wait until user force's exit (ctrl+c)"
            while True:
                gevent.sleep(1)


def gatt_write(connection_manager, conn, handle, message, fuzz_positions, num_iterations):
    '''Make a single write to a handle using bleSuite'''
    current_message = message
    if fuzz_positions:
        for position in fuzz_positions:
            current_message = current_message[0:position*2] + \
                binascii.hexlify(chr(random.randint(0, 255))) + \
                current_message[position*2:-1]
    for _ in range(num_iterations):
        handle = handle.encode('hex')
        current_message = current_message.decode('hex')
        print "sending: " + current_message + " on " + handle
        if not connection_manager.is_connected(conn):
            connection_manager.connect(conn)
        req = connection_manager.gatt_write_handle(conn, int(handle, 16), current_message)
