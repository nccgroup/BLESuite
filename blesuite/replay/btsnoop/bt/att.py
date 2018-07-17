"""
Parse ATT packets
"""
import struct


"""
ATT PDUs

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part F (Section 3.4.8) - Attribute Opcode Summary
"""
ATT_PDUS = {
        0x01 : "ATT Error_Response",
        0x02 : "ATT Exchange_MTU_Request",
        0x03 : "ATT Exchange_MTU_Response",
        0x04 : "ATT Find_Information_Request",
        0x05 : "ATT Find_Information_Response",
        0x06 : "ATT Find_By_Type_Value_Request",
        0x07 : "ATT Find_By_Type_Value_Response",
        0x08 : "ATT Read_By_Type_Request",
        0x09 : "ATT Read_By_Type_Response",
        0x0A : "ATT Read_Request",
        0x0B : "ATT Read_Response",
        0x0C : "ATT Read_Blob_Request",
        0x0D : "ATT Read_Blob_Response",
        0x0E : "ATT Read_Multiple_Request",
        0x0F : "ATT Read_Multiple_Response",
        0x10 : "ATT Read_By_Group_Type_Request",
        0x11 : "ATT Read_By_Group_Type_Response",
        0x12 : "ATT Write_Request",
        0x13 : "ATT Write_Response",
        0x52 : "ATT Write_Command",
        0xD2 : "ATT Signed_Write_Command",
        0x16 : "ATT Prepare_Write_Request",
        0x17 : "ATT Prepare_Write_Response",
        0x18 : "ATT Execute_Write_Request",
        0x19 : "ATT Execute_Write_Response",
        0x1B : "ATT Handle_Value_Notification",
        0x1D : "ATT Handle_Value_Indication",
        0x1E : "ATT Handle_Value_Confirmation"
    }


def parse(data):
    """
    Attribute opcode is the first octet of the PDU

     0 1 2 3 4 5 6 7
    -----------------
    |   att opcode  |
    -----------------
    |     a     |b|c|
    -----------------
    a - method
    b - command flag
    c - authentication signature flag

    References can be found here:
        * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
        ** [vol 3] Part F (Section 3.3) - Attribute PDU

    Return a tuple (opcode, data)
    """
    opcode = struct.unpack("<B", data[:1])[0]
    return (opcode, data[1:])


def opcode_to_str(opcode):
    """
    Return a string representing the ATT PDU opcode
    """
    return ATT_PDUS[opcode]