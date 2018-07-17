"""
  Parse hci events
"""
import struct


"""
Event codes and names for HCI events

Event code is 1 byte.

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
---------------------------------
|   event code  |    length     |
---------------------------------

However, LE Meta events adds additional data that needs to be handled.

LE_META_EVENT:

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
-------------------------------------------------
|   event code  |    length     | subevent code |
-------------------------------------------------
"""


"""
The HCI LE Meta Event is used to encapsulate all LE Controller specific events.
The Event Code of all LE Meta Events shall be 0x3E. The Subevent_Code is
the first octet of the event parameters. The Subevent_Code shall be set to one
of the valid Subevent_Codes from an LE specific event
"""
HCI_LE_META_EVENT = 0x3e;


"""
HCI LE Meta events

References can be found here:
* https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
** [vol 2] Part E (Section 7.7.65) - Le Meta Event
"""
HCI_LE_META_EVENTS = {
        0x01 : "EVENT LE_Connection_Complete",
        0x02 : "EVENT LE_Advertising_Report",
        0x03 : "EVENT LE_Connection_Update_Complete",
        0x04 : "EVENT LE_Read_Remote_Used_Features_Complete",
        0x05 : "EVENT LE_Long_Term_Key_Request",
        0x06 : "EVENT LE_Remote_Connection_Parameter_Request"
    }


"""
HCI Event codes

References can be found here:
* https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
** [vol 2] Part E (Section 7.7) - Events
"""
HCI_EVENTS = {
        0x01 : "EVENT Inquiry_Complete",
        0x02 : "EVENT Inquiry_Result",
        0x03 : "EVENT Connection_Complete",
        0x04 : "EVENT Connection_Request",
        0x05 : "EVENT Disconnection_Complete",
        0x06 : "EVENT Authentication_Complete",
        0x07 : "EVENT Remote_Name_Request_Complete",
        0x08 : "EVENT Encryption_Change",
        0x09 : "EVENT Change_Connection_Link_Key_Complete",
        0x0a : "EVENT Master_Link_Key_Complete",
        0x0b : "EVENT Read_Remote_Supported_Features_Complete",
        0x0c : "EVENT Read_Remote_Version_Information_Complete",
        0x0d : "EVENT QoS_Setup_Complete",
        0x0e : "EVENT Command_Complete",
        0x0f : "EVENT Command_Status",
        0x10 : "EVENT Hardware_Error",
        0x11 : "EVENT Flush_Occurred",
        0x12 : "EVENT Role_Change",
        0x13 : "EVENT Number_Of_Completed_Packets",
        0x14 : "EVENT Mode_Change",
        0x15 : "EVENT Return_Link_Keys",
        0x16 : "EVENT PIN_Code_Request",
        0x17 : "EVENT Link_Key_Request",
        0x18 : "EVENT Link_Key_Notification",
        0x19 : "EVENT Loopback_Command",
        0x1a : "EVENT Data_Buffer_Overflow",
        0x1b : "EVENT Max_Slots_Change",
        0x1c : "EVENT Read_Clock_Offset_Complete",
        0x1d : "EVENT Connection_Packet_Type_Changed",
        0x1e : "EVENT QoS_Violation",
        0x20 : "EVENT Page_Scan_Repetition_Mode_Change",
        0x21 : "EVENT Flow_Specification_Complete",
        0x22 : "EVENT Inquiry_Result_with_RSSI",
        0x23 : "EVENT Read_Remote_Extended_Features_Complete",
        0x2c : "EVENT Synchronous_Connection_Complete",
        0x2d : "EVENT Synchronous_Connection_Changed",
        0x2e : "EVENT Sniff_Subrating",
        0x2f : "EVENT Extended_Inquiry_Result",
        0x30 : "EVENT Encryption_Key_Refresh_Complete",
        0x31 : "EVENT IO_Capability_Request",
        0x32 : "EVENT IO_Capability_Response",
        0x33 : "EVENT User_Confirmation_Request",
        0x34 : "EVENT User_Passkey_Request",
        0x35 : "EVENT Remote_OOB_Data_Request",
        0x36 : "EVENT Simple_Pairing_Complete",
        0x38 : "EVENT Link_Supervision_Timeout_Changed",
        0x39 : "EVENT Enhanced_Flush_Complete",
        0x3b : "EVENT User_Passkey_Notification",
        0x3c : "EVENT Keypress_Notification",
        0x3d : "EVENT Remote_Host_Supported_Features_Notification",
        HCI_LE_META_EVENT : "EVENT LE_Meta_Event",
        0x40 : "EVENT Physical_Link_Complete",
        0x41 : "EVENT Channel_Selected",
        0x42 : "EVENT Disconnection_Physical_Link_Complete",
        0x43 : "EVENT Physical_Link_Loss_Early_Warning",
        0x44 : "EVENT Physical_Link_Recovery",
        0x45 : "EVENT Logical_Link_Complete",
        0x46 : "EVENT Disconnection_Logical_Link_Complete",
        0x47 : "EVENT Flow_Spec_Modify_Complete",
        0x48 : "EVENT Number_Of_Completed_Data_Blocks",
        0x4c : "EVENT Short_Range_Mode_Change_Complete",
        0x4d : "EVENT AMP_Status_Change",
        0x49 : "EVENT AMP_Start_Test",
        0x4a : "EVENT AMP_Test_End",
        0x4b : "EVENT AMP_Receiver_Report",
        0x4e : "EVENT Triggered_Clock_Capture",
        0x4f : "EVENT Synchronization_Train_Complete",
        0x50 : "EVENT Synchronization_Train_Received",
        0x51 : "EVENT Connectionless_Slave_Broadcast_Receive",
        0x52 : "EVENT Connectionless_Slave_Broadcast_Timeout",
        0x53 : "EVENT Truncated_Page_Complete",
        0x54 : "EVENT Slave_Page_Response_Timeout",
        0x55 : "EVENT Connectionless_Slave_Broadcast_Channel_Map_Change",
        0x56 : "EVENT Inquiry_Response_Notification",
        0x57 : "EVENT Authenticated_Payload_Timeout_Expired",
    }


def parse(data):
    """
    Parse HCI event data

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5) - HCI Data Formats
    ** [vol 2] Part E (Section 5.4) - Exchange of HCI-specific information
    ** [vol 2] Part E (Section 7.7) - Events
    ** [vol 2] Part E (Section 7.7.65) - Le Meta Event

    All integer values are stored in "little-endian" order.

    Returns a tuple of (evtcode, length, subevtcode, data) if LE_Meta_Event,
    else (evtcode, length, data)
    """
    evtcode, length = struct.unpack("<BB", data[:2])
    if evtcode != HCI_LE_META_EVENT:
        return evtcode, length, data[2:]
    else:
        subevtcode = struct.unpack("<B", data[2:3])[0]
        length -= 1 # Subtrackt length of SubEvent code
        return evtcode, length, subevtcode, data[3:]


def evt_to_str(evtcode):
    """
    Return a string representing the event code
    """
    return HCI_EVENTS[evtcode]