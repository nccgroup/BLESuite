// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

extern "C" {
#include "lib/uuid.h"
}

#include <exception>
#include <iostream>

#include "beacon.h"


#define EIR_FLAGS                   0x01
#define EIR_NAME_SHORT              0x08
#define EIR_NAME_COMPLETE           0x09
#define EIR_MANUFACTURE_SPECIFIC    0xFF


#define LE_META_EVENT 0x0
#define EVT_LE_ADVERTISING_REPORT 0x02
#define BEACON_LE_ADVERTISING_LEN 45
#define BEACON_COMPANY_ID 0x004c
#define BEACON_TYPE 0x02
#define BEACON_DATA_LEN 0x15

typedef struct {
    uint16_t company_id;
    uint8_t type;
    uint8_t data_len;
    uint128_t uuid;
    uint16_t major;
    uint16_t minor;
    uint8_t power;
    int8_t rssi;
} beacon_adv;


BeaconService::BeaconService(const std::string device)
        : DiscoveryService(device) {}


void
BeaconService::process_input(unsigned char* buffer, int size,
		boost::python::dict & ret) {
	if(size != BEACON_LE_ADVERTISING_LEN) return;

	unsigned char* ptr = buffer + HCI_EVENT_HDR_SIZE + 1;
	evt_le_meta_event* meta = (evt_le_meta_event*) ptr;

	if (meta->subevent != EVT_LE_ADVERTISING_REPORT
	        || (uint8_t)buffer[BLE_EVENT_TYPE] != LE_META_EVENT) {
		return;
	}

    le_advertising_info* info = (le_advertising_info*) (meta->data + 1);
	beacon_adv* beacon_info = (beacon_adv*) (info->data + 5);

	if(beacon_info->company_id != BEACON_COMPANY_ID
			|| beacon_info->type != BEACON_TYPE
			|| beacon_info->data_len != BEACON_DATA_LEN) {
		return;
	}

	char addr[18];
	ba2str(&info->bdaddr, addr);
	boost::python::list data;

	//uuid bytes to string conversion
	char uuid[MAX_LEN_UUID_STR + 1];
	uuid[MAX_LEN_UUID_STR] = '\0';
	bt_uuid_t btuuid;
	bt_uuid128_create(&btuuid, beacon_info->uuid);
	bt_uuid_to_string(&btuuid, uuid, sizeof(uuid));

	data.append(uuid);
	data.append(beacon_info->major);
	data.append(beacon_info->minor);
	data.append(beacon_info->power);
	data.append(beacon_info->rssi);
	ret[addr] = data;
}


boost::python::dict
BeaconService::scan(int timeout) {
	boost::python::dict retval;

	enable_scan_mode();
	get_advertisements(timeout, retval);
	disable_scan_mode();

	return retval;
}

#define MAJOR_MINOR_LIMIT 65535

void
BeaconService::start_advertising(const std::string uuid, int major, int minor,
        int txpower, int interval) {

    bt_uuid_t btuuid;
    int ret = bt_string_to_uuid(&btuuid, uuid.c_str());
    if (ret < 0) {
        throw std::runtime_error("Incorrect uuid format");
    }
    if(!(0 < major && major <= MAJOR_MINOR_LIMIT)) {
        throw std::runtime_error("Incorrect major value(must be: 1 to 65535)");
    }
    if(!(0 < minor && minor <= MAJOR_MINOR_LIMIT)) {
        throw std::runtime_error("Incorrect minor value(must be: 1 to 65535)");
    }
    if(!(-40 < txpower && txpower <= 4)) {
        throw std::runtime_error("Incorrect txpower value(must be: -40 to 4)");
    }

    le_set_advertising_parameters_cp adv_params_cp;
    memset(&adv_params_cp, 0, sizeof(adv_params_cp));
    adv_params_cp.min_interval = htobs(interval);
    adv_params_cp.max_interval = htobs(interval);
    adv_params_cp.chan_map = 7;

    uint8_t status;
    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
    rq.cparam = &adv_params_cp;
    rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    ret = hci_send_req(_device_desc, &rq, 1000);
    if (ret < 0) {
        throw std::runtime_error("Can't send hci request");
    }

    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));
    advertise_cp.enable = 0x01;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
    rq.cparam = &advertise_cp;
    rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    ret = hci_send_req(_device_desc, &rq, 1000);
    if (ret < 0) {
        throw std::runtime_error("Can't send hci request");
    }

    le_set_advertising_data_cp adv_data_cp;
    memset(&adv_data_cp, 0, sizeof(adv_data_cp));

    uint8_t segment_length = 1;
    adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(EIR_FLAGS); segment_length++;
    adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(0x1A); segment_length++;
    adv_data_cp.data[adv_data_cp.length] = htobs(segment_length - 1);

    adv_data_cp.length += segment_length;

    segment_length = 1;
    adv_data_cp.data[adv_data_cp.length + segment_length] = htobs(EIR_MANUFACTURE_SPECIFIC); segment_length++;

    beacon_adv * beacon_data = (beacon_adv *)(&adv_data_cp.data[adv_data_cp.length + segment_length]);
    beacon_data->company_id = htobs(BEACON_COMPANY_ID);
    beacon_data->type = htobs(BEACON_TYPE);
    beacon_data->data_len = htobs(BEACON_DATA_LEN);

    beacon_data->uuid = btuuid.value.u128;
    beacon_data->major = htobs(major);
    beacon_data->minor = htobs(minor);
    beacon_data->power = htobs(uint8_t(txpower));

    adv_data_cp.data[adv_data_cp.length] = htobs(segment_length - 1 + sizeof(beacon_adv) - 1);
    adv_data_cp.length += adv_data_cp.data[adv_data_cp.length] + 1;

    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
    rq.cparam = &adv_data_cp;
    rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    ret = hci_send_req(_device_desc, &rq, 1000);
    if(ret < 0) {
        throw std::runtime_error("Can't send hci request");
    }

    if (status) {
        throw std::runtime_error("LE set advertise enable on returned status");
    }
}

void
BeaconService::stop_advertising() {

    le_set_advertise_enable_cp advertise_cp;
    memset(&advertise_cp, 0, sizeof(advertise_cp));

    uint8_t status;

    struct hci_request rq;
    memset(&rq, 0, sizeof(rq));
    rq.ogf = OGF_LE_CTL;
    rq.ocf = OCF_LE_SET_ADVERTISE_ENABLE;
    rq.cparam = &advertise_cp;
    rq.clen = LE_SET_ADVERTISE_ENABLE_CP_SIZE;
    rq.rparam = &status;
    rq.rlen = 1;

    int ret = hci_send_req(_device_desc, &rq, 1000);
    if (ret < 0) {
        throw std::runtime_error("Can't set advertise mode");
    }

    if (status) {
        throw std::runtime_error("LE set advertise enable on returned status");
    }

}
