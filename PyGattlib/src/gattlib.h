// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#ifndef _MIBANDA_GATTLIB_H_
#define _MIBANDA_GATTLIB_H_

#define MAX_WAIT_FOR_PACKET 15 // seconds

#include <boost/python/list.hpp>
#include <boost/python/tuple.hpp>
#include <boost/python/dict.hpp>
#include <string>
#include <stdint.h>
#include <glib.h>

extern "C" {
#include "lib/uuid.h"
#include "attrib/att.h"
#include "attrib/gattrib.h"
#include "attrib/gatt.h"
#include "attrib/utils.h"
}

#include "event.hpp"

class IOService {
public:
	IOService(bool run);
	void start();
	void operator()();
};

class GATTResponse {
public:
	GATTResponse();
	virtual ~GATTResponse() {};

	virtual void on_response(const std::string data);
	virtual void on_response(boost::python::object data);
	boost::python::list received();
	bool wait(uint16_t timeout);
	void notify(uint8_t status);

private:
	uint8_t _status;
	boost::python::list _data;
	Event _event;
};

void connect_cb(GIOChannel* channel, GError* err, gpointer user_data);

class GATTRequester {
public:
	GATTRequester(std::string address,
			bool do_connect=true, std::string device="hci0");
	virtual ~GATTRequester();

	virtual void on_notification(const uint16_t handle, const std::string data);
	virtual void on_indication(const uint16_t handle, const std::string data);

	void connect(bool wait=false, std::string channel_type="public",
			std::string security_level="low", int psm=0, int mtu=0);
	static boost::python::object connect_kwarg(boost::python::tuple args, boost::python::dict kwargs);
	bool is_connected();
	void disconnect();
	void read_by_handle_async(uint16_t handle, GATTResponse* response);
	boost::python::list read_by_handle(uint16_t handle);
	void read_by_uuid_async(std::string uuid, GATTResponse* response);
	boost::python::list read_by_uuid(std::string uuid);
	void write_by_handle_async(uint16_t handle, std::string data, GATTResponse* response);
    boost::python::list write_by_handle(uint16_t handle, std::string data);
  
	void write_cmd_by_handle_async(uint16_t handle, std::string data, GATTResponse* response);
    boost::python::list write_cmd_by_handle(uint16_t handle, std::string data);

	friend void connect_cb(GIOChannel*, GError*, gpointer);
	friend gboolean disconnect_cb(GIOChannel* channel, GIOCondition cond, gpointer userp);
	friend void events_handler(const uint8_t* data, uint16_t size, gpointer userp);

	boost::python::list discover_primary();
	void discover_primary_async(GATTResponse* response);
	boost::python::list discover_characteristics(int start = 0x0001, int end = 0xffff, std::string uuid = "");
	void discover_characteristics_async(GATTResponse* response, int start = 0x0001, int end = 0xffff, std::string uuid = "");
private:
	void check_channel();
	void check_connected();

    enum State {
        STATE_DISCONNECTED,
        STATE_CONNECTING,
        STATE_CONNECTED,
        STATE_ERROR_CONNECTING
    } _state;

	std::string _device;
	std::string _address;
	int _hci_socket;
	GIOChannel* _channel;
	GAttrib* _attrib;
};

#endif // _MIBANDA_GATTLIB_H_
