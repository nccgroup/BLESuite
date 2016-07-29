// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#ifndef _BEACON_H_
#define _BEACON_H_

#include "gattservices.h"


class BeaconService : public DiscoveryService {
public:
    BeaconService(const std::string device="hci0");
	boost::python::dict scan(int timeout);
	void start_advertising(
	        const std::string uuid="11111111-2222-3333-4444-555555555555",
	        int major=1, int minor=1,
	        int txpower=1, int interval=200);
    void stop_advertising();

protected:
	void process_input(unsigned char* buffer, int size,
			boost::python::dict & ret);

};

#endif // _BEACON_H_
