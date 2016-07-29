// -*- mode: c++; coding: utf-8; tab-width: 4 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#include <boost/thread/mutex.hpp>
#include <boost/thread/condition_variable.hpp>
#include <iostream>

class Event {
public:
    Event() : _flag(false) {
    }

    void set() {
		{
			boost::lock_guard<boost::mutex> lock(_mutex);
			_flag = true;
		}

		_cond.notify_all();
    }

    void clear() {
		boost::lock_guard<boost::mutex> lock(_mutex);
		_flag = false;
    }

    bool wait(uint16_t timeout) {
		if (_flag)
			return _flag;

		boost::unique_lock<boost::mutex> lock(_mutex);
		if (timeout >= 0) {
			boost::system_time const ts =
				boost::get_system_time() +
				boost::posix_time::milliseconds(timeout * 1000);

			try {
				_cond.timed_wait(lock, ts);
			} catch(...) {
				std::cout << "ERROR" << std::endl;
				std::cout.flush();
			}
		}
		else {
			while (!_flag)
				_cond.wait(lock);
		}

		return _flag;
    }

private:
    bool _flag;
    boost::mutex _mutex;
    boost::condition_variable _cond;
};
