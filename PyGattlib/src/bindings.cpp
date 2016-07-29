// -*- mode: c++; coding: utf-8 -*-

// Copyright (C) 2014, Oscar Acena <oscaracena@gmail.com>
// This software is under the terms of Apache License v2 or later.

#include <boost/python.hpp>
#include <boost/python/suite/indexing/map_indexing_suite.hpp>
#include <boost/python/overloads.hpp>
#include <boost/python/raw_function.hpp>
#include <boost/python/to_python_converter.hpp>

#include "gattlib.h"
#include "gattservices.h"
#include "beacon.h"

using namespace boost::python;

class PyGILGuard {
public:
    PyGILGuard() { _state = PyGILState_Ensure(); }
    ~PyGILGuard() { PyGILState_Release(_state); }

private:
    PyGILState_STATE _state;
};

/** to-python convert for std::vector<char> */
struct bytes_vector_to_python_bytes
{
    static PyObject* convert(std::vector<char> const& s)
    {
        return PyBytes_FromStringAndSize(s.data(), s.size());
    }
};

class GATTResponseCb : public GATTResponse {
public:
    GATTResponseCb(PyObject* p) : self(p) {
    }

    // to be called from c++ side
    void on_response(const std::string data) {
        PyGILGuard guard;
        try {
            call_method<void>(self, "on_response", data);
        } catch(error_already_set const&) {
            PyErr_Print();
        }
    }

    // to be called from python side
    static void default_on_response(GATTResponse& self_, const std::string data) {
        self_.GATTResponse::on_response(data);
    }

private:
    PyObject* self;
};

class GATTRequesterCb : public GATTRequester {
public:
    GATTRequesterCb(PyObject* p, std::string address,
            bool do_connect=true, std::string device="hci0") :
        GATTRequester(address, do_connect, device),
        self(p) {
    }

    // to be called from c++ side
    void on_notification(const uint16_t handle, const std::string data) {
        PyGILGuard guard;
        try {
            const std::vector<char> vecdata(data.begin(), data.end());
            call_method<void>(self, "on_notification", handle, vecdata);
        } catch(error_already_set const&) {
            PyErr_Print();
        }
    }

    // to be called from python side
    static void default_on_notification(GATTRequester& self_,
                                        const uint16_t handle,
                                        const std::string data) {
        self_.GATTRequester::on_notification(handle, data);
    }

    // to be called from c++ side
    void on_indication(const uint16_t handle, const std::string data) {
        PyGILGuard guard;
        try {
            const std::vector<char> vecdata(data.begin(), data.end());
            call_method<void>(self, "on_indication", handle, vecdata);
        } catch(error_already_set const&) {
            PyErr_Print();
        }
    }

    // to be called from python side
    static void default_on_indication(GATTRequester& self_,
                                      const uint16_t handle,
                                      const std::string data) {
        self_.GATTRequester::on_indication(handle, data);
    }

private:
    PyObject* self;
};

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(
        start_advertising, BeaconService::start_advertising, 0, 5)

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(
        GATTRequester_discover_characteristics_overloads,
        GATTRequester::discover_characteristics, 0, 3)

BOOST_PYTHON_MEMBER_FUNCTION_OVERLOADS(
        GATTRequester_discover_characteristics_async_overloads,
        GATTRequester::discover_characteristics_async, 1, 4)

BOOST_PYTHON_MODULE(gattlib) {

    to_python_converter<std::vector<char>, bytes_vector_to_python_bytes>();

    register_ptr_to_python<GATTRequester*>();

    class_<GATTRequester, boost::noncopyable, GATTRequesterCb> ("GATTRequester",
            init<std::string, optional<bool, std::string> >())

        .def("connect", boost::python::raw_function(GATTRequester::connect_kwarg,1))
        .def("is_connected", &GATTRequester::is_connected)
        .def("disconnect", &GATTRequester::disconnect)
        .def("read_by_handle", &GATTRequester::read_by_handle)
        .def("read_by_handle_async", &GATTRequester::read_by_handle_async)
        .def("read_by_uuid", &GATTRequester::read_by_uuid)
        .def("read_by_uuid_async", &GATTRequester::read_by_uuid_async)
        .def("write_by_handle", &GATTRequester::write_by_handle)
        .def("write_by_handle_async", &GATTRequester::write_by_handle_async)
        .def("write_cmd_by_handle", &GATTRequester::write_by_handle)
        .def("write_cmd_by_handle_async", &GATTRequester::write_by_handle_async)
        .def("on_notification", &GATTRequesterCb::default_on_notification)
        .def("on_indication", &GATTRequesterCb::default_on_indication)
        .def("discover_primary", &GATTRequester::discover_primary,
                "returns a list with of primary services,"
                " with their handles and UUIDs.")
        .def("discover_primary_async", &GATTRequester::discover_primary_async)
        .def("discover_characteristics",
                &GATTRequester::discover_characteristics,
                GATTRequester_discover_characteristics_overloads())
        .def("discover_characteristics_async",
                &GATTRequester::discover_characteristics_async,
                GATTRequester_discover_characteristics_async_overloads());

    register_ptr_to_python<GATTResponse*>();

    class_<GATTResponse, boost::noncopyable, GATTResponseCb>("GATTResponse")
            .def("received", &GATTResponse::received)
            .def("on_response", &GATTResponseCb::default_on_response);

    class_<DiscoveryService>("DiscoveryService", init<optional<std::string> >())
            .def("discover", &DiscoveryService::discover);

    class_<BeaconService>("BeaconService", init<optional<std::string> >())
            .def("scan", &BeaconService::scan)
            .def("start_advertising", &BeaconService::start_advertising,
                    start_advertising(
                        args("uuid", "major", "minor", "txpower", "interval"),
                        "starts advertising beacon packets"))
            .def("stop_advertising", &BeaconService::stop_advertising);
}
