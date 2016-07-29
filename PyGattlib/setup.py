#!/usr/bin/python
# -*- mode: python; coding: utf-8 -*-

import sys
import subprocess
from setuptools import setup, Extension

extension_modules = list()

if sys.platform.startswith('linux'):
    glib_headers = subprocess.check_output(
        "pkg-config --cflags glib-2.0".split()).decode('utf-8')
    glib_headers = glib_headers.strip().split("-I")
    glib_headers = [x.strip() for x in glib_headers if x]

    glib_libs = subprocess.check_output(
        "pkg-config --libs glib-2.0".split()).decode('utf-8')
    glib_libs = glib_libs.strip().split("-l")
    glib_libs = [x.strip() for x in glib_libs if x]

    if sys.version_info.major == 3:
        boost_libs = ["boost_python-py34"]
    else:
        boost_libs = ["boost_python"]
    extension_modules = [
        Extension(
            'gattlib',
            ['src/gattservices.cpp',
             'src/beacon.cpp',
             'src/bindings.cpp',
             'src/gattlib.cpp',
             'src/bluez/lib/uuid.c',
             'src/bluez/attrib/gatt.c',
             'src/bluez/attrib/gattrib.c',
             'src/bluez/attrib/utils.c',
             'src/bluez/attrib/att.c',
             'src/bluez/src/shared/crypto.c',
             'src/bluez/src/log.c',
             'src/bluez/btio/btio.c'],

            libraries=glib_libs + boost_libs + ["boost_thread", "bluetooth"],
            include_dirs=glib_headers + ['src/bluez'],
            define_macros=[('VERSION', '"5.25"')]

        )
    ]
else:
    raise OSError("Not supported OS")


setup(
    name='gattlib',
    version="0.20150805",
    description="Library to access Bluetooth LE devices",
    author="Oscar Acena",
    author_email="oscar.acena@gmail.com",
    url="https://bitbucket.org/OscarAcena/pygattlib",
    ext_modules=extension_modules,
)
