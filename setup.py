# -*- coding: utf-8 -*-


"""setup.py: distutils.core setup control."""

import re
from distutils.core import setup, Extension


with open("README", "rb") as f:
    long_descr = f.read().decode("utf-8")

#grab version from bleSuite/bleSuite.py
version = re.search(
    '^__version__\s*=\s*"(.*)"',
    open('bleSuite/__init__.py').read(),
    re.M
    ).group(1)

setup(
    name = "BLESuite",
    packages = ['bleSuite', 'bleSuite.entities', 'bleSuite.utils'],
    #uncomment if you would like to try to install the modified version
    #of bdaddr
    #ext_modules = [Extension("bdaddr", sources=["tools/bdaddr.c", "tools/oui.c"],  libraries=["bluetooth"])],
    version = version,
    description = "Python library for communicating with and testing Bluetooth LE devices.",
    #long_description = long_descr,
    author = "Taylor Trabun",
    #url = "TBD",
    author_email = "taylor.trabun@nccgroup.trust"

    )
