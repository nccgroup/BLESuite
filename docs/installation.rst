Installation
============

The following are installation instruction for the BLESuite Python package.

Prerequisites
-------------

The following are requirements in order to use BLESuite:

* Bluez bluetooth stack
* libbluetooth-dev and libpython-dev
* Python library PyGattlib (https://bitbucket.org/OscarAcena/pygattlib)
  The version included in this project is a fork of PyGattlib
  that contains additional fixes that have not yet been implemented
  in the mainline of PyGattlib.



Python Package
--------------

Run the following command to install the python package:

.. code-block:: bash

    cd PyGattlib
    sudo python setup.py install
    cd ../
    sudo python setup.py install

