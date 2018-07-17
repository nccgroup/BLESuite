Installing
============

The following are installation instructions for the BLESuite Python package.

Prerequisites
-------------

**Supported Operating Systems:**

BLESuite was developed and tested against Debian 9.3. The library may be supported
by other Linux distributions, however support is not currently guaranteed. 


**Note:**
Recent attempts to use BLESuite with Fedora 28 were achieved by installing the
following items:

* dnf install bluez-libs-devel python2-devel python2-sphinx python2-gevent
* follow the rest of the installtion instructions to install the supplied version
  of Scapy and BLESuite

With Fedora 28, there has been one non-repeatable reported issue with BLESuite 
related to a
TypeError that is not present in Debian 9.3 installations when attemtping to handle
an incoming ATT request. 

Fix contributions welcome!

**Required Software**

The following are requirements in order to install and run BLESuite:

* libbluetooth-dev
* libpython-dev
* python-sphinx
* gevent (https://pypi.org/project/gevent/)
* Scapy (https://github.com/secdev/scapy/) (MUST BE INSTALLED FROM THE COPY IN THIS REPOSITORY FOR NOW)
    * This version of Scapy includes several modifications to the bluetooth.py
      layer that supports several new packet types and gracefully closes
      the BluetoothUserSocket. These changes are not currently available
      in Scapy's mainline.
* pycrypto (https://pypi.org/project/pycrypto/)
* pyshark (https://github.com/KimiNewt/pyshark/)
* prettytable (https://pypi.org/project/PrettyTable/)
* sphinx_rtd_theme (https://pypi.org/project/sphinx_rtd_theme/) - For compiling documentation


After installing libbluetooth-dev, libpython-dev, and python-sphinx, run the following to install the remaining Python dependencies:

.. code-block:: bash

    pip install -r requirements.txt

Documentation
--------

From the docs folder, run:

.. code-block:: bash

    make html


Then in docs/_build/html, a full set of documentation and reference guides will be available.


Installing Everything
---------

Run the following command to install the python package:

.. code-block:: bash

    python setup.py install

If you do not want to install the BDADDR Python API or are having issues getting it to install,
comment out the following line in setup.py and re-run the command above:

.. code-block:: python

    ext_modules = [c_ext],

