Logging
=======
BLESuite has been written with a logging system that outputs debug messages
that detail many of the reads and writes made to carry out different
actions. This logging may be enabled/disabled by following the methods
described below.



Modules
-------
When importing different modules from BLESuite, logging can be configured
by calling the following code:

.. code-block:: python

    import logging
    logging.basicConfig(level=logging.DEBUG)


By default, logging is set to be ignored if not enabled specifically by the user