Frequently Asked Questions
============

* **What permissions are needed to run BLESuite?**

    To run BLESuite, you can either use `sudo` or a user with the ability to open sockets on your host.

* **BLESuite isn't running commands I issue, what's going on?**

    Try enabling debugging and digging through the logs output to STDOUT. In some cases it may be that
    the user running the program does not have sufficient privileges to open the socket.