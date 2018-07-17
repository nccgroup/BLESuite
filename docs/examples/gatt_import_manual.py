from blesuite.connection_manager import BLEConnectionManager
import blesuite.pybt.gatt as PyBTGATT


with BLEConnectionManager(0, "peripheral") as connection_manager:

    # Retrieve GATTServer instance
    gatt_server = connection_manager.get_gatt_server()

    # Generate primary service
    service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("2124"))

    # Add service to server
    gatt_server.add_service(service_1)

    # generate characteristic in service1
    char1 = service_1.generate_and_add_characteristic("testValue", PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                      PyBTGATT.UUID("2124"),
                                                      PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                      PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                      PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)

    # add user description descriptor to characteristic
    char1.generate_and_add_user_description_descriptor("Characteristic 1")

    # generate another service
    service_2 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("000AA000-0BB0-10C0-80A0-00805F9B34FB"))

    # add service to server
    gatt_server.add_service(service_2)

    # generate a characteristic for this service
    char2 = service_2.generate_and_add_characteristic("testValue2", PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                      PyBTGATT.UUID("000AA000-0BB0-10C0-80A0-00805F999999"),
                                                      PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                      PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                      PyBTGATT.ATT_SECURITY_MODE_ENCRYPTION_NO_AUTHENTICATION, False)


    char2.generate_and_add_user_description_descriptor("Characteristic 2")

    # refresh attribute database to include all attributes generated from above GATT entities
    gatt_server.refresh_database()

    gatt_server.debug_print_db()