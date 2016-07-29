

def printDataAndHex(data, handleInData, prefix=""):
    """Print supplied data followed by the hexadecimal equivalent

    :param data: List of data strings to be printed
    :param handleInData: If data supplied contains the source handle sending the data, such as when we read data from a device using a UUID, we need to know to print the handle separate from the handle
    :param prefix: Prefix all printed lines with the supplied string
    :type data: list of strings
    :type handleInData: bool
    :type prefix: str

    """
    ''' old side-by-side print method
    print "Data"
    print "====="
    for i in data:
        chunks = [i[x:x+groupLen] for x in range(0, len(i), groupLen)]
        for chunk in chunks:
            if len(chunk) != groupLen:
                print chunk+(" "*(groupLen-len(chunk)+1)), "||", " ".join("{:02x}".format(ord(c)) for c in chunk)
            else:
                print chunk, "||", " ".join("{:02x}".format(ord(c)) for c in chunk)
    print "====="'''
    print prefix + "Data (Copy/Paste version)"
    print prefix + "=========================="
    if data == -1:
        print prefix + "Invalid Handle/UUID"
        print prefix + "====="
        return
    if data == -2:
        print prefix + "Permission error. Cannot read supplied handle/UUID."
        print prefix + "====="
        return
    for i in data:
        '''chunks = [i[x:x+groupLen] for x in range(0, len(i), groupLen)]
        for chunk in chunks:
            print chunk
        print "-"*(groupLen+1)
        for chunk in chunks:
            print " ".join("{:02x}".format(ord(c)) for c in chunk)'''
        if handleInData:
            #UUID read response packets contain
            #the originating header in the first two bytes
            #handle reverse order when received
            handle = i[:2][::-1]
            i = i[2:]
            if handle is not None:
                print prefix + "Handle:", "".join("{:02x}".format(ord(c)) for c in handle)
            else:
                print prefix + "Handle:"
        print prefix + i
        print prefix + "-" * len(i)
        print prefix + " ". join("{:02x}".format(ord(c)) for c in i)
    print prefix + "====="
