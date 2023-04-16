import socket, glob

# Define port and ip address
port = 53
ip = '127.0.0.1'

# Establish a UDP socket for communication (UDP message: 512 octets or less)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the server
sock.bind((ip, port))

def load_zones():
    """Load zone files."""
    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    
    return jsonzone

zonedata = load_zones()

def getflags(flags):
    """Get different types of the flags based on the data."""
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    rflags = ''

    # Byte1

    # Query(0) or response(1)
    QR = '1'

    # Type of query
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += str(ord(byte1)&(1<<bit))

    # Authoritative Answer
    AA = '1'

    # Trucation 
    TC = '0'

    # Recursion desired?
    RD = '0'

    # Byte2

    # Recursion Available?
    RA = '0'

    # Reserved for future use
    Z = '000'

    # Response code
    RCODE = '0000'

    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def getquestiondomain(data):
    """Get the domain name as well as the question type."""
    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte 
        y += 1
    
    questiontype = data[y:y+2]
        
    return (domainparts, questiontype)

def getzone(domain):
    global zonedata

    # "domain" is a list
    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    domain, questiontype = getquestiondomain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a '

    zone = getzone(domain)

    return (zone[qt], qt, domain)

def buildquestion(domainname, rectype):
    """Build the question query."""
    qbytes = b''

    # Build question
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])

        for char in part:
            qbytes += ord(char).to_bytes(1, byteorder='big')

    # Build question type        
    if rectype == 'a':
        qbytes += (1).to_bytes(2, byteorder='big')

    # Build question count
    qbytes += (1).to_bytes(2, byteorder='big')

    return qbytes

def rectobytes(domainname, rectype, recttl, recval):

    # DNS compression result
    rbytes = b'\xc0\x0c'

    # TYPE
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1])

    # CLASS
    rbytes = rbytes + bytes([0]) + bytes([1])

    # TTL
    rbytes += int(recttl).to_bytes(4, byteorder='big')

    # For an "a" record
    if rectype == 'a':
        # RDLENGTH
        rbytes = rbytes + bytes([0]) + bytes([4])

        # RDATA
        for part in recval.split('.'):
            rbytes += bytes([int(part)])

    return rbytes

def buildresponse(data):
    """Build response."""
    # The first two byte of the data represent the transaction ID
    # It is used for identifying the sent-back response
    TransactionID = data[:2]
    TID = ''
    for byte in TransactionID:
       TID += hex(byte)[2:]

    # Get the flags
    Flags = getflags(data[2:4])

    # Question count (For practice, every query contains one question)
    QDCOUNT = b'\x00\x01'

    # Answer count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2, byteorder='big')

    # Nameserver count
    NSCOUNT = (0).to_bytes(2, byteorder='big')

    # Additional count
    ARCOUNT = (0).to_bytes(2, byteorder='big')

    dnsheader = TransactionID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT 

    # Create DNS body
    dnsbody = b''

    # Get answer for query
    records, rectype, domainname = getrecs(data[12:])

    # Build the dns question
    dnsquestion = buildquestion(domainname, rectype)

    # Fill the dnsbody
    for record in records:
        dnsbody += rectobytes(domainname, rectype, record["ttl"], record["value"])

    return dnsheader+dnsquestion+dnsbody

# Main loop of the program
while 1:
    # Receive message
    data, addr = sock.recvfrom(512)

    # Build response
    r = buildresponse(data)

    # Respond correspondingly
    sock.sendto(r, addr)
