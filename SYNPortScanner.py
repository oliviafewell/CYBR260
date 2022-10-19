import sys
import logging
from datetime import datetime
from time import strftime

# all scapy packages
from scapy.config import conf
from scapy.layers.inet import IP, ICMP, TCP, sr1
from scapy.sendrecv import send
from scapy.volatile import RandShort

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Within this try else, try else hierarchy I have the user initiate the ports they would like to scan as well as ensure
# The ports are in a valid range and exit is the user wishes to
try:
    print("You are scanning IP address 10.0.0.1")
    target = "10.0.0.1"
    port_min = input("Enter Minimum Port Number: ")
    port_max = input("Enter Maximum Port Number: ")

    try:
        if 0 <= int(port_min) <= int(port_max) and int(port_max) >= 0:
            pass
        else:
            print("\nThis is an invalid Range of Ports")
            print("\nExiting Program")
            sys.exit(1)
    except Exception:
        print("\nInvalid Range of Ports")
        print("\nExiting program")
        sys.exit(1)
except KeyboardInterrupt:
    print("\nUser Implemented Ctr+C")
    print("\nExiting Program")
    sys.exit(1)

# various global variable used within code
ports = range(int(port_min), int(port_max) + 1)
clock = datetime.now()
rst_ack = 0x14


# Function: hostUp
# Purpose: This checks to see if the host 10.0.0.1 is up before it begins the scan it also has a Try/Except function in
# Purpose(cont.): case the target can not be resolved
# Input: NA
# Output: Tells the user if the target port is up or not
def hostUp(ip):
    conf.verb = 0
    try:
        host_ping = IP(dst=ip) / ICMP()
        print("\nThe Target is up - Scan starting")
        response = sr1(host_ping, timeout=10)
        if response is None:
            return False
        else:
            return True
    except Exception:
        print("\nProgram could not resolve target")
        print("\nClosing program")
        sys.exit(1)


# Function: portScan
# Purpose: Here we are creating our SYNACK packet and comparing the reply to the flag if it returns 0x12 we reply with
# Purpose(cont.): a RSTACK packet and print Open if it does not we know it is closed
# Input: NA
# Output: Confirmation on Open or Closed port
def portScan(port):
    conf.verb = 0
    src_port = RandShort()
    syn_ack_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="S")
    res = sr1(syn_ack_pkt, timeout=0.5)

    rst_pkt = IP(dst=target) / TCP(sport=src_port, dport=port, flags="R")
    send(rst_pkt)

    if res and res.haslayer(TCP) and res.getlayer(TCP).flags == 0x12:
        return True
    elif res and res.haslayer(TCP) and res.getlayer(TCP).flags == 0x14:
        return False


# Function: main
# Purpose: To call portScan and hostUp and print the total time the program too to run
# Input: NA
# Output: To time the program began running and what ports are open and the total time the program took to run
def main():
    conf.verb = 0
    hostUp(target)
    print("Scan is starting at " + strftime("%H:%M:%S"))

    for port in ports:
        status = portScan(port)
        if status is True:
            print("Port " + str(port) + ": Open")

    clock_stop = datetime.now()
    total_time = clock_stop - clock
    print("Your scan is now finished!")
    print("Total duration: " + str(total_time))


main()
