#!/bin/python3

import argparse,psutil,socket,os,sys
import scapy.all as scapy
from colorama import Fore

#colors
GREEN = Fore.GREEN
MAGENTA=Fore.MAGENTA
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW=Fore.YELLOW
BLUE = Fore.BLUE
WHITE=Fore.WHITE
RESET = Fore.RESET

class ScanInterface:
    def __init__(self,interface):
        self.interface = interface
        
    def checkRoot():
        return os.geteuid()
        
    def get_ip_subnet_of_interface(self):
        try:
            addresses = psutil.net_if_addrs()[self.interface]
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    ip_address = addr.address
                    ip_with_0_at_end = ip_address[:ip_address.rindex('.')]+".0"
                    ip_range = ip_with_0_at_end+"/24"
                    return ip_range
            return None
        except KeyError:
            return None
        
    def scan_subnet(self,subnet):
        arp_header = scapy.ARP(pdst = subnet)
        ether_header = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_packet = ether_header/arp_header
        answered_list= scapy.srp(arp_request_packet,timeout=1,verbose=False)[0]
        networks =[]
        
        for elements in answered_list:
            if(len(networks)==0 and elements[1].pdst != "0.0.0.0"):
                networks.append({"ip":elements[1].pdst,"mac":elements[1].hwdst,"you":True})
            networks.append({"ip":elements[1].psrc,"mac":elements[1].hwsrc,"you":False})
        
        if(len(networks)>0):
            print(f"\n{GREEN}---------------------------------------------------------")    
            print(f"{GREEN}IP\t\t\t  MAC Address{RESET}")
            print(f"{GREEN}---------------------------------------------------------")
            for network in networks:
                print(f"{YELLOW}{network['ip']}{RESET}\t\t{WHITE}{network['mac']}{RESET}\t{MAGENTA}{f'<< [YOU]' if network['you']==True else ''} {RESET}")
            
            print(f"{GREEN}---------------------------------------------------------\n")
        else:
            print("[X] No Networks Found!!")
	



parser = argparse.ArgumentParser(description="scan network with interface")
parser.add_argument("-i","--interface",type=str,default=None,help="Interface to scan")
parser.add_argument("-r","--range",type=str,default=None,help="subnet to scan")

args = parser.parse_args()

interface = args.interface
subnet = args.range

if interface == None and subnet == None:
    print(f"{RED}[X]Interface or Subnet Required , use -i or -r to specify interface or subnet{RESET}")
else:
    
    
    
    interfaceOrSubnetScan = ScanInterface(interface)
    
    #check root permission
    if interfaceOrSubnetScan.checkRoot != 0:
        print(f"{RED}[X] Root Permission Required, Run as Rooot {RESET}")
        sys.exit(0)
    
    print(f"""{GREEN}
█▀ █▀▀ ▄▀█ █▄ █
▄█ █▄▄ █▀█ █ ▀█
---------------
█▄ █ █▀▀ ▀█▀ █ █ █ █▀█ █▀█ █▄▀
█ ▀█ ██▄  █  ▀▄▀▄▀ █▄█ █▀▄ █ █
      github.com/sundaesploits{RESET}""")
    
    
    if interface!=None:
        ip_subnet= interfaceOrSubnetScan.get_ip_subnet_of_interface()
    else:
        ip_subnet = subnet
    
    
    
    print(f"\nSubnet : {YELLOW} {ip_subnet} {RESET}")
    if ip_subnet==None:
        print(f"{RED}Interface not Found{RESET}")
    else:
         interfaceOrSubnetScan.scan_subnet(ip_subnet)
        
        



    
