import scapy.all as scapy
import psutil,socket

class ScanInterface:
    def __init__(self,interface)->None:
        self.interface = interface

    def get_ip_address_of_interface(self):
        try:
            addresses = psutil.net_if_addrs()[self.interface]
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    ip_address = addr.address
                    ip_with_0_at_end = ip_address[:ip_address.rindex('.')]+".0"
                    ip_range = ip_with_0_at_end+"/24"
                    return ip_range
        except KeyError:
            return "NOTFOUND"

    def scan(self,subnet):
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
            print("\n-------------------------------------------------------")    
            print(f"IP\t\t\t  MAC Address")
            print("-------------------------------------------------------")
            for network in networks:
                print(f"{network['ip']}\t\t{network['mac']}\t{f'<< [YOU]' if network['you']==True else ''}")
            print("\n\n")
        else:
            print("[X] No Networks Found!!")



scanner = ScanInterface("wlan0")

if(scanner.get_ip_address_of_interface()!="NOTFOUND"):
    subnet=scanner.get_ip_address_of_interface()
    scanner.scan(subnet)
else:
    print("Ip address not found")
