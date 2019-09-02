import scapy.all as scapy

import argparse

def get_user_input():

    parse_object=argparse.ArgumentParser()

    parse_object.add_argument("-t","--target",dest="ip_address",help="example: -t 10.0.2.1/24")


    user_input = parse_object.parse_args()

    if not user_input.ip_address:

        print("Enter ip address")

    return user_input



def scan_network(ip):

    arp_request_packet = scapy.ARP(pdst=ip)

    broadcast_packet=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    combined_packet=broadcast_packet/arp_request_packet

    answered_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]


    print("IP\t\t\tMac Address\n-----------------------------------------")

    for element in answered_list:

        client_dic={"ip": element[1].psrc, "mac":element}

        print(element[1].psrc+"\t\t"+element[1].hwsrc)


user_ip_address = get_user_input()

scan_network(user_ip_address.ip_address)