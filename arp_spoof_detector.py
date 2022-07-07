import scapy.all as scapy
import optparse

def get_arguments():
    parser=optparse.OptionParser()
    parser.add_option("-i","--interface",dest="interface",help="-i eth0")
    
    (options,argument) = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please enter an interface")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] Arp spoof detected !")
        except IndexError:
            pass


try:
    options=get_arguments()
    interface=options.interface
    sniff(interface)

except KeyboardInterrupt:
    print("\n [-] Quitting...\n")
