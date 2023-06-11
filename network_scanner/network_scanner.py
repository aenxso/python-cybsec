#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP range for scanning.")
    options, arguments = parser.parse_args()
    if not options.target:
        parser.error("[-] Please enter a target IP range, use --help for more info")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = [] #init empty dictionary, to be filled in for loop
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n-----------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

target_ip_range = get_arguments()
scan_result = scan(target_ip_range.target)
print_result(scan_result)

