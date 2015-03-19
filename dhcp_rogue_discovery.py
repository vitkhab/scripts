#!/usr/bin/env python
'''
Author: Vitaly Khabarov <vitkhab@gmail.com>

Dependencies: scapy, dnet

Description: This script scans network for available DHCP servers.

Usage:
    dhcp_rogue_discovery.py [-h] -i dev [-d ip] [-t sec] [-c num]

    Search for rogue DHCP servers.

    optional arguments:
      -h, --help            show this help message and exit
      -i dev, --interface dev
                            Network interface name
      -d ip, --dhcp-server ip
                            server IP address
      -t sec, --timer sec   How often script will send DHCPDISCOVER
      -c num, --count num   How many times script will send DHCPDISCOVER

Examples:
    Monitor (output to console) available DHCP servers on eth0, send requests every 60 seconds
        ./dhcp_rogue_discovery.py -i eth0 -t 60
    Print all DHCP servers once accessible on eth0 (timeout 5 seconds)
        ./dhcp_rogue_discovery.py -i eth0 -t 5 -c 1
    Print all rogue DHCP servers once accessible on eth0 (timeout 5 seconds), 192.168.0.1 is legitimate DHCP server
        ./dhcp_rogue_discovery.py -i eth0 -t 5 -c 1 -d 192.168.0.1
'''

# Suppress Scapy IPv6 Warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import argparse
import threading
from scapy.all import *
from random import Random


class DHCPTester():

    r = Random()
    r.seed()
    running = False

    def __init__(self, nic, server_ip = None, timer = 60, count = None):
        self.nic = nic
        self.timer = timer
        self.server_ip = server_ip
        self.count = count
        fam, self.mac_address = get_if_raw_hwaddr(self.nic)
        self.thread_sniffing = threading.Thread(target=self.start_sniffing)
        self.thread_discover = threading.Thread(target=self.start_discover)
        self.thread_sniffing.daemon = True
        self.thread_discover.daemon = True
        self.thread_sniffing.start()
        self.thread_discover.start()
        self.running = True


    def send_discover(self):
        '''
        Send DHCPDISCOVER packet into the network
        '''
        self.xid = self.r.randint(0, 0xffffffff)

        ethernet = Ether(src = self.mac_address, dst = 'ff:ff:ff:ff:ff:ff', type = 0x800)
        ip = IP(src = '0.0.0.0', dst = '255.255.255.255')
        udp = UDP(sport = 68, dport = 67)
        bootp = BOOTP(chaddr = self.mac_address, ciaddr = '0.0.0.0', flags = 1, op = 1, xid = self.xid)
        dhcp = DHCP(options = [("message-type", "discover"), "end"])
        packet = ethernet / ip / udp / bootp / dhcp

        sendp(packet, iface = self.nic, verbose = 0)


    def get_server_ip(self, packet):
        '''
        Return all 
        '''
        if packet[BOOTP].xid == self.xid \
           and (packet[Ether].src != str2mac(self.mac_address)) \
           and packet[IP].src != self.server_ip:
            return '{} {}'.format(packet[Ether].src, packet[IP].src)


    def start_discover(self):
        if self.count:
            for i in xrange(self.count):
                self.send_discover()
                time.sleep(self.timer)
            self.running = False
        else:
            while True:
                self.send_discover()
                time.sleep(self.timer)

    def start_sniffing(self):
        sniff( prn = self.get_server_ip,
               lfilter = lambda x: self.running,
               filter = "udp and port 67 and port 68",
               iface = self.nic )


def main():
    parser = argparse.ArgumentParser(description='Search for rogue DHCP servers.')
    parser.add_argument( '-i', '--interface', action = 'store', dest = 'nic', metavar="dev",
                         help='Network interface name', required = True)
    parser.add_argument( '-d', '--dhcp-server', action = 'store', dest = 'server_ip', metavar="ip",
                         help='server IP address')
    parser.add_argument( '-t', '--timer', action = 'store', dest = 'timer', metavar="sec",
                         help='How often script will send DHCPDISCOVER', default = 60, type = int)
    parser.add_argument( '-c', '--count', action = 'store', dest = 'count', metavar="num",
                         help='How many times script will send DHCPDISCOVER', type = int)
    args = parser.parse_args()

    tester = DHCPTester(args.nic, args.server_ip, args.timer, args.count)

    while tester.running:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(1)


if __name__ == '__main__':
    main()