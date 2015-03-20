#!/usr/bin/env python
'''
Author: Vitaly Khabarov <vitkhab@gmail.com>

Dependencies: scapy, dpkt, pcap
    pip install scapy
    pip install dpkt
    pip install http://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz

    May be needed: dnet
    pip install https://libdnet.googlecode.com/files/libdnet-1.12.tgz    

Description: This script scans network for available DHCP servers.

Usage:
    dhcp_rogue_discovery.py [-h] -i dev [-d ip [ip ...]] [-t sec] [-c num]

    Search for rogue DHCP servers.

    optional arguments:
      -h, --help            show this help message and exit
      -i dev, --interface dev
                            Network interface name
      -d ip [ip ...], --dhcp-server ip [ip ...]
                            server IP address
      -t sec, --timer sec   How often script will send DHCPDISCOVER
      -c num, --count num   How many times script will send DHCPDISCOVER

Examples:
    Monitor (output to console) available DHCP servers on eth0, send requests every 60 seconds
        ./dhcp_rogue_discovery.py -i eth0 -t 60

    Print all DHCP servers once accessible on eth0 (timeout 5 seconds)
        ./dhcp_rogue_discovery.py -i eth0 -t 5 -c 1

    Print all rogue DHCP servers once accessible on eth0 (timeout 5 seconds).
    192.168.0.1 and 192.168.0.2 are legitimate DHCP servers
        ./dhcp_rogue_discovery.py -i eth0 -t 5 -c 1 -d 192.168.0.1 192.168.0.2

    Check for rogue DHCP servers every 5 minutes through cron. Change path to script, legitimate dhcp server IP
    and email address and place thease lines to your crontab.
    Be aware of how you put multiline command into your crontab, if you unsure just make it oneliner.
        */5 * * * * root s=$(/path/to/dhcp_rogue_discovery.py -i eth0 -t 2 -c 1 -d 192.168.0.1); \
                         test -n "$s" && echo "$s" | mail -s "Rogue DHCP servers found" root@example.com
'''

# Suppress Scapy IPv6 Warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import argparse
import threading
import pcap
import dpkt
from scapy.all import *
from random import Random


class DHCPTester():

    r = Random()
    r.seed()
    running = False

    def __init__(self, nic, server_ip = None, timer = 60, count = None):
        self.nic = nic
        self.timer = timer
        if server_ip:
            self.server_ip = server_ip
        else:
            self.server_ip = []
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


    def get_server_address(self, pktlen, packet, timestamp):
        '''
        If legitimate DHCP server IP is set, script returns MAC and IP addresses of rogue DHCP servers.
        Otherwise it returns MAC and IP addresses of all discovered DHCP servers.
        '''
        if not packet:
            return

        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        udp = ip.data
        if struct.unpack(">L", udp.data[4:8])[0] == self.xid \
           and eth.src != self.mac_address \
           and socket.inet_ntoa(ip.src) not in self.server_ip:
            print '{} {}'.format(str2mac(eth.src), socket.inet_ntoa(ip.src))


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
        p = pcap.pcapObject()
        p.open_live(self.nic, 1600, 0, 100)
        p.setfilter('udp and port 67 and port 68', 0, 0)
        while True:
            p.dispatch(1, self.get_server_address)


def main():
    parser = argparse.ArgumentParser(description='Search for rogue DHCP servers.')
    parser.add_argument( '-i', '--interface', action = 'store', dest = 'nic', metavar="dev",
                         help='Network interface name', required = True)
    parser.add_argument( '-d', '--dhcp-server', action = 'store', dest = 'server_ip', metavar="ip",
                         help='server IP address', nargs = "+")
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