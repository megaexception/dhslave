#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

from time import sleep
from threading import Thread

from scapy.all import ARP, Ether, IP, ICMP, UDP, BOOTP, DHCP, sniff, conf

from dhsession import DHSession


class DHSlave:
    FILTER = "(udp and src port 67) or icmp or arp"

    def __init__(self, iface, count, interpacketdelay=0, opt82=None, release_on_exit=False):
        self.release_on_exit = release_on_exit
        self.iface = iface
        self.count = count
        self.sessions = dict()
        self.ipd = interpacketdelay
        self.opt82 = opt82
        self.listener = Thread(target=self.register_listener)
        self.listener.start()

    def listen_offers(self, pkt):
        if pkt.haslayer(UDP):
            mac = pkt[BOOTP].chaddr[:6]
            if pkt[DHCP].options[0] == ('message-type', 2):
                self.sessions[mac].get_offer(pkt)
            if pkt[DHCP].options[0] == ('message-type', 6):
                self.sessions[mac].get_nack(pkt)
            if pkt[DHCP].options[0] == ('message-type', 5):
                self.sessions[mac].get_ack(pkt)
        elif pkt.haslayer(ARP):
            mac = pkt[Ether].dst
            if mac in self.sessions:
                print(f"Received arp for {mac}")
        elif pkt.haslayer(ICMP):
            mac = pkt[Ether].dst
            if mac in self.sessions:
                print(f"Received icmp for {mac}")

    def start(self):
        sock = conf.L2socket(iface=self.iface)
        # create all sessions
        for _ in range(self.count):
            ses = DHSession(sock=sock, opt82=self.opt82)
            self.sessions[ses.mac[:6]] = ses
        print(f"Created {len(self.sessions)} sessions")
        # handle retransmits
        try:
            while True:
                print(".", end='')
                for ses in self.sessions.values():
                    # if still waiting for offer, retransmit
                    if ses.state in ["discover", "init"]:
                        ses.discover()
                        sleep(self.ipd)
                    if ses.state in ["request"]:
                        ses.request()
                        sleep(self.ipd)
                    if ses.state in ["ack"]:
                        ses.ping()
                        sleep(self.ipd)
                # wait 5 seconds between retransmits
                sleep(5)
        except KeyboardInterrupt:
            print("DHSlave Interrupting due to ^C")
            if self.release_on_exit:
                print("Releasing all sessions")
                for ses in self.sessions.values():
                    if ses.state in ["ack", "release"]:
                        ses.release()

    def register_listener(self):
        try:
            sniff(iface=self.iface, prn=self.listen_offers, filter=self.FILTER, store=0)
        except KeyboardInterrupt:
            print("Listener Interrupting due to ^C")
