#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

from time import sleep
from threading import Thread

from scapy.all import BOOTP, DHCP, sniff, conf

from dhsession import DHSession

class DHSlave:

    def __init__(self, iface, count, interpacketdelay=0):
        self.iface = iface
        self.count = count
        self.sessions = dict()
        self.ipd = interpacketdelay
        self.listener = Thread(target=self.register_listener)
        self.listener.start()

    def listen_offers(self, pkt):
        mac = pkt[BOOTP].chaddr[:6]
        if pkt[DHCP].options[0] == ('message-type', 2):
            self.sessions[mac].get_offer(pkt)
        if pkt[DHCP].options[0] == ('message-type', 6):
            self.sessions[mac].get_nack(pkt)
        if pkt[DHCP].options[0] == ('message-type', 5):
            self.sessions[mac].get_ack(pkt)

    def start(self):
        sock = conf.L2socket(iface=self.iface)
        # create all sessions
        for _ in range(self.count):
            ses = DHSession(sock=sock)  # opt82="sw1 eth 0/0/1:.707990A978E5"
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
                # wait 5 seconds between retransmits
                sleep(5)
        except KeyboardInterrupt:
            print("DHSlave Interrupting due to ^C")

    def register_listener(self):
        try:
            sniff(iface=self.iface, prn=self.listen_offers, filter="udp and src port 67", store=0)
        except KeyboardInterrupt:
            print("Listener Interrupting due to ^C")


