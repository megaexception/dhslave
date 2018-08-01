#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

from scapy.all import Ether, IP, ICMP, UDP, BOOTP, DHCP, sendp, mac2str, str2mac

from utils import gen_opt82, gen_mac


class DHSession:

    def __init__(self, mac=None, sock=None, iface=None, opt82=None):
        self.mac = mac or gen_mac()
        self.sock = sock
        self.iface = iface
        self.opt82 = opt82
        self.state = "init"
        self.addr = None
        self.options = [("client-id", str2mac(self.mac))]
        self.dhcp_server = None
        if self.opt82:
            self.options.append(("relay_agent_Information", gen_opt82(value=self.opt82)))

    def discover(self):
        pkt = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=self.mac, xid=int.from_bytes(self.mac[2:], 'big'))
        pkt /= DHCP(options=[("message-type", "discover"), *self.options, "end"])
        self.sendp(pkt)
        self.state = "discover"

    def sendp(self, pkt):
        if self.sock:
            self.sock.send(pkt)
        else:
            sendp(pkt, iface=self.iface)

    def get_offer(self, offer):
        self.addr = offer[BOOTP].yiaddr
        self.dhcp_server = offer[BOOTP].siaddr
        print(f"Session {str2mac(self.mac)} got offer for {self.addr} from {self.dhcp_server}")
        for i in offer[DHCP].options:
            if i == 'end':
                break
            if i[0] in ["client-id", "message-type", "relay_agent_Information"]:
                continue
            self.options.append(i)
        self.request()

    def request(self):
        pkt = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src="0.0.0.0", dst="255.255.255.255")
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=self.mac)
        pkt /= DHCP(options=[("message-type", "request"), ("requested_addr", self.addr), *self.options, "end"])
        self.sendp(pkt)
        self.state = "request"

    def get_ack(self, ack):
        print(f"Session {str2mac(self.mac)} got ack for {self.addr}")
        self.state = "ack"

    def get_nack(self, nack):
        print(f"Session {str2mac(self.mac)} got nack for {self.addr}")

    def release(self):
        pkt = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src=self.addr, dst=self.dhcp_server)
        pkt /= UDP(sport=68, dport=67)
        pkt /= BOOTP(chaddr=self.mac)
        pkt /= DHCP(options=[("message-type", "release"), "end"])
        self.sendp(pkt)
        print(f"Session {str2mac(self.mac)} released of {self.addr}")
        self.state = "done"

    def ping(self):
        # print(f"Session {str2mac(self.mac)} running ping from {self.addr} to {self.dhcp_server}")
        pkt = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
        pkt /= IP(src=self.addr, dst=self.dhcp_server)
        pkt /= ICMP()
        self.sendp(pkt)

    def arp(self):
        pkt = Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")
        pkt /= ARP(psrc=self.addr, hwsrc=self.mac, pdst="ff:ff:ff:ff:ff:ff")
        self.sendp(pkt)

    def get_arp(self, arp_req):
        pass

    def get_ping(self, echo):
        pass
