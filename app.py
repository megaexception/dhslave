#!/usr/bin/env python3
# -*- coding: utf-8 *-
"""
"""

from optparse import OptionParser

from dhslave import DHSlave


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-c", "--count", help="Number of DHCP sessions to create", type="int", default=5)
    parser.add_option("-i", "--interface", help="interface to use", type="str", default="eth0")
    parser.add_option("-d", "--delay", help="interpacket delay", type="float", default="0.01")
    (options, args) = parser.parse_args()
    slave = DHSlave(options.interface, options.count, options.delay)
    slave.start()
