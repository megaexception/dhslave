# DHCP Slave

DHCP session generator.
emulates a number of random clients with different MAC addresses, which attempt to acquire IP address via DHCP, and then periodicaly generate ICMP pings and ARP.

# Installation

pip install https://github.com/megaexception/dhslave

# Usage

```
Usage: dhslave [options]

Options:
  -h, --help            show this help message and exit
  -c COUNT, --count=COUNT
                        Number of DHCP sessions to create
  -i INTERFACE, --interface=INTERFACE
                        interface to use
  -d DELAY, --delay=DELAY
                        interpacket delay
  --opt82=OPT82         value of DHCP option 82 (circuit-id)
  --release             release on exit
```
