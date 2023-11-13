import socket
import os
from scapy.layers.inet import IP, ICMP
from scapy.all import *

def send_icmp_request(target, timeout=2):
    # Create an ICMP packet (ping request)
    packet = IP(dst=target, ttl=64) / ICMP()

    # Send the packet and wait for a response
    reply = sr1(packet, timeout=timeout)

    # Check if a response was received
    if reply:
        # Print information about the response
        print(f"Target {target} is reachable")
        return(reply.show())
    else:
        print(f"Target {target} is unreachable")
        return False

def main():
    # Set the target IP address
    target_ip = "1.1.1.1"

    # Send ICMP request to the target
    send_icmp_request(target_ip)

if __name__ == "__main__":
    main()