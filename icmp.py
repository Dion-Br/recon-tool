import scapy.all as scapy

def send_icmp_request(target, timeout=2):
    # ICMP ping maken
    packet = scapy.IP(dst=target, ttl=64) / scapy.ICMP()

    # Ping sturen en op response wachten
    reply = scapy.sr1(packet, timeout=timeout)

    # Repsonse controleren en log
    if reply:
        print(f"Target {target} is reachable")
        return(reply.show())
    else:
        print(f"Target {target} is unreachable")
        return False

def main():
    # IP target instellen (werkt ook met links)
    target_ip = "1.1.1.1"

    # Ping naar target sturen
    send_icmp_request(target_ip)

if __name__ == "__main__":
    main()