import scapy.all as scapy

def send_icmp_request(target, timeout=2):
    # ICMP ping maken
    packet = scapy.IP(dst=target, ttl=64) / scapy.ICMP()

    # Ping sturen en op response wachten
    reply = scapy.sr1(packet, timeout=timeout)

    # Repsonse controleren en resultaat versturen
    if reply:
        return f"{target} is bereikbaar: {reply.show}"
    else:
        return f"{target} is onbereikbaar"

def main():
    # IP target instellen (werkt ook met links)
    target_ip = "1.1.1.1"

    # Ping naar target sturen
    send_icmp_request(target_ip)

if __name__ == "__main__":
    main()