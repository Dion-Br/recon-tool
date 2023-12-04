from icmp import send_icmp_request
from portscan import check_port

# Volledige recon tool
def main():
    target = "www.google.com"
    if send_icmp_request(target) is not False:
        # Als target online is verder gaan met recon
        # Port scanner implementeren
        open_ports = check_port(target, [22, 80, 443, 8000])

        if open_ports:
            print(open_ports)
        

if __name__ == "__main__":
    main()
