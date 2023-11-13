from icmp import send_icmp_request
from portscan import check_port

# Volledige recon tool
def main():
    target = "www.google.com"
    if send_icmp_request(target) is not False:
        # Als target online is verder gaan met recon
        # Port scanner implementeren
        check_port(target, 80)
        check_port(target, 443)
        check_port(target, 8000)
        check_port(target, 22)
        

if __name__ == "__main__":
    main()
