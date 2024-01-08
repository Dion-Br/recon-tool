import dns.resolver
import requests

# DNS tool
def perform_dns_lookup(domain):
    try:
        answers_a = dns.resolver.resolve(domain, 'A')
        answers_mx = dns.resolver.resolve(domain, 'MX')
        answers_txt = dns.resolver.resolve(domain, 'TXT')
        answers_ns = dns.resolver.resolve(domain, 'NS')
        answers_soa = dns.resolver.resolve(domain, 'SOA')

        a_records = [f"A Record: {str(r)}" for r in answers_a]
        mx_records = [f"MX Record: {r.exchange} (Priority: {r.preference})" for r in answers_mx]
        txt_records = [f"TXT Record: {str(r)}" for r in answers_txt]
        ns_records = [f"NS Record: {str(r)}" for r in answers_ns]
        soa_records = [f"SOA Record: {str(r)}" for r in answers_soa]

        return a_records + mx_records + txt_records + ns_records + soa_records

    except dns.resolver.NXDOMAIN:
        return ["Domain not found"]

def domain_reputation_check(domain):
    # Ipinfo ophalen
    try:
        ip_info = requests.get(f"http://ipinfo.io/{domain}/json").json()
        return [f"IP Geolocation: {ip_info}"]

    except requests.RequestException:
        return ["Vul een correct IP adres in"]

def main():
    domain = "google.com"
    dns_results = perform_dns_lookup(domain)
    for result in dns_results:
        print(result)

if __name__ == "__main__":
    main()