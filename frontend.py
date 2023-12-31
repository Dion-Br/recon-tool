import streamlit as st
from icmp import send_icmp_request
from portscan import check_port, identify_service_on_open_ports
from sitescan import SSLCertificateMonitor, LinkExtractor, find_sql_injections, analyze_http_headers
from jsonhandler import delete_ip_from_json, add_ip_to_json, read_all_ips_from_json
from dnstool import domain_reputation_check, perform_dns_lookup

# Streamlit pagina
def main():
    st.set_page_config(layout="wide")
    col1, col2 = st.columns([1,2])

    with col1:
        targets = read_all_ips_from_json()

        # Target input
        st.title("Toevoegen")
        target = st.text_input("Voer een IP Adres of website in:")
        if st.button("Toevoegen"):
            add_ip_to_json(target)
            st.rerun()

        st.title("IP Adressen")
        if not targets:
            st.write("Er zijn geen IP adressen ingegeven.")
        else:
            for t in targets:
                delete_button = st.button(f"{t}", key=f"delete_{t}", help=f"Verwijder {t}")
                if delete_button:
                    delete_ip_from_json(t)
                    st.rerun()
        
    with col2:
        st.title("Network Utilities App")

        for target in targets:
            st.header(f"Section for {target}")

            # Ping naar target
            if st.button(f"Send ICMP Request for {target}"):
                st.write(f"Running ICMP Request for {target}...")
                output = send_icmp_request(target)
                st.code(f"{output}")

            # Open poorten en service op target
            if st.button(f"Check Open Ports for {target}"):
                st.write(f"Checking Open Ports for {target}...")
                open_ports = check_port(target)
                st.write(f"Open Ports for {target}: {open_ports}")
                st.write(f"Identifying Service on Open Ports for {target}...")
                st.write(identify_service_on_open_ports(target, open_ports))

            # Certificates op webserver
            if st.button(f"Check certificates for {target}"):
                st.write("Checking certificate validity")
                sitescanner = SSLCertificateMonitor(target)
                st.code(sitescanner.check_certificate_expiration())

            # HTTP headers controleren of zwaktes
            if st.button(f"Analyze HTTP Headers for {target}"):
                headers, security_issues = analyze_http_headers(target_url=f"https://{target}")

                # Display headers
                st.subheader("HTTP Headers:")
                st.write(headers)

                # Display security issues
                st.subheader("Security Issues:")
                if security_issues:
                    for issue in security_issues:
                        st.warning(issue)
                else:
                    st.success("No security issues found.")

            # Controleren op sql injectie
            if st.button(f"Scan SQL Injections for {target}"):
                vulnerabilities = find_sql_injections(target_url=f"https://{target}")

                if vulnerabilities:
                    st.success("Scan complete. Vulnerabilities found:")
                    for vuln in vulnerabilities:
                        st.write(vuln)
                else:
                    st.info("No vulnerabilities found.")

            # Links uit webserver halen
            if st.button(f"Extract links on website for {target}"):
                st.write("Extracting links")
                links = LinkExtractor(target_url=f"https://{target}")
                st.code(links.scan_for_links())

            # Dns lookup tool implementeren
            if st.button(f"Check DNS and GeoIP for {target}"):
                dns_results = perform_dns_lookup(target)
                if not dns_results:
                    st.write("No results found.")
                else:
                    for result in dns_results:
                        st.write(result)

                reputation_results = domain_reputation_check(target)
                st.write("Domain Reputation Check results:")
                for result in reputation_results:
                    st.write(result)


if __name__ == "__main__":
    main()