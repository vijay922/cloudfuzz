import socket
import ssl
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_certificate_details(ip):
    try:
        # Retrieve the raw certificate
        cert_pem = ssl.get_server_certificate((ip, 443), timeout=5)  # Timeout for each connection
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Extract certificate details
        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        organization = (
            cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
            if cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            else "N/A"
        )

        # Subject Alternative Names
        try:
            san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = san_extension.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san_list = []

        return {
            "IP Address": ip,
            "Common Name": common_name,
            "Issuer": issuer,
            "Organization": organization,
            "Subject Alternative DNS Name": ", ".join(san_list),
        }
    except ssl.SSLError:
        return None
    except socket.timeout:
        return None
    except Exception:
        return None


def process_ip_list(file_path, max_threads=10):
    try:
        with open(file_path, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        
        valid_results = []

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_threads) as executor:
            future_to_ip = {executor.submit(get_certificate_details, ip): ip for ip in ips}

            for future in as_completed(future_to_ip):
                try:
                    details = future.result()
                    if details:  # Only include valid results
                        valid_results.append(
                            f"{details.get('IP Address')}, Common Name: {details.get('Common Name')}, "
                            f"Issuer: {details.get('Issuer')}, Organization: {details.get('Organization')}, "
                            f"Subject Alternative DNS Name: {details.get('Subject Alternative DNS Name')}"
                        )
                except Exception:
                    continue
        return valid_results
    except FileNotFoundError:
        return [f"Error: File '{file_path}' not found"]
    except Exception as e:
        return [f"Error processing file '{file_path}': {e}"]


def process_ip_range(cidr, max_threads=10):
    try:
        ip_range = ipaddress.ip_network(cidr, strict=False)
        valid_results = []

        # Use ThreadPoolExecutor for parallel processing
        with ThreadPoolExecutor(max_threads) as executor:
            future_to_ip = {executor.submit(get_certificate_details, str(ip)): ip for ip in ip_range}

            for future in as_completed(future_to_ip):
                try:
                    details = future.result()
                    if details:  # Only include valid results
                        valid_results.append(
                            f"{details.get('IP Address')}, Common Name: {details.get('Common Name')}, "
                            f"Issuer: {details.get('Issuer')}, Organization: {details.get('Organization')}, "
                            f"Subject Alternative DNS Name: {details.get('Subject Alternative DNS Name')}"
                        )
                except Exception:
                    continue
        return valid_results
    except ValueError as e:
        return [f"Error: Invalid CIDR range '{cidr}': {e}"]


def main():
    parser = argparse.ArgumentParser(description="Fetch SSL Certificate details from an IP, CIDR range, or a file of IPs.")
    parser.add_argument("-i", "--ip", help="IP address of the server")
    parser.add_argument("-cidr", help="CIDR range of IP addresses")
    parser.add_argument("-ips", help="File containing a list of IP addresses")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for parallel processing")
    args = parser.parse_args()

    if args.ip:
        details = get_certificate_details(args.ip)
        if details:
            output = (
                f"{details.get('IP Address')}, Common Name: {details.get('Common Name')}, "
                f"Issuer: {details.get('Issuer')}, Organization: {details.get('Organization')}, "
                f"Subject Alternative DNS Name: {details.get('Subject Alternative DNS Name')}"
            )
            print(output)
    elif args.cidr:
        results = process_ip_range(args.cidr, args.threads)
        for result in results:
            print(result)
    elif args.ips:
        results = process_ip_list(args.ips, args.threads)
        for result in results:
            print(result)
    else:
        print("Error: One of --ip, --cidr, or --ips arguments is required.")
        parser.print_help()


if __name__ == "__main__":
    main()
