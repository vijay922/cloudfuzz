# cloudfuzz

## SSL Certificate Fetcher

This script fetches SSL certificate details from a single IP address or a range of IPs defined in CIDR notation. It supports parallel processing to handle large CIDR ranges efficiently and excludes error results from the output.

---

## Features
- Fetches SSL certificate details for a given IP or IP range.
- Supports both single IP (`-i`) and CIDR range (`-cidr`) inputs.
- Multithreaded execution for faster processing.
- Filters out IPs with errors, showing only valid results.

---

## Requirements
- Python 3.6+
- `cryptography` library for handling SSL certificate details.

---

## Installation
1. Clone this repository:
   ```
   git clone https://github.com/yourusername/ssl-certificate-fetcher.git
   cd ssl-certificate-fetcher
   ```

## Usage
# Single IP
Fetch SSL certificate details for a single IP:

```
python ssl_fetcher.py -i 176.34.184.91
```

# CIDR Range
Fetch SSL certificate details for a range of IPs in CIDR notation:
```
python ssl_fetcher.py -cidr <CIDR_RANGE> [-t <THREADS>]
```
-t (optional): Number of threads for parallel processing (default: 10).
Example:

```
python ssl_fetcher.py -cidr 176.34.184.91/24 -t 200
```
