import re
import sys

def extract_strings(file_path):
    """
    Extracts printable ASCII strings of length 4 or more from a binary file.

    Args:
        file_path (str): Path to the binary file.

    Returns:
        list of bytes: Extracted strings from the file.
    """
    with open(file_path, 'rb') as f:
        # Read the entire file into memory
        data = f.read()
    # Find printable ASCII strings of length 4 or more
    return re.findall(b"[ -~]{4,}", data)

def detect_iocs(strings):
    """
    Detects URLs and IPv4 addresses in a list of strings.

    Args:
        strings (list of bytes): List of extracted strings.

    Returns:
        tuple: Two lists containing detected URLs and IP addresses.
    """
    # Regex patterns for URLs and IPv4 addresses
    url_pattern = re.compile(b'https?://[^\s]+')
    ip_pattern = re.compile(
        b'\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])'
        b'(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})\b'
    )

    # Detect URLs and IPs using the compiled regex patterns
    urls = [s for s in strings if url_pattern.search(s)]
    ips = [s for s in strings if ip_pattern.search(s)]
    return urls, ips

if __name__ == "__main__":
    # Check if the file path is provided as a command-line argument
    if len(sys.argv) != 2:
        print("Usage: python extract_iocs.py <file_path>")
        sys.exit(1)

    # Get the file path from the command-line argument
    file_path = sys.argv[1]

    # Extract strings from the file
    try:
        strings = extract_strings(file_path)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    # Detect IOCs from the extracted strings
    urls, ips = detect_iocs(strings)

    # Print the results
    print("URLs:")
    for url in urls:
        print(f"  - {url.decode('utf-8', errors='replace')}")

    print("IPs:")
    for ip in ips:
        print(f"  - {ip.decode('utf-8', errors='replace')}")
