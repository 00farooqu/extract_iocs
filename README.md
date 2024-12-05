# Malware IOC Extractor

This script extracts strings from binary files and detects **Indicators of Compromise (IOCs)** such as URLs and IP addresses. It is particularly useful for malware analysis or reverse engineering tasks.

---

## Features

- Extracts ASCII strings (minimum length of 4 characters) from binary files.
- Detects URLs and IPv4 addresses from the extracted strings.
- Prints human-readable results to the console.

---

## Requirements

- Python 3.7 or higher

---

## Installation

1. Clone this repository:
```bash
git clone https://github.com/00farooqu/malware-ioc-extractor.git
cd malware-ioc-extractor
```
## Usage

1. Place the binary file you want to analyse (e.g., malware_sample.exe) in the same directory as the script.
2. Run the script:
```bash
python extract_iocs.py malware_sample.exe
```
3. Results will be displayed in the console, showing detected URLs and IPs.

## Example Output
```plaintext
URLs: ['http://malicious-site.com', 'https://another-malware-site.com']
IPs: ['192.168.1.1', '8.8.8.8']
```
## Contributions

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool is intended for educational and research purposes only. Use it responsibly and ensure you comply with local laws and regulations.
