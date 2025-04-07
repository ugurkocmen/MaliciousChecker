# Malicious Content Checker

A comprehensive web application for analyzing and detecting malicious URLs, IP addresses, and file hashes. The application integrates multiple threat intelligence sources and provides an intuitive interface for security analysis.

## Features

- **Multi-source Threat Intelligence**: Integration with USOM, URLScan.io, AbuseIPDB, and MalwareBazaar
- **Versatile Analysis**: Check URLs, IP addresses, and file hashes
- **Real-time Phishing Detection**: Advanced analysis for phishing detection
- **Email Security Assessment**: Evaluate domain email security configurations (SPF, DMARC, DKIM)
- **YARA Rule Management**: Create, test, and manage YARA rules for malware detection
- **Local Analysis Engine**: Perform offline analysis of suspicious content
- **Threat Intelligence Dashboard**: Visualize trends and patterns in threat data
- **API Integration**: Full-featured API for integration with other security tools

## Installation

1. Clone the repository
2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python app.py
   ```

## Tab Descriptions

### Home Page
The home page displays recent threats detected from various sources including USOM and MalwareBazaar. Each entry shows the timestamp, threat type (URL, IP, Hash), and status. You can click on any entry to view detailed analysis.

### Search/Analysis
The search functionality allows you to analyze:

- **URLs**: Performs comprehensive phishing analysis and checks against URLScan.io to determine if a URL is malicious.
  - Phishing analysis includes domain age, SSL verification, special character detection, and typosquatting checks
  - URLScan.io results provide external verification and screenshots of suspicious websites

- **IP Addresses**: Checks IP addresses against AbuseIPDB to determine reputation.
  - Shows confidence score, country of origin, ISP details
  - Displays abuse reports and usage type
  - Calculates risk level based on multiple factors

- **File Hashes**: Checks file hashes against MalwareBazaar database.
  - Displays file details (name, size, type)
  - Shows hash values (MD5, SHA1, SHA256)
  - Lists associated malware families and tags
  - Provides first/last seen dates

### Recent Threats
Displays the most recent threats detected across all integrated threat intelligence sources. The page provides a chronological view of threats with filtering options and detailed analysis links.

### USOM Threats
Displays the latest threats reported by Turkish National CERT (USOM). This tab shows malicious URLs and domains that are officially blocked or reported in Turkey.

### Malware List
Provides a comprehensive list of recent malware samples from MalwareBazaar, including file names, hashes, types, and associated tags.

### Mail Security
Analyzes domain email security configurations:
- Checks SPF (Sender Policy Framework) records
- Verifies DMARC (Domain-based Message Authentication, Reporting & Conformance) policies
- Tests DKIM (DomainKeys Identified Mail) configurations
- Evaluates MX records
- Provides recommendations for improving email security

### Threat Intelligence
Offers advanced threat intelligence visualization:
- Displays threat type distribution
- Shows confidence score distribution
- Presents trend analysis over time
- Lists recent threats with detailed information

### YARA Rules Management
Allows creation and management of YARA rules for malware detection:
- Create new rules with syntax highlighting
- Test rules for proper compilation
- View existing rules
- Delete outdated rules

### Local Analysis
Performs offline analysis of URLs and file hashes using local databases and engines:
- Checks URLs against locally stored blacklists
- Verifies file hashes against local malware databases
- Provides quick results without external API calls

## API Integration

The application provides a RESTful API for integration with other security tools:

```
GET /api/check/url?value={url}
GET /api/check/ip?value={ip}
GET /api/check/hash?value={hash}
```

Refer to the API documentation for more details on endpoints and response formats.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [URLScan.io](https://urlscan.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [USOM](https://www.usom.gov.tr/) 