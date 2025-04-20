# ReconXtreme

ReconXtreme is a comprehensive web application security reconnaissance and vulnerability scanning tool designed for security professionals, penetration testers, and bug bounty hunters.

## Features

- **Subdomain Enumeration**: Discover subdomains using multiple techniques including DNS bruteforce and certificate transparency logs.
- **Port Scanning**: Identify open ports and services on target hosts.
- **Web Crawling**: Discover endpoints, forms, and content on web applications.
- **Asynchronous Architecture**: High-performance scanning with controlled concurrency.
- **Modular Design**: Easily extensible with additional scanning modules.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/sami-tor/ReconXtreme.git
cd ReconXtreme
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:

```bash
python main.py scan example.com
```

Options:

```
--module, -m              Specific modules to run (subdomain, port_scan, web_crawler)
--output, -o              Output format (json, html, pdf)
--threads, -t             Number of threads for scanning
--timeout                 Request timeout in seconds
--verbose, -v             Enable verbose output
--config, -c              Path to config file
```

Example with options:

```bash
python main.py scan example.com --module subdomain --module port_scan --output json --threads 20 --verbose
```

## Configuration

ReconXtreme can be configured using a YAML or JSON file:

```yaml
general:
  max_threads: 20
  timeout: 30
  output_dir: "results"

modules:
  subdomain_enumeration:
    enabled: true
    bruteforce: true
    wordlist: "path/to/wordlist.txt"
  
  port_scanning:
    enabled: true
    ports: "1-1000,3389,8080-8090"
    scan_type: "connect"
  
  web_crawling:
    enabled: true
    max_depth: 3
    max_urls: 500
    respect_robots: true

api_keys:
  shodan: "your-api-key"
  censys: "your-api-key"
```

## Legal Disclaimer

ReconXtreme is designed for legal security testing only. Users must ensure they have proper authorization before scanning any target. The developers are not responsible for any misuse of this tool.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.