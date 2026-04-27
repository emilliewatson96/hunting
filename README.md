# 🔒 autorecon - Authorized Security Assessment Tool

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0+-orange.svg)](https://www.gnu.org/software/bash/)

> **⚠️ AUTHORIZED USE ONLY**: This tool is designed exclusively for authorized defensive security assessments. Unauthorized scanning of systems you do not own or have explicit written permission to test is **illegal and unethical**.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Output Structure](#output-structure)
- [Stages](#stages)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Ethical Guidelines](#ethical-guidelines)
- [License](#license)

---

## 🎯 Overview

`autorecon` is a production-ready, modular reconnaissance orchestration script for authorized security assessments. It automates the collection and analysis of open-source intelligence (OSINT) about target domains through a structured, multi-stage pipeline.

### Key Design Principles

- **Safety First**: Built-in allowlist enforcement, rate limiting, and user confirmation
- **Correctness Over Speed**: Prioritizes accurate, deduplicated results over raw scanning throughput
- **Resumability**: Checkpoint-based execution allows resuming interrupted scans
- **Modularity**: Each stage is independent and can be run separately
- **Audit Trail**: Comprehensive logging for compliance and troubleshooting

---

## ✨ Features

### 🔐 Safety & Compliance
- ✅ Target allowlist enforcement
- ✅ Explicit user confirmation before scanning
- ✅ Rate-limited scanning to minimize impact
- ✅ Comprehensive audit logging
- ✅ "AUTHORIZED USE ONLY" headers in all outputs

### 🛠 Technical Capabilities
- ✅ **6-Stage Reconnaissance Pipeline**:
  1. Subdomain Enumeration (passive sources)
  2. Port Scanning (top 1000 ports)
  3. HTTP Probing (tech detection, status codes)
  4. URL Crawling (JavaScript extraction)
  5. Secret Scanning (sensitive patterns)
  6. Vulnerability Scanning (Nuclei integration)

- ✅ **Tool Integration**:
  - ProjectDiscovery suite (subfinder, dnsx, naabu, httpx, tlsx, katana, nuclei)
  - Community tools (assetfinder, findomain, amass, gospider, gf)

- ✅ **Smart Resource Management**:
  - Adaptive concurrency based on system resources
  - Memory-aware thread allocation
  - Configurable rate limits

- ✅ **Robust Error Handling**:
  - `set -euo pipefail` for strict error checking
  - Per-stage error isolation (`|| true` where appropriate)
  - Structured logging with timestamps

---

## 📦 Prerequisites

### System Requirements
- **OS**: Linux (Kali, Parrot, Ubuntu, Debian recommended)
- **CPU**: 2+ cores (4+ recommended)
- **RAM**: 2GB minimum (8GB+ recommended)
- **Disk**: 1GB free space for tools + output
- **Network**: Stable internet connection

### Required Tools
The installer (`install_deps.sh`) will automatically install:

| Tool | Purpose |
|------|---------|
| subfinder | Subdomain enumeration |
| assetfinder | Subdomain discovery |
| findomain | Fast subdomain finder |
| amass | OWASP mapping project (passive) |
| dnsx | DNS resolution toolkit |
| naabu | Port scanning |
| httpx | HTTP probing |
| tlsx | TLS fingerprinting |
| katana | Web crawling |
| gospider | Spider/crawler |
| nuclei | Vulnerability scanner |
| gf | Pattern matching wrapper |
| jq | JSON processor |

---

## 🚀 Installation

### Quick Start

```bash
# 1. Clone or download the repository
cd /path/to/autorecon

# 2. Make scripts executable
chmod +x *.sh

# 3. Install dependencies (requires sudo)
./install_deps.sh

# 4. Setup configuration
cp config.example.yaml config.yaml
nano config.yaml  # Edit as needed

# 5. Add your authorized targets
echo "example.com" > targets.txt
nano targets.txt  # Add all authorized targets
```

### Manual Installation

If you prefer manual installation:

```bash
# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install system packages (Debian/Ubuntu)
sudo apt update
sudo apt install -y jq curl wget git dnsutils

# Setup resolvers
echo -e "8.8.8.8\n1.1.1.1\n9.9.9.9" > resolvers.txt
```

---

## 📖 Usage

### Basic Syntax

```bash
./autorecon.sh [OPTIONS]
```

### Options

| Option | Description |
|--------|-------------|
| `-t, --target DOMAIN` | Target domain (required) |
| `-a, --allowlist FILE` | Path to allowlist file |
| `-c, --config FILE` | Path to config file |
| `-s, --stage N` | Run specific stage only (1-6) |
| `--dry-run` | Validate without executing |
| `--resume` | Resume from checkpoint |
| `-v, --verbose` | Enable debug logging |
| `-h, --help` | Show help message |

### Common Workflows

#### 1. Validate Configuration (Recommended First Step)

```bash
./autorecon.sh --target example.com \
               --allowlist targets.txt \
               --dry-run
```

#### 2. Full Assessment

```bash
./autorecon.sh --target example.com \
               --allowlist targets.txt
```

#### 3. Run Specific Stage

```bash
# Only subdomain enumeration
./autorecon.sh --target example.com --stage 1

# Only port scanning
./autorecon.sh --target example.com --stage 2
```

#### 4. Resume Interrupted Scan

```bash
./autorecon.sh --target example.com --resume
```

#### 5. Verbose Mode

```bash
./autorecon.sh --target example.com --verbose
```

---

## ⚙️ Configuration

Edit `config.yaml` to customize behavior:

```yaml
# Rate limiting
rate_limit: 100          # Requests per second
thread_count: 10         # Concurrent threads
timeout: 30              # Request timeout (seconds)

# Output
output_dir: ./recon_output

# DNS resolvers
resolvers: ./resolvers.txt

# Tool-specific settings
nuclei_severity: "low,medium,high,critical"
katana_depth: 3
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_FILE` | Path to config file | `./config.yaml` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

---

## 📁 Output Structure

After running an assessment, results are organized as follows:

```
recon_<domain>_<timestamp>/
├── config/
│   ├── config.yaml          # Runtime config snapshot
│   └── targets.txt          # Validated target list
├── subdomains/
│   ├── raw/                 # Per-tool outputs
│   ├── all_subdomains.txt   # Deduped passive results
│   ├── resolved.txt         # dnsx output with IPs
│   └── live_hosts.txt       # Final resolved host list
├── ports/
│   ├── ports.json           # naabu JSON output
│   └── open_ports.txt       # host:port list
├── http/
│   ├── http_results.jsonl   # httpx + tlsx JSON
│   └── live_urls.txt        # Extracted URLs
├── urls/
│   ├── all_urls.txt         # Crawled + extracted URLs
│   └── js_files.txt         # JavaScript endpoints
├── secrets/
│   ├── gf_sensitive.txt     # Sensitive pattern matches
│   ├── trufflehog.json      # TruffleHog results
│   └── gitleaks.json        # GitLeaks results
├── vulns/
│   ├── nuclei_results.jsonl # Nuclei findings
│   └── nuclei_errors.log    # Nuclei errors
├── logs/
│   └── recon.log            # Unified execution log
└── REPORT.md                # Auto-generated summary
```

---

## 🔄 Stages

### Stage 1: Subdomain Enumeration
- **Tools**: subfinder, assetfinder, findomain, amass (passive), ctfr
- **Output**: `subdomains/all_subdomains.txt`, `subdomains/resolved.txt`
- **Duration**: ~2-5 minutes per domain

### Stage 2: Port Scanning
- **Tools**: naabu
- **Ports**: Top 1000 + common ports
- **Output**: `ports/ports.json`, `ports/open_ports.txt`
- **Duration**: ~5-15 minutes depending on host count

### Stage 3: HTTP Probing
- **Tools**: httpx, tlsx
- **Features**: Status codes, titles, tech detection, TLS fingerprinting
- **Output**: `http/http_results.jsonl`, `http/live_urls.txt`
- **Duration**: ~3-10 minutes

### Stage 4: URL Crawling
- **Tools**: katana, gospider
- **Depth**: 3 levels (configurable)
- **Output**: `urls/all_urls.txt`, `urls/js_files.txt`
- **Duration**: ~5-20 minutes

### Stage 5: Secret Scanning
- **Tools**: gf patterns
- **Patterns**: API keys, AWS credentials, private keys, etc.
- **Output**: `secrets/gf_sensitive.txt`
- **Duration**: ~1-3 minutes

### Stage 6: Vulnerability Scanning
- **Tools**: nuclei
- **Severity**: Low, Medium, High, Critical
- **Output**: `vulns/nuclei_results.jsonl`
- **Duration**: ~10-30 minutes

---

## 📝 Examples

### Example 1: Complete Workflow

```bash
# Setup
./install_deps.sh
cp config.example.yaml config.yaml
echo "target.com" >> targets.txt

# Validate
./autorecon.sh -t target.com -a targets.txt --dry-run

# Execute
./autorecon.sh -t target.com -a targets.txt

# Review results
cat recon/target.com_*/REPORT.md
jq . recon/target.com_*/vulns/nuclei_results.jsonl | head -50
```

### Example 2: Quick Subdomain Discovery

```bash
./autorecon.sh -t target.com -a targets.txt -s 1
cat recon/target.com_*/subdomains/all_subdomains.txt
```

### Example 3: Focused Vulnerability Scan

```bash
# First run stages 1-3 to get live hosts
./autorecon.sh -t target.com -a targets.txt -s 1
./autorecon.sh -t target.com -a targets.txt -s 2
./autorecon.sh -t target.com -a targets.txt -s 3

# Then run vulnerability scan only
./autorecon.sh -t target.com -a targets.txt -s 6
```

---

## 🔧 Troubleshooting

### Common Issues

#### "Target not in allowlist"
```bash
# Add your target to targets.txt
echo "your-target.com" >> targets.txt
```

#### "Missing required tools"
```bash
# Re-run the installer
./install_deps.sh

# Or check which tools are missing
./autorecon.sh -t example.com -a targets.txt --dry-run
```

#### "Permission denied"
```bash
# Make scripts executable
chmod +x autorecon.sh install_deps.sh
```

#### "Out of memory"
```bash
# Reduce thread count in config.yaml
thread_count: 5

# Or reduce rate limit
rate_limit: 50
```

#### "Stage failed but others completed"
```bash
# Resume from last checkpoint
./autorecon.sh -t target.com -a targets.txt --resume

# Or run specific failed stage
./autorecon.sh -t target.com -a targets.txt -s <stage_number>
```

### Log Files

Check `recon/<target>_<timestamp>/logs/recon.log` for detailed execution logs.

---

## ⚖️ Ethical Guidelines

### ✅ DO:
- Obtain **written authorization** before scanning any target
- Respect rate limits to avoid service disruption
- Use results responsibly for defensive purposes
- Maintain confidentiality of findings
- Comply with all applicable laws and regulations

### ❌ DON'T:
- Scan systems you don't own or have explicit permission to test
- Use aggressive rate limits that could cause DoS
- Share findings without authorization
- Use for illegal activities or unauthorized penetration testing
- Ignore legal boundaries or terms of service

### Legal Disclaimer

This tool is provided for **educational and authorized defensive security purposes only**. The developers assume no liability for misuse. By using this tool, you acknowledge:

1. You have obtained proper authorization for all scanning activities
2. You understand and accept full responsibility for your actions
3. You will comply with all applicable local, state, national, and international laws
4. You will not use this tool for malicious purposes

---

## 🤝 Contributing

Contributions are welcome! Please ensure all submissions:
- Follow the existing code style
- Include appropriate documentation
- Maintain safety and ethical safeguards
- Pass shellcheck validation

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for excellent security tools
- [TomNomNom](https://github.com/tomnomnom) for useful recon utilities
- The offensive security community for inspiration and best practices

---

## 📬 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review troubleshooting guide

---

**Remember**: With great power comes great responsibility. Use this tool ethically and legally. 🔐
