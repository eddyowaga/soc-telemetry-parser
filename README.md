# SOC Telemetry Parser Labs

A lightweight, high-performance Python framework designed to automate the ingestion, parsing, and analysis of raw system authentication logs. This tool mimics core Security Operations Center (SOC) SIEM capabilities by isolating access anomalies, tracking Indicators of Compromise (IoCs), and highlighting potential brute-force or unauthorized access vectors.

## Features
- **Multi-Source Ingestion:** Supports raw Linux authentication logs (`auth.log`) and structured security events.
- **Regex Extraction Engine:** Efficiently extracts timestamps, source IPs, usernames, and authentication statuses.
- **Anomaly Detection Logic:** Automatically flags potential brute-force attacks based on customizable threshold limits (e.g., X failed attempts within a time window).
- **Structured Telemetry Output:** Generates clean JSON summaries and human-readable security alerts for triage.

## Architecture & Data Flow
1. **Ingest:** Reads raw, unstructured telemetry files line-by-line to minimize memory footprint.
2. **Parse:** Utilizes optimized regular expressions to extract structured security fields.
3. **Analyze:** Evaluates logs against specific rule matrices (e.g., tracking unique failed logins per IP).
4. **Report:** Outputs an actionable summary flagging high-risk indicators.

## Getting Started

### Prerequisites
- Python 3.8 or higher

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_GITHUB_USERNAME/soc-telemetry-parser.git](https://github.com/YOUR_GITHUB_USERNAME/soc-telemetry-parser.git)
   cd soc-telemetry-parser