
<p align="center">
  <img src="https://cdn.prod.website-files.com/64e2669792befecb2c6bd088/65ea1483c5e3f90ff5acb460_logo.png" alt="OneVM Logo" width="200"/>
</p>


## Overview

OneVM includes an intelligent security chatbot assistant that enhances the user experience(NEW)
OneVM is a comprehensive container security scanning application designed to identify, analyze, and report vulnerabilities in Docker images and Kubernetes environments. Built with Python and Flask, it provides an intuitive web interface for scanning containers and visualizing security issues.

## Features

### Container Image Scanning
- **Vulnerability Detection**: Scan Docker images for known vulnerabilities using Trivy
- **Severity Classification**: Automatically categorize vulnerabilities by severity (Critical, High, Medium, Low)
- **Detailed Reporting**: Generate comprehensive HTML reports documenting all vulnerabilities
- **Progress Tracking**: Real-time progress bars during scanning operations
- **Context Management**: Leverages the Model Context Protocol (MCP) to maintain state between components

### Kubernetes Integration
- **Cluster Connectivity**: Connect to Kubernetes clusters to discover resources
- **Namespace Scanning**: Scan all container images within a Kubernetes namespace
- **Resource Visualization**: View pods, deployments, and images in each namespace
- **Aggregated Reporting**: See vulnerability summaries across all images in a namespace

### AI-Powered Analysis (with Claude)
- **Intelligent Analysis**: Optional integration with Claude AI for deeper vulnerability insights
- **Remediation Recommendations**: Get specific actions to address security vulnerabilities
- **Security Best Practices**: Receive contextual security advice for your containers
- **Natural Language Explanations**: Technical security information translated into clear explanations

### BOT Features (Claude Powered)
- **Interactive Help**: Get instant answers to questions about container security and application usage
- **AI-Powered Responses**: Uses Claude AI for sophisticated, contextual responses to security questions
- **Security Guidance**: Provides recommendations for addressing vulnerabilities and improving security posture
- **Container Security Knowledge**: Access expert information about container security best practices
- **Context-Aware**: Maintains conversation history to provide more coherent assistance

## Installation

### Prerequisites
- Python 3.9+
- Docker
- Trivy (for vulnerability scanning)
- Kubernetes access (optional, for Kubernetes features)
- Anthropic API key (optional, for Claude integration)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/onevm.git
cd onevm
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install flask kubernetes anthropic
```

4. Install Trivy:
```bash
# Using snap (Ubuntu)
sudo snap install trivy

# Or using apt (Debian/Ubuntu)
sudo apt-get install wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

5. Set environment variables (for Claude integration, optional):
```bash
export ANTHROPIC_API_KEY="your-api-key-here"
```

## Usage

### Running the Application

1. Start the MCP server (in one terminal):
```bash
python src/mcp/server.py
```

2. Start the web application (in another terminal):
```bash
python run_webapp.py
```

3. Access the application at http://localhost:5000

### Scanning Docker Images

1. From the home page, enter a Docker image name (e.g., `ubuntu:latest`, `node:14`, `python:3.9`) in the form
2. Click "Scan Image"
3. The scan progress will be displayed with a progress bar
4. View detailed results when the scan completes
5. Generate a comprehensive HTML report if desired

### Scanning Kubernetes Resources

1. Click on "Kubernetes" in the navigation menu
2. Browse available namespaces in your connected cluster
3. Select a namespace to view its resources (pods, deployments, images)
4. Click "Scan Namespace" to scan all images in that namespace
5. View aggregated vulnerability results across all namespace images

### Using Claude AI Analysis

1. After scanning an image or namespace, click "Analyze with Claude"
2. Claude will process the vulnerability data and provide:
   - A summary of security risks
   - Detailed explanations of serious vulnerabilities
   - Specific remediation recommendations
   - General container security best practices

## Architecture

OneVM is built with a modular architecture:

- **Web Interface**: Flask-based frontend for user interaction
- **MCP Server**: Model Context Protocol server for maintaining state
- **Vulnerability Scanner**: Integrates with Trivy for security scanning
- **Kubernetes Client**: Connects to Kubernetes APIs
- **Claude Analyzer**: Optional AI-powered analysis component

## Project Structure

```
onevm/
├── run_webapp.py           # Main application entry point
├── src/
│   ├── ai/                 # Claude AI integration
│   │   ├── __init__.py
│   │   └── claude_client.py
│   ├── kubernetes/         # Kubernetes integration
│   │   ├── __init__.py
│   │   ├── client.py
│   │   └── scanner.py
│   ├── mcp/                # Model Context Protocol
│   │   ├── __init__.py
│   │   ├── client.py
│   │   └── server.py
│   ├── scanner/            # Vulnerability scanning
│   │   ├── __init__.py
│   │   ├── vulnerability_scanner.py
│   │   └── report_generator.py
│   └── web/                # Web interface
│       ├── __init__.py
│       ├── app.py
│       ├── static/
│       │   ├── css/
│       │   │   └── style.css
│       │   └── img/
│       │       └── onevm-logo.png
│       └── templates/
│           ├── base.html
│           ├── index.html
│           ├── scan_results.html
│           └── ...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Trivy by Aqua Security for vulnerability scanning
- Anthropic's Claude for AI analysis capabilities
- Kubernetes for container orchestration

