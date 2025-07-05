# 🔒 Endpoint Hardening Scripts

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue.svg)](https://github.com/yourusername/endpointHardening)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-green.svg)](https://docs.microsoft.com/en-us/powershell/)
[![Bash](https://img.shields.io/badge/Bash-4.0+-orange.svg)](https://www.gnu.org/software/bash/)

> **Enterprise-grade endpoint hardening scripts for Windows, Linux, and macOS systems. Implements security best practices and compliance standards to reduce attack surface and enhance system security posture.**

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Controls](#security-controls)
- [Compliance](#compliance)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)
- [Changelog](#changelog)

## 🎯 Overview

This repository provides comprehensive endpoint hardening solutions designed for enterprise environments. The scripts implement security best practices aligned with industry standards such as CIS Benchmarks, NIST Cybersecurity Framework, and Microsoft Security Baselines.

### Key Benefits

- **Cross-Platform Support**: Windows, Linux, and macOS compatibility
- **Industry Standards**: Aligned with CIS, NIST, and vendor security baselines
- **Modular Design**: Easy to customize and extend for specific requirements
- **Comprehensive Logging**: Detailed audit trails for compliance and troubleshooting
- **Idempotent Operations**: Safe to run multiple times without side effects
- **Zero Dependencies**: No external tools or libraries required

## ✨ Features

### 🔧 Windows Hardening (`Endpoint-Hardening.ps1`)

#### Network Security
- Disable legacy protocols (SMBv1, LLMNR, NetBIOS, IPv6)
- Enable and configure Windows Firewall
- Restrict RDP access with NLA and strong encryption
- Disable network discovery and file sharing

#### System Security
- Enforce password complexity and account lockout policies
- Enable BitLocker encryption (where supported)
- Configure User Account Control (UAC)
- Disable guest accounts and unnecessary services
- Enable Secure Boot verification

#### Application Security
- Configure Windows Defender with advanced protections
- Restrict PowerShell script execution
- Disable Windows Script Host
- Configure AppLocker (Enterprise editions)
- Disable browser-based attacks

#### Privacy & Telemetry
- Disable Cortana and consumer experiences
- Disable telemetry and data collection
- Disable Windows Store and OneDrive integration
- Disable Wi-Fi Sense and location services

#### Additional Controls
- Disable autorun and USB storage
- Configure screen lock timeouts
- Disable unnecessary scheduled tasks
- Enable comprehensive auditing
- Restrict local administrator access

### 🐧 Linux/macOS Hardening (`endpoint-hardening.sh`)

#### Network Security
- Configure firewall (UFW, firewalld, or macOS firewall)
- Harden SSH with strong ciphers and access controls
- Disable unused network services
- Enable rate limiting for SSH connections

#### System Security
- Enforce password policies and account restrictions
- Lock system accounts and restrict user privileges
- Enable ASLR and kernel hardening
- Configure filesystem security (/tmp, /var/tmp)
- Enable disk encryption recommendations

#### Service Hardening
- Disable unnecessary services (avahi, cups, bluetooth, etc.)
- Configure logging and audit systems
- Enable automatic security updates
- Restrict USB storage access

#### macOS-Specific Controls
- Disable AirDrop and Siri
- Enable FileVault and Gatekeeper
- Restrict sharing services
- Disable remote Apple events

## 🚀 Quick Start

### Prerequisites

- **Windows**: PowerShell 5.1+ with Administrator privileges
- **Linux**: Bash 4.0+ with root access
- **macOS**: Bash 4.0+ with administrator privileges

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/endpointHardening.git
cd endpointHardening

# Make scripts executable (Linux/macOS only)
chmod +x endpoint-hardening.sh
```

### Basic Usage

#### Windows
```powershell
# Run as Administrator
Set-ExecutionPolicy RemoteSigned -Scope Process
.\Endpoint-Hardening.ps1
```

#### Linux/macOS
```bash
# Run as root/administrator
sudo ./endpoint-hardening.sh
```

## 📦 Installation

### Method 1: Git Clone (Recommended)
```bash
git clone https://github.com/yourusername/endpointHardening.git
cd endpointHardening
```

### Method 2: Download ZIP
1. Click the "Code" button on GitHub
2. Select "Download ZIP"
3. Extract to your desired location

### Method 3: Package Manager (Future)
```bash
# Coming soon: Install via package managers
# Windows: winget install endpointHardening
# Linux: apt install endpoint-hardening
```

## 🔧 Usage

### Windows PowerShell Script

#### Basic Execution
```powershell
# Navigate to script directory
cd "C:\path\to\endpointHardening"

# Set execution policy (if needed)
Set-ExecutionPolicy RemoteSigned -Scope Process

# Run the script
.\Endpoint-Hardening.ps1
```

#### Advanced Options
```powershell
# Run with verbose logging
$VerbosePreference = "Continue"
.\Endpoint-Hardening.ps1

# Run specific functions only
# (Modify script to call specific functions)
```

### Linux/macOS Bash Script

#### Basic Execution
```bash
# Navigate to script directory
cd /path/to/endpointHardening

# Make executable (if needed)
chmod +x endpoint-hardening.sh

# Run with sudo
sudo ./endpoint-hardening.sh
```

#### Advanced Options
```bash
# Run with debug output
sudo bash -x ./endpoint-hardening.sh

# Run specific functions only
# (Modify script to call specific functions)
```

## ⚙️ Configuration

### Customization Options

#### Windows Configuration
```powershell
# Modify these variables in the script
$LogFile = "$PSScriptRoot\Endpoint-Hardening.log"
$PasswordMinLength = 12
$ScreenLockTimeout = 900  # 15 minutes
```

#### Linux/macOS Configuration
```bash
# Modify these variables in the script
LOGFILE="$(pwd)/endpoint-hardening.log"
PASS_MIN_LEN=12
SSH_LOGIN_GRACE_TIME=30
```

### Environment-Specific Customization

#### Server Environment
- Disable all GUI components
- Restrict remote access to specific IPs
- Enable strict logging and monitoring
- Disable unnecessary services

#### Workstation Environment
- Balance security with usability
- Enable user-friendly features
- Configure appropriate screen lock timeouts
- Allow required USB devices

#### Compliance Environment
- Align with specific compliance standards
- Enable additional audit logging
- Configure specific password policies
- Implement required access controls

## 🛡️ Security Controls

### Implemented Controls

| Control Category | Windows | Linux | macOS |
|------------------|---------|-------|-------|
| Network Security | ✅ | ✅ | ✅ |
| Access Control | ✅ | ✅ | ✅ |
| Encryption | ✅ | ✅ | ✅ |
| Logging & Monitoring | ✅ | ✅ | ✅ |
| Application Security | ✅ | ✅ | ✅ |
| Privacy Controls | ✅ | ✅ | ✅ |

### Control Details

#### Network Security Controls
- **Firewall Configuration**: Enable and configure host-based firewalls
- **Protocol Restrictions**: Disable insecure protocols (SMBv1, LLMNR, etc.)
- **Remote Access Hardening**: Secure SSH/RDP configurations
- **Network Discovery**: Disable unnecessary network services

#### Access Control
- **Password Policies**: Enforce strong password requirements
- **Account Management**: Lock system accounts and restrict privileges
- **Authentication**: Configure multi-factor authentication where possible
- **Session Management**: Implement appropriate session timeouts

#### Encryption
- **Disk Encryption**: Enable BitLocker (Windows) or FileVault (macOS)
- **Transport Security**: Enforce TLS/SSL for network communications
- **Key Management**: Secure cryptographic key storage

## 📋 Compliance

### Supported Standards

- **CIS Benchmarks**: Windows, Linux, and macOS security baselines
- **NIST Cybersecurity Framework**: Core security functions
- **Microsoft Security Baselines**: Windows security recommendations
- **ISO 27001**: Information security management
- **PCI DSS**: Payment card industry standards

### Compliance Mapping

| Control ID | Description | Implementation |
|------------|-------------|----------------|
| CIS 1.1 | Disable Guest Account | ✅ Implemented |
| CIS 1.2 | Enforce Password Policy | ✅ Implemented |
| CIS 1.3 | Configure Account Lockout | ✅ Implemented |
| CIS 2.1 | Enable Windows Firewall | ✅ Implemented |
| CIS 2.2 | Disable Unnecessary Services | ✅ Implemented |

## 🔍 Troubleshooting

### Common Issues

#### Windows Issues

**Error: "This script must be run as Administrator"**
```powershell
# Solution: Run PowerShell as Administrator
# Right-click PowerShell → "Run as administrator"
```

**Error: "Execution policy prevents running scripts"**
```powershell
# Solution: Set execution policy
Set-ExecutionPolicy RemoteSigned -Scope Process
```

**Error: "Access denied" for registry modifications**
```powershell
# Solution: Ensure running as Administrator
# Check UAC settings and group policy restrictions
```

#### Linux/macOS Issues

**Error: "Permission denied"**
```bash
# Solution: Run with sudo
sudo ./endpoint-hardening.sh
```

**Error: "Command not found"**
```bash
# Solution: Install required packages
# Ubuntu/Debian: sudo apt update && sudo apt install <package>
# CentOS/RHEL: sudo yum install <package>
```

### Log Analysis

#### Windows Log Location
```
Endpoint-Hardening.log
```

#### Linux/macOS Log Location
```
endpoint-hardening.log
```

#### Log Format
```
2024-01-15 10:30:45 [INFO] Script started as Administrator
2024-01-15 10:30:46 [INFO] SMBv1 disabled successfully
2024-01-15 10:30:47 [ERROR] Failed to enable BitLocker: Not supported
```

### Debug Mode

#### Windows Debug
```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
.\Endpoint-Hardening.ps1
```

#### Linux/macOS Debug
```bash
sudo bash -x ./endpoint-hardening.sh
```

## ⚠️ Security Considerations

### Important Warnings

1. **Administrator Privileges Required**: Scripts modify system-wide settings
2. **Test Environment**: Always test in non-production environment first
3. **Backup Configuration**: Backup system configuration before running
4. **Network Impact**: Some changes may affect network connectivity
5. **Application Compatibility**: Some applications may be affected

### Risk Mitigation

- **Rollback Plan**: Document original settings for potential rollback
- **Gradual Deployment**: Deploy changes incrementally
- **Monitoring**: Monitor system performance after changes
- **Documentation**: Maintain detailed change logs

### Security Best Practices

- **Principle of Least Privilege**: Only grant necessary permissions
- **Defense in Depth**: Combine multiple security controls
- **Regular Updates**: Keep scripts and systems updated
- **Continuous Monitoring**: Monitor for security events

## 🤝 Contributing

We welcome contributions from the security community! Please follow these guidelines:

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Contribution Guidelines

- **Code Quality**: Follow existing code style and patterns
- **Documentation**: Update README and inline comments
- **Testing**: Test on multiple platforms and versions
- **Security**: Ensure changes don't introduce vulnerabilities

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourusername/endpointHardening.git
cd endpointHardening

# Create development branch
git checkout -b development

# Make changes and test
# Submit pull request
```

### Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Follow security best practices
- Maintain professional communication

## 🆘 Support

### Getting Help

- **Documentation**: Check this README and inline comments
- **Issues**: Report bugs and request features via GitHub Issues
- **Discussions**: Join community discussions on GitHub
- **Security**: Report security vulnerabilities privately

### Community Resources

- **Security Forums**: Engage with the security community
- **Conferences**: Present and learn at security conferences
- **Blog Posts**: Share experiences and improvements
- **Training**: Provide training and workshops

## 📝 Changelog

### [Unreleased]
- Initial release
- Cross-platform support
- Comprehensive security controls

### [1.0.0] - 2024-01-15
#### Added
- Windows PowerShell hardening script
- Linux/macOS Bash hardening script
- Comprehensive logging system
- Cross-platform compatibility
- CIS and NIST compliance controls

#### Changed
- Initial release

#### Fixed
- PowerShell variable reference issues
- Execution policy handling
- Administrator privilege checks

---

## 🙏 Acknowledgments

- **CIS Benchmarks**: For security baseline guidance
- **NIST Cybersecurity Framework**: For security control framework
- **Microsoft Security Baselines**: For Windows security recommendations
- **Open Source Community**: For tools and inspiration

---

**⭐ If this project helps you, please give it a star on GitHub!**
