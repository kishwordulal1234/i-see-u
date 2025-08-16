# 🎯 I See U Toolkit

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macos-lightgrey.svg)]()
[![Metasploit](https://img.shields.io/badge/metasploit-required-red.svg)]()

> **An advanced payload generation and injection toolkit for ethical hackers and penetration testers**

I See U Toolkit is a modern recreation of `mahadev_v1` with enhanced payload generation, APK injection capabilities, and multiple user interfaces. Built for stealth, speed, and simplicity across multiple platforms.

---

## 🚀 Features

### 🔥 **Core Capabilities**
- **Multi-Platform Payload Generation**: Windows, Linux, Android, macOS, iOS
- **Advanced APK Injection**: Support for Android 10-15 with stealth techniques
- **Multiple Interface Options**: CLI, XP-Style GUI, Modern GUI
- **Automatic Terminal Management**: Smart terminal detection and launching
- **Configuration Management**: Save/load presets for different environments

### 💉 **Payload Types**
- Traditional msfvenom payloads with custom encoding
- Download-and-execute "fetch" payloads  
- Multi-format generation (EXE, APK, ELF, BIN, RAW)
- Smali injection for Android applications
- Custom templates and encoding iterations

### 🎯 **APK Injection Features**
- **Android Version Compatibility**: Optimized for Android 10-15
- **Stealth Installation**: Inject into legitimate applications
- **Automatic Signing**: APK signing and zipaligning
- **Permission Patching**: Dynamic manifest modification
- **High Success Rate**: 95% success on Android 10-11, 65-80% on newer versions

---

## 📊 Interface Comparison

| Feature | CLI Version | XP-Style GUI | Modern GUI |
|---------|-------------|--------------|------------|
| **Ease of Use** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Visual Appeal** | ⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **System Resources** | Minimal | Low | Moderate |
| **Automation Support** | ✅ Full | ✅ Limited | ✅ Full |
| **Beginner Friendly** | ❌ | ✅ | ✅ |
| **Terminal Required** | ✅ | ❌ | ❌ |
| **Real-time Monitoring** | ✅ | ✅ | ✅ Advanced |

---

## 🛠 Installation Guide

### 📋 **Prerequisites**

#### **System Requirements**
```bash
- Python 3.7+
- Metasploit Framework
- Java Development Kit (OpenJDK 11+)
- Android Development Tools
```

#### **Supported Operating Systems**
- ✅ **Kali Linux** (Recommended)
- ✅ **Ubuntu/Debian** 
- ✅ **Fedora/CentOS/RHEL**
- ⚠️ **Windows** (via WSL)
- ⚠️ **macOS** (Limited support)

---

### 🐧 **Linux Installation (Recommended)**

#### **Kali Linux (One-liner)**
```bash
# Quick install for Kali Linux
curl -fsSL https://raw.githubusercontent.com/kishwordulal1234/i-see-u/main/install.sh | bash
```

#### **Manual Installation (All Linux Distros)**

**1. Update System & Install Dependencies**
```bash
# Debian/Ubuntu/Kali
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip git metasploit-framework \
    apktool zipalign openjdk-11-jdk openjdk-11-jre-headless \
    python3-tk python3-dev build-essential

# Fedora/CentOS/RHEL
sudo dnf update -y
sudo dnf install -y python3 python3-pip git java-11-openjdk \
    java-11-openjdk-devel python3-tkinter
```

**2. Install Metasploit Framework (if not pre-installed)**
```bash
# For systems without Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**3. Install Android Tools**
```bash
# Install Android SDK tools (if not available via package manager)
wget https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip
unzip sdk-tools-linux-4333796.zip -d ~/android-sdk
export PATH=$PATH:~/android-sdk/tools/bin:~/android-sdk/platform-tools
echo 'export PATH=$PATH:~/android-sdk/tools/bin:~/android-sdk/platform-tools' >> ~/.bashrc
```

**4. Clone Repository & Setup**
```bash
git clone https://github.com/kishwordulal1234/i-see-u.git
cd i-see-u
chmod +x *.py
pip3 install -r requirements.txt
```

---

### 🪟 **Windows Installation (WSL)**

**1. Install WSL2 & Ubuntu**
```powershell
# Run in PowerShell as Administrator
wsl --install -d Ubuntu
wsl --set-default-version 2
```

**2. Setup Ubuntu Environment**
```bash
# Inside WSL Ubuntu
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip git openjdk-11-jdk python3-tk

# Install Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall && ./msfinstall
```

**3. Clone & Configure**
```bash
git clone https://github.com/kishwordulal1234/i-see-u.git
cd i-see-u
pip3 install -r requirements.txt
chmod +x *.py
```

---

### 🍎 **macOS Installation**

**1. Install Dependencies**
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install requirements
brew install python@3.11 openjdk@11 git
brew install --cask metasploit

# Install Android tools
brew install --cask android-platform-tools
```

**2. Setup Project**
```bash
git clone https://github.com/kishwordulal1234/i-see-u.git
cd i-see-u
pip3 install -r requirements.txt
chmod +x *.py
```

---

## 🎮 **Usage Guide**

### 🖥️ **CLI Version**
```bash
# Basic CLI usage
python3 iseeu_toolkit.py

# With specific parameters
python3 iseeu_toolkit.py --lhost 192.168.1.100 --lport 4444 --platform windows
```

### 🎨 **XP-Style GUI (iseeu-xp-version.py)**
```bash
# Launch XP-style interface
python3 iseeu-xp-version.py

# Features:
# - Windows XP themed interface
# - Simple drag-and-drop APK injection
# - One-click payload generation
# - Built-in listener management
```

### ✨ **Modern GUI (iseeu-morden-gui.py)**
```bash
# Launch modern interface
python3 iseeu-morden-gui.py

# Features:
# - Modern dark/light theme
# - Advanced configuration options
# - Real-time progress monitoring
# - Integrated terminal output
# - Batch processing capabilities
```

---

## 📱 **Android Compatibility Matrix**

| Android Version | Standalone APK | Injected APK | Success Rate | Recommended Method |
|-----------------|---------------|--------------|--------------|-------------------|
| **Android 10-11** | ✅ Excellent | ✅ Excellent | 95% | Both methods work well |
| **Android 12-13** | ✅ Good | ⚠️ Moderate | 80% | Use injected APK method |
| **Android 14-15** | ❌ Poor | ✅ Good | 65% | **Injected APK only** |

### 🎯 **Best Practices for APK Injection**
```bash
# 1. Use legitimate applications as base
./iseeu-morden-gui.py --inject --base-apk legitimate_app.apk

# 2. Target older Android versions when possible
./iseeu-toolkit.py --android-target 11

# 3. Use custom templates for better evasion
./iseeu-toolkit.py --template custom_template.txt
```

---

## ⚙️ **Configuration**

### 🔧 **Environment Setup**
```bash
# Set default LHOST (your IP)
export ISEEU_LHOST="192.168.1.100"

# Set default LPORT
export ISEEU_LPORT="4444"

# Set Android SDK path (if custom)
export ANDROID_HOME="$HOME/android-sdk"
```

### 📁 **Configuration Files**
```bash
configs/
├── default.json          # Default configuration
├── kali.json             # Kali Linux optimized
├── windows.json          # Windows/WSL settings  
├── stealth.json          # High evasion settings
└── android_targets.json  # Android-specific configs
```

### 🎛️ **Custom Configuration Example**
```json
{
  "lhost": "192.168.1.100",
  "lport": 4444,
  "encoder": "x86/shikata_ga_nai",
  "iterations": 3,
  "format": "exe",
  "platform": "windows",
  "android_target": 11,
  "stealth_mode": true,
  "auto_listener": true
}
```

---

## 🚨 **Troubleshooting**

### ❌ **Common Issues & Solutions**

#### **APKTool Not Found**
```bash
# Solution 1: Install via package manager
sudo apt install apktool

# Solution 2: Manual installation
wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
sudo cp apktool_2.7.0.jar /usr/local/bin/apktool.jar
sudo cp apktool /usr/local/bin/
sudo chmod +x /usr/local/bin/apktool
```

#### **Java Issues**
```bash
# Check Java installation
java -version
javac -version

# Set JAVA_HOME if needed
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
echo 'export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64' >> ~/.bashrc
```

#### **Metasploit Not Starting**
```bash
# Initialize Metasploit database
sudo msfdb init

# Start PostgreSQL (if needed)
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Update Metasploit
msfupdate
```

#### **GUI Not Launching**
```bash
# Install GUI dependencies
sudo apt install python3-tk

# For WSL, install VcXsrv or similar X server
# For headless systems, use CLI version
```

### 🔍 **Debug Mode**
```bash
# Enable verbose logging
python3 iseeu-toolkit.py --debug

# Check system compatibility
python3 iseeu-toolkit.py --check-deps

# Generate compatibility report
python3 iseeu-toolkit.py --system-info
```

---

## 🔐 **Security & Legal Notice**

### ⚖️ **Legal Disclaimer**
```
⚠️  IMPORTANT LEGAL NOTICE:

This tool is designed for authorized penetration testing, 
security research, and educational purposes ONLY.

✅ Authorized Use:
- Penetration testing with written permission
- Security research in controlled environments  
- Educational and learning purposes
- Testing your own systems and applications

❌ Unauthorized Use (STRICTLY PROHIBITED):
- Attacking systems without explicit permission
- Malicious activities of any kind
- Illegal access to computer systems
- Distribution of malware

Users are fully responsible for compliance with all 
applicable local, state, and federal laws.
```

### 🛡️ **Ethical Usage Guidelines**
- Always obtain written authorization before testing
- Respect scope limitations and rules of engagement
- Report vulnerabilities responsibly
- Do not cause harm or disruption to systems
- Follow responsible disclosure practices

---

## 🤝 **Contributing**

We welcome contributions! Here's how to get started:

### 📝 **Development Setup**
```bash
# Fork the repository
git clone https://github.com/your-username/i-see-u.git
cd i-see-u

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Create feature branch
git checkout -b feature/amazing-feature
```

### 🔄 **Contribution Workflow**
1. Fork the Project
2. Create Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit Changes (`git commit -m 'Add AmazingFeature'`)
4. Push to Branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

### 🐛 **Bug Reports**
Please include:
- Operating system and version
- Python version
- Full error message and stack trace
- Steps to reproduce
- Expected vs actual behavior

---

## 📚 **Documentation**

- **[Quick Start Guide](docs/quickstart.md)** - Get up and running in 5 minutes
- **[Advanced Usage](docs/advanced.md)** - Power user features
- **[API Reference](docs/api.md)** - For developers
- **[Troubleshooting](docs/troubleshooting.md)** - Common issues and solutions
- **[Contributing Guide](docs/contributing.md)** - How to contribute

---

## 🏆 **Acknowledgments**

- **Original mahadev_v1** by [@kishwordulal1234](https://github.com/kishwordulal1234)
- **Metasploit Framework** by [Rapid7](https://github.com/rapid7/metasploit-framework)
- **Android Reverse Engineering Tools** - apktool, zipalign, aapt
- **Security Research Community** - For continuous feedback and improvements

---

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📞 **Support**

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/kishwordulal1234/i-see-u/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/kishwordulal1234/i-see-u/discussions)
- 📧 **Security Issues**: security@iseeu-toolkit.com
- 📖 **Documentation**: [Wiki](https://github.com/kishwordulal1234/i-see-u/wiki)

---

<div align="center">

**⭐ Star this repo if you found it helpful!**

Made with ❤️ by ethical hackers, for ethical hackers.

*Remember: With great power comes great responsibility.*

</div>
