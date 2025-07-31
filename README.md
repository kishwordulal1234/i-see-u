# 🔍 I See U Toolkit

&#x20; &#x20;

> A modern recreation of `mahadev_v1` with enhanced payload generation, APK injection, terminal automation, and advanced configuration management.

---

## 📜 About the Project

**I See U Toolkit** is a powerful, cross-platform payload generation utility written in Python. It offers advanced features like automatic terminal management, Android APK injection (up to Android 15), multi-format payload creation, and more—targeting ethical hackers, red teamers, and penetration testers.

> ✨ Inspired by [`mahadev_v1`](https://github.com/kishwordulal1234/mahadev_v1) by @kishwordulal1234

---

## 🌟 Features

### ✅ Core Capabilities

- Traditional msfvenom payload generation (Windows, Linux, Android, macOS, iOS)
- Multiple encoding iterations and custom templates
- Download-and-execute "fetch" payloads
- Multi-format payload generation (EXE, APK, ELF, etc.)
- Automatic Metasploit listener launching in new terminals

### 📱 Android-Specific

- Android 10–15 support (injected APKs work best)
- Smali injection for payload execution
- Manifest permission patching
- APK signing and zipaligning
- Works with legit apps for stealth installs

### 💻 Terminal Management

- Auto-detection and handling of terminal emulators
- Supports: `xterm`, `gnome-terminal`, `konsole`, `terminator`, and more
- Fallback to background mode if no terminal is available

### 🔧 Configuration Management

- Save/load config presets for different test environments
- Input validation and sanitization
- Logging with timestamps

---

## ⚙️ Installation

### 📋 Prerequisites

- Python 3.7+
- Metasploit Framework
- Android tools: `apktool`, `zipalign`, `keytool`, `jarsigner`
- Java (OpenJDK 11+)

### 🧪 Tested OS:

- ✅ Kali Linux (Recommended)
- ✅ Ubuntu/Debian
- ✅ Fedora/CentOS
- ⚠️ Windows via WSL

### 💠 Install on Kali Linux:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip metasploit-framework apktool zipalign openjdk-11-jdk
```

### 💾 Install the Toolkit:

```bash
git clone https://github.com/yourusername/iseeu-toolkit.git
cd iseeu-toolkit
pip3 install -r requirements.txt
chmod +x iseeu_toolkit.py
python3 iseeu_toolkit.py
```

---

## 📖 Usage Guide

Upon running the tool, you'll see:

```
============ I SEE U TOOLKIT - MAIN MENU ============
1. Generate Traditional Payload
2. Inject Payload into Original APK
3. Generate Fetch Payload
4. Generate Multi-Format Payload
5. Start Meterpreter Listener
6. Configure Settings
7. Configure Terminal Settings
8. Load Preset Configuration
9. Save Current Configuration
10. View Help
0. Exit
======================================================
```

### 🔥 Common Workflows

#### 1️⃣ Traditional Payload (Windows EXE)

```bash
→ Platform: Windows
→ Payload: meterpreter/reverse_tcp
→ Format: exe
→ LHOST: 192.168.1.100
→ LPORT: 4444
→ Encoding: x86/shikata_ga_nai (3 iterations)
```

#### 2️⃣ Android APK Injection

```bash
→ Original APK: /path/to/app.apk
→ Payload: android/meterpreter/reverse_tcp
→ Inject smali code & permissions
→ Output: backdoored_app.apk (signed and zipaligned)
```

#### 3️⃣ Multi-Format Payload

```bash
→ Platform: Linux
→ Payload: meterpreter/reverse_tcp
→ Output: ELF, BIN, RAW formats
→ Encoder: x64/xor_dynamic (2 iterations)
```

---

## 📱 Android Compatibility Matrix

| Android Version | Standalone APK | Injected APK | Success Rate |
| --------------- | -------------- | ------------ | ------------ |
| 10–11           | ✅ Works        | ✅ Works      | 95%          |
| 12–13           | ⚠️ Limited     | ✅ Works      | 80%          |
| 14–15           | ❌ Rare         | ✅ Works      | 65%          |

> ⚠️ Use injected APKs with legit apps for better stealth & evasion.

---

## ❓ Troubleshooting

| Issue                       | Cause                         | Solution                                         |
| --------------------------- | ----------------------------- | ------------------------------------------------ |
| ❌ `apktool` not found       | Android tools missing         | `sudo apt install apktool`                       |
| ❌ No terminal opens         | Terminal not installed        | Set fallback or install supported emulator       |
| ❌ Payload fails to generate | Metasploit issues or bad args | Validate msfvenom command manually               |
| ❌ APK signing fails         | JDK not installed             | Install OpenJDK and check `keytool`, `jarsigner` |

---

## ⚠️ Legal & Ethical Notice

This tool is for **authorized penetration testing** and **educational** purposes **only**.

> ❗ Unauthorized use of this tool is strictly prohibited.\
> ❗ You are responsible for any actions taken using this software.

---

## 🤝 Contributing

Contributions are welcome!

```bash
# Example workflow
git fork https://github.com/yourusername/iseeu-toolkit.git
cd iseeu-toolkit
git checkout -b feature/my-feature
# Make changes
git commit -am "Added awesome feature"
git push origin feature/my-feature
# Open a pull request
```

---

## 📜 License

MIT License. See `LICENSE` file for full terms.

---

## 🙏 Acknowledgments

- **mahadev\_v1** by [@kishwordulal1234](https://github.com/kishwordulal1234)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- Android reverse engineering tools (apktool, zipalign)
- All penetration testers and researchers providing feedback

---

