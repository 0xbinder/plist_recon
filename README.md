**A comprehensive attack surface enumeration tool for iOS and macOS applications.**

This tool parses the binary or XML `Info.plist` file found in Apple applications (IPA/APP) to extract critical security configurations, identify potential vulnerabilities, and generate instant hooking snippets for Frida and Objection.

---

## ⚡ Features

*   **🔍 Target Profiling**: Extracts Bundle IDs, SDK versions, and Minimum OS requirements.
*   **🔓 Attack Surface Discovery**: Enumerates custom URL Schemes (Deep Links) prone to XSS or logic flaws.
*   **🌐 Network Security Audit**: Analyzes App Transport Security (ATS) exceptions (`NSAllowsArbitraryLoads`, Exception Domains).
*   **👁️ Surveillance & Privacy**: Audits sensitive permissions (Camera, Mic, Location) with risk severity ratings.
*   **📂 Data Leakage Checks**: Detects file sharing capabilities (`UIFileSharingEnabled`) and document access.
*   **💉 Reversing Aid**: Identifies Entry Points (App/Scene Delegates) and generates ready-to-use **Frida** & **Objection** commands.
*   **🎨 Cyberpunk UI**: Features a stylized, color-coded terminal output for rapid visual parsing.

---

## 🚀 Installation

**Zero Dependencies.** This tool uses Python's standard library. No `pip install` required.

1.  **Clone the repository (or download the script):**
    ```bash
    git clone https://github.com/0xbinder/plist_recon.git
    cd plist-analyzer
    ```

2.  **Make executable:**
    ```bash
    chmod +x plist_recon.py
    ```

---

## 🕹️ Usage

Simply provide the path to the `Info.plist` file extracted from an IPA or macOS `.app` bundle.

```bash
python3 plist_parser.py path/to/Info.plist
```
