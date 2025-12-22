# 👁️ Sauron Eye (OSINT)

Sauron Eye is an **OSINT username profiling tool** designed to discover a user's presence across **social media, tech platforms, and online services**.

Inspired by the architecture and philosophy of **Sherlock**, Sauron uses a **JSON-driven platform definition** to perform scalable and extensible username reconnaissance.

> “One username to rule them all.”

---
## ✨ Why Use Sauron Eye

- Designed for non-aggressive OSINT: does not exploit vulnerabilities or bypass protections

- Works fully legally, only analyzing publicly accessible data

- Highly recommended: use --deep mode for JavaScript-heavy platforms

- Only username scanning is fully supported; email and full name scanning are experimental

---

## ✨ Features

- 🔍 Search usernames across multiple platforms (social, media, tech, communities)
- 🧠 Confidence-based results (high / medium / low / retry)
- ⚙️ JSON-driven architecture (`data.json`) for easy extension
- 🚀 Async & fast scanning using `httpx`
- 👁️ **Deep mode** using Playwright for JavaScript-heavy platforms
- 🧪 Safe testing logic (no private APIs, no authentication bypass)
- 📊 Clean, colored CLI output with logging

---

## 🏗 Architecture

Sauron is built around a **data-driven engine**:

- Platforms are defined in a JSON file (`data.json`)
- Each platform specifies:
  - URL patterns
  - Request method (GET / POST)
  - Payload (if needed)
  - Response success / error / retry patterns
  - Scan mode (normal / deep)
  - Confidence level

This design makes Sauron **easy to maintain and extend** without touching core logic.

---

## 🔬 Scan Modes

### Normal Mode
- Uses direct HTTP requests
- Suitable for platforms with static or JSON-based responses
- Fast and lightweight

### Deep Mode (`--deep`) - Highly recommended.
- Uses **Playwright + Chromium**
- Required for JavaScript-heavy platforms (e.g. Twitch, Facebook)
- Renders pages like a real browser
- Detects content via DOM, title, and selectors

⚠️ Deep mode is intentionally slower to avoid abuse and enumeration.

---

## 📦 Requirements

### Python
- Python **3.10+** recommended

### Python dependencies
```bash
pip install httpx
```
For ```--deep``` mode:
```pip install playwright
playwright install chromium
```

## 🚀 Usage (For this version, only the username works well)

**Highly recommended:** use --deep mode for non‑aggressive scanning of JavaScript-heavy platforms. Most results depend on it.

Scan a username

```python sauron_eye.py --username johndoe```

Enable deep scan mode

```python sauron_eye.py --username johndoe --deep```



Scan using email (derive possible usernames)

```python sauron_eye.py --email john.doe@example.com```

Scan using full name

```python sauron_eye.py --name "John Doe"```



## 📊 Output

Results are displayed with:

Platform name

Confidence level

URL or message

Color-coded confidence

Example:

[USERNAME] Found 5 items!

Platform     Level     Message
---------------------------------------
Twitter      high      https://twitter.com/johndoe
GitHub       medium    https://github.com/johndoe
Discord      retry     The resource is being rate limited


Logs are automatically saved under:

logs/sauron_YYYYMMDD_HHMMSS.txt

🧠 Confidence Levels

high – strong evidence of account existence

medium – probable match

low – weak indicator

retry – rate-limited or temporary error

⚠️ Disclaimer

This tool is intended for:

Educational purposes

OSINT research

Defensive security

Personal investigations

It does NOT:

Use private or authenticated APIs

Bypass protections

Exploit vulnerabilities

You are responsible for how you use this tool.

🧩 Inspiration

Inspired by Sherlock

Practiced and validated using real-world OSINT techniques

Designed with extensibility and safety in mind

📌 Roadmap

Add more platforms

Output to JSON / CSV

Username permutation engine

Rate-limit awareness per platform

Plugin system for custom checks

👤 Author

David Maimoun
OSINT • Web Security • Offensive & Defensive Research

Feel free to contribute, report issues, or suggest improvements.

👁️ Sauron sees all.
