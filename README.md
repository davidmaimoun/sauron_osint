# 👁️ Sauron Eye (OSINT)

Sauron Eye is an **OSINT username profiling tool** designed to discover a user's presence across **social media, tech platforms, and online services**.

Inspired by the architecture and philosophy of **Sherlock**, Sauron uses a **JSON-driven platform definition** to perform scalable and extensible username reconnaissance.

> “One username to rule them all.”

---
## ✨ About Sauron Eye

### A non-aggressive OSINT 

- Does not exploit vulnerabilities or bypass protections

- Works fully legally, only analyzing publicly accessible data

- Highly recommended: use --deep mode for JavaScript-heavy platforms

- Only username scanning is fully supported

### 🔁 OSINT Pivoting


Starting from a known username on a single platform (for example a profile you encountered or interacted with), Sauron helps identify other **public accounts using the same username** across different services.

This allows analysts to:
- Map public digital presence
- Correlate accounts across platforms
- Understand online behavior patterns

All checks are passive and rely only on publicly accessible information.

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

## 🚀 Usage

**Highly recommended:** use --deep mode for non‑aggressive scanning of JavaScript-heavy platforms. Most results depend on it.

Scan a username

```python sauron_eye.py --username johndoe --data ./data.json```

Enable deep scan mode

```python sauron_eye.py --username johndoe --deep ./data.json```

---
## 📊 Output

Results show:

- **Platform name**
- **Confidence level**
- **URL / message**

**Example:**

**[USERNAME] Found 46!**

### Platforms Found

| #  | Platform               | Level  | Message                                                      |
|----|-----------------------|--------|--------------------------------------------------------------|
| 1  | About.me               | high   | https://about.me/johndoe                                     |
| 2  | Apple Developer        | high   | https://developer.apple.com/forums/profile/johndoe           |
| 3  | Apple Discussions      | high   | https://discussions.apple.com/profile/johndoe                |
| 4  | Behance                | high   | https://www.behance.net/johndoe                              |
| 5  | Bluesky                | high   | https://bsky.app/profile/johndoe.bsky.social                 |
| 6  | BuyMeACoffee           | high   | https://www.buymeacoffee.com/johndoe                         |
| .. | ...                    | ...    | ...                                                          |
| 46 | X(Twitter)             | medium | https://x.com/johndoe                                        |

---

### Not Found (11)

**BitBucket**, **Bugcrowd**, **Carrd**, **Gravatar**, **HackTheBox**, **PentesterLab**, **Root-Me**, **RubyGems**, **Telegram**, **YesWeHack**, **YouTube**

---

**[PROFILING]**

**Profile analysis of the ring bearer:** `johndoe`

██████████░░░░░░░░░░ 50% → Tech

███████░░░░░░░░░░░░░ 39% → Social / Media

░░░░░░░░░░░░░░░░░░░░ 4% → Hacking

░░░░░░░░░░░░░░░░░░░░ 4% → Professional

░░░░░░░░░░░░░░░░░░░░ 3% → Competitive


## [Sauron verdict]

- 🧠 Strong technical inclination — structured, methodical, and quietly efficient.  
- 👥 Moderate social activity — present in the world, but not consumed by it.  
- 🔍 Minor hacking traces — watches the Eye, but does not serve it.  
- 🗃️ Minimal professional footprint — walks outside the established realms.  

### 🧠 Confidence Levels

- **high** – strong evidence of account existence  
- **medium** – probable match  
- **low** – weak indicator  
- **retry** – rate-limited or temporary error  

### ⚠️ Legal & Ethical Use

This tool is intended for:

- Educational purposes  
- OSINT research  
- Defensive security  
- Personal investigations  

It does **NOT**:

- Use private or authenticated APIs  
- Bypass platform protections  
- Exploit vulnerabilities  

You are responsible for your own usage.

---

### 🧩 Inspiration & Roadmap

- Inspired by Sherlock, extended with modern techniques  
- Validated using real-world OSINT methods  

**Roadmap:**

- Add more platforms  
- Output to JSON / CSV  
- Username permutation engine  
- Rate-limit awareness per platform  
- Plugin system for custom checks  

---

### 👤 Author

David Maimoun – OSINT, Web Security, Offensive & Defensive Research  

Contributions, issues, and suggestions are welcome.


👁️ **Sauron Eye sees all.**
