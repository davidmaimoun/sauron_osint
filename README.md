👁️ Sauron Eye (OSINT)

Sauron Eye is an OSINT username profiling tool that quietly observes a user’s digital footprint across social media, tech platforms, and online services.

Inspired by the architecture and philosophy of **Sherlock**, Sauron uses a **JSON-driven platform definition** to perform scalable and extensible username reconnaissance.

“One username to rule them all… and to quietly watch over the digital lands.”


✨ Why Use Sauron

Designed for **non-aggressive OSINT**: does not exploit vulnerabilities or bypass protections

Works fully legally, only analyzing publicly accessible data

**Highly recommended**: use `--deep` for non-aggressif scan JavaScript-heavy platforms. Most of the results depend of that.

Only `--username` scanning is fully supported; email and full name scanning are experimental


🏹 Features

🔍 Scan usernames across multiple platforms (social, media, tech, communities)

🧠 Confidence-based scoring (high / medium / low / retry)

⚙️ JSON-driven (data.json) for easy extension

🚀 Async & fast scanning using httpx

👁️ Deep mode using Playwright + Chromium for dynamic pages

🧪 Safe testing logic: no private APIs, no authentication bypass

📊 Clean, colored CLI output with logging

🏗 Architecture

Platforms defined in data.json with:

URL patterns

Request method (GET / POST)

Response success / error / retry patterns

Scan mode (normal / deep)

Confidence level

Core logic never needs to be changed for adding platforms

🔬 Scan Modes
Normal Mode

Simple HTTP requests

Works for static or JSON-based responses

Fast, lightweight

Deep Mode (--deep)

Uses Playwright + Chromium

Required for JavaScript-heavy platforms (e.g., Twitch, Instagram)

Renders pages like a real browser

Detects content via DOM, selectors, and titles

Slightly slower by design to avoid aggressive scanning

⚠️ Highly recommended for maximum accuracy.

📦 Requirements
Python

Python 3.10+ recommended

Dependencies
pip install httpx


For deep mode:

pip install playwright
playwright install chromium

🚀 Usage (Username Only)

Scan a username:

python sauron.py --username johndoe


Enable deep scan mode:

python sauron.py --username johndoe --deep


(Email & full name scanning are under development and may require aggressive enumeration.)

📊 Output

Results show:

Platform name

Confidence level

URL / message

Example:

[USERNAME] Found 5 items!

Platform     Level     Message
---------------------------------------
Twitter      high      https://twitter.com/johndoe
GitHub       medium    https://github.com/johndoe
Discord      retry     The resource is being rate limited


Logs saved automatically under:
logs/sauron_YYYYMMDD_HHMMSS.txt

Confidence Levels

high – strong evidence of account existence

medium – probable match

low – weak indicator

retry – rate-limited or temporary error

⚠️ Legal & Ethical Use

This tool is intended for:

Educational purposes

OSINT research

Defensive security

Personal investigations

It does NOT:

Use private or authenticated APIs

Bypass platform protections

Exploit vulnerabilities

You are responsible for your own usage.

🧩 Inspiration & Roadmap

Inspired by Sherlock, extended with modern techniques

Validated using real-world OSINT methods

Roadmap:

More platforms

Output to JSON / CSV

Username permutation engine

Rate-limit awareness per platform

Plugin system for custom checks

👤 Author

David Maimoun – OSINT, Web Security, Offensive & Defensive Research

Contributions, issues, and suggestions are welcome.

👁️ Sauron sees all.
