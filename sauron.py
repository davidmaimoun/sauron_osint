#!/usr/bin/env python3
import asyncio
import argparse
import json
import datetime
import os
from collections import Counter, defaultdict
import httpx

# ================= COLORS & LEVELS =================
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    ORANGE = "\033[38;5;208m"

class Level:
    HIGH    = 'high'
    MEDIUM  = 'medium'
    LOW     = 'low'
    RETRY   = 'retry'

class Status:
    GOOD      = "good"
    BAD       = "bad"
    FORBIDDEN = "forbidden"
    REDIRECT  = "redirect"
    UNKNOWN   = "unknown"

DATA_JSON = 'data.json'
KEY_USERNAME = 'username'
KEY_NAME      = 'name'
KEY_USERNAMES_PROBABLES = 'usernames_probables'
KEY_PLATFORM = 'platform'
KEY_MESSAGE    = 'message'
KEY_LEVEL    = 'level'
KEY_EMAIL    = 'email'

# ================= LOGGING =================
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, f"sauron_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")

def log(msg: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def out(msg: str, color: str = "", bold: bool = False):
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{msg}{Colors.RESET}")
    log(msg)

def out_results(results: dict):
    if not results:
        out("No results found", Colors.YELLOW)
        return
    
    for key, val in results.items():
        if not val:
            out("No results found", Colors.YELLOW)
            continue
        out(f"\n{Colors.CYAN}[{key.upper()}]{Colors.RESET}  Found {len(val)} items!\n", bold=True)
        
        if key == KEY_USERNAME or key == KEY_NAME:
            if val:  
                platform_width = max(len(str(v[KEY_PLATFORM])) for v in val) + 2
                level_width = max(len(str(v[KEY_LEVEL])) for v in val) + 2 
                url_width = 40

                # Header
                print(f"{ 'Platform'.ljust(platform_width)}   {'Level'.ljust(level_width)}  Message")
                print(f"{'-'*platform_width}  {'-'*level_width}  {'-'*url_width}")

                # Rows
                for v in val:
                    platform = v[KEY_PLATFORM].capitalize().ljust(platform_width)
                    level_text = str(v[KEY_LEVEL]).ljust(level_width)
                    if v[KEY_LEVEL] == Level.HIGH:
                        level_color = f"{Colors.BOLD}{Colors.GREEN}{level_text}{Colors.RESET}"
                    elif v[KEY_LEVEL] == Level.MEDIUM:
                        level_color = f"{Colors.BOLD}{Colors.ORANGE}{level_text}{Colors.RESET}"
                    else:
                        level_color = f"{Colors.BOLD}{Colors.CYAN}{level_text}{Colors.RESET}"

                    url = v[KEY_MESSAGE]
                    print(f"{platform}   {level_color}  {Colors.BLUE}{url}{Colors.RESET}")

def out_level_color(level: str):
    if level == Level.HIGH:
        return f'{Colors.BOLD}{Colors.GREEN}{Level.HIGH}{Colors.RESET}'
    elif level == Level.MEDIUM:
        return f'{Colors.BOLD}{Colors.ORANGE}{Level.MEDIUM}{Colors.RESET}'
    else:
        return f'{Colors.BOLD}{Colors.CYAN}{Level.LOW}{Colors.RESET}'


# ================= UTILITIES =================    
def derive_usernames(email: str):
    local = email.split("@")[0]
    candidates = [
        local,
        local.replace(".", ""),
        local.replace("_", ""),
    ]
    return list(dict.fromkeys(candidates))

def generate_username(name: str):
    return name.replace(" ", "").lower()

def map_status_code(status_code: int) -> Status:
    """
    Map HTTP status code to internal Status
    """

    if status_code in (200, 201, 202):
        return Status.GOOD

    if status_code in (301, 302, 307, 308):
        return Status.REDIRECT

    if status_code in (401, 403):
        return Status.FORBIDDEN

    if status_code == 404:
        return Status.BAD

    return Status.UNKNOWN

def get_confidence_level(conf):
    if conf == -1:
        return Level.UNKNOWN
    return (
        Level.HIGH if conf == 3
        else Level.MEDIUM if conf == 2
        else Level.LOW
    )

def match_any(response_data: dict, patterns: list[dict]) -> bool:
    """
    Match response_data against ANY pattern in patterns
    - string values: substring match (case-insensitive)
    - non-string values: strict equality
    """

    # normalize response data
    data = {
        k.lower(): (v.lower() if isinstance(v, str) else v)
        for k, v in response_data.items()
    }

    for pattern in patterns:
        pat = {
            k.lower(): (v.lower() if isinstance(v, str) else v)
            for k, v in pattern.items()
        }

        matched = True

        for k, v in pat.items():
            if k not in data:
                matched = False
                break

            # string → substring match
            if isinstance(v, str):
                if v not in data[k]:
                    matched = False
                    break
            # non-string → strict match
            else:
                if data[k] != v:
                    matched = False
                    break

        if matched:
            return True

    return False

def match_text_errors(text: str, patterns: list) -> bool:
    text = text.lower()

    for p in patterns:
        # simple string
        if isinstance(p, str):
            if p.lower() in text:
                return True

        # dict pattern (future-proof)
        elif isinstance(p, dict):
            for v in p.values():
                if isinstance(v, str) and v.lower() in text:
                    return True

    return False

def extract_retry_message(response_data: dict, patterns: list[dict]) -> str | None:
    """
    Return the REAL retry message from response_data
    if it matches any retry pattern.
    """
    data = {
        k.lower(): (v.lower() if isinstance(v, str) else v)
        for k, v in response_data.items()
    }

    for pattern in patterns:
        pat = {
            k.lower(): (v.lower() if isinstance(v, str) else v)
            for k, v in pattern.items()
        }

        for k, v in pat.items():
            if k in data and isinstance(v, str) and v in data[k]:
                # return original (non-lowercased) message
                return response_data.get(k)

    return None

def get_disclaimer():
    return  (
        "[! Disclaimer]\n"
        "    - Deep scan mode uses a real browser to load JavaScript content.\n"
        "    - It is intentionally slower to avoid username enumeration abuse.\n"
        "    - No private APIs, authentication, or bypass techniques are used.\n"
        )

def get_help():
        return(
            "Sauron Eye OSINT Scanner\n"
            "--username     Username to scan\n"
            "--email        Email to scan\n"
            "--name         Ex: \"Jonh Doe\"\n"
            "--deep         Enable deep checks using Playwright + Chromium\n"
        )

# ================= LOAD SITES =================
def load_data(input_type: str | None = None) -> dict:
    """
    Load site definitions from JSON and optionally filter by input_type.
    If a site has no 'inputType', it defaults to 'username'.
    :param input_type: "username", "email", "name", etc.
    :return: dict of sites matching the input_type (or all if None)
    """
    with open(DATA_JSON, "r", encoding="utf-8") as f:
        sites = json.load(f)

    if input_type:
        # Filter sites where 'inputType' matches, default to 'username' if missing
        filtered = {
            site_name: cfg
            for site_name, cfg in sites.items()
            if cfg.get("inputType", "username") == input_type
        }
        return filtered

    return sites


# ================= CHECK ENGINE =================

async def fetch(site_cfg, url, payload=None, deep=False, timeout=15000):
    headers = site_cfg.get("headers", {'User-Agent': 'Mozilla/5.0'})
    method = site_cfg.get("requestMethod", "GET").upper()

    # ===== DEEP (Playwright) =====
    if deep:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(user_agent=headers.get("User-Agent"))

            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
            await page.wait_for_timeout(3000)

            result = {
                "status": response.status if response else None,
                "text": (await page.content()).lower(),
                "title": (await page.title()).lower(),
                "json": None,
                "page": page
            }

            await browser.close()
            return result

    # ===== NORMAL (HTTPX) =====
    async with httpx.AsyncClient(timeout=10, headers=headers, follow_redirects=True) as client:
        if method == "POST" and payload:
            r = await client.post(url, json=payload)
        else:
            r = await client.get(url)

        try:
            data = r.json()
        except Exception:
            data = None

        return {
            "status": r.status_code,
            "text": r.text.lower(),
            "title": "",
            "json": data,
            "page": None
        }

def analyze_response(
    site_name,
    site_cfg,
    username,
    url_display,
    response,
    conf
):
    response_type = site_cfg.get("responseType")
    responses_error = site_cfg.get("responsesError", [])
    responses_success = site_cfg.get("responsesSuccess", [])
    responses_retry = site_cfg.get("responsesRetry", [])

    status = map_status_code(response["status"])

    # ===== STATUS HANDLING =====
    if status == Status.BAD:
        return None

    if status == Status.FORBIDDEN:
        return {
            "platform": site_name,
            "username": username,
            "message": "access forbidden - this may indicate that the user exists",
            "level": "forbidden",
            "confidence": 1,
            "tags": site_cfg.get("tags", [])
        }

    # ===== JSON =====
    if response_type == "json" and response["json"]:
        data = response["json"]

        if responses_retry and match_any(data, responses_retry):
            return {
                "platform": site_name,
                "username": username,
                "message": extract_retry_message(data, responses_retry),
                "level": "retry",
                "confidence": -1,
                "tags": []
            }

        if responses_error and match_any(data, responses_error):
            return None

        if responses_success and not match_any(data, responses_success):
            return None

    # ===== HTML / MESSAGE =====
    if response_type in ("html", "message"):
        text = response["text"]
        title = response["title"]

        if responses_error and match_text_errors(text, responses_error):
            return None

        if username.lower() in text or username.lower() in title:
            return {
                "platform": site_name,
                "username": username,
                "message": url_display,
                "level": get_confidence_level(conf),
                "confidence": conf,
                "tags": site_cfg.get("tags", [])
            }

    return {
        "platform": site_name,
        "username": username,
        "message": url_display,
        "level": get_confidence_level(conf),
        "confidence": conf,
        "tags": site_cfg.get("tags", [])
    }

async def check_site(site_name, site_cfg, username=None, name=None, deep=False):
    conf = site_cfg.get("confidence", 1)

    if username:
        url = site_cfg["url"].format(username)
        payload = site_cfg.get("requestPayload")
        if payload:
            payload = {k: v.format(username) for k, v in payload.items()}
    else:
        fn, ln = name.split(" ", 1)
        url = site_cfg["url"].format(fn, ln)
        payload = None
        username = name

    response = await fetch(
        site_cfg=site_cfg,
        url=url,
        payload=payload,
        deep=deep and site_cfg.get("scanMode") == "deep"
    )

    return analyze_response(
        site_name=site_name,
        site_cfg=site_cfg,
        username=username,
        url_display=url,
        response=response,
        conf=conf
    )

# =================  SCAN  ====================
async def scan(input_type, input_val, deep=False):
    sites = load_data(input_type)
    if input_type == "username":
        tasks = [check_site(site, cfg, username=input_val, name=None, deep=deep) for site, cfg in sites.items()]
    elif input_type == "name":
        tasks = [check_site(site, cfg, username=None, name=input_val, deep=deep) for site, cfg in sites.items()]

    results = await asyncio.gather(*tasks)

    return [r for r in results if r]


async def generate_and_scan(username=None, email=None, name=None, deep=False):
    results = {}
    
    if username:
        out(f"Scan required for the username: {Colors.BLUE}{username}{Colors.RESET}")
        results["username"] = await scan('username', username, deep=deep)
    
    if name:
        out(f"Scan required for the name: {Colors.BLUE}{name}{Colors.RESET}")
        results["name"] = await scan('name', name, deep=deep)
    return results


async def run_scan(username=None, email=None, name=None, deep=False):
    out("\n👁️  SAURON EYE STARTED\n", Colors.BOLD)
    if deep:
        out(get_disclaimer(),Colors.YELLOW,)

    results = await generate_and_scan(username=username, email=email, name=name, deep=deep)
    
    out_results(results)

    out("\n👁️  SAURON EYE DONE\n", Colors.BOLD)


# ================= ARGUMENTS =================
def main():
    parser = argparse.ArgumentParser(description="Sauron Eye OSINT Scanner")
    parser.add_argument("--username", type=str, help="Username to scan")
    parser.add_argument("--email", type=str, help="Email to scan")
    parser.add_argument("--name", type=str, help="ex: \"Jonh Doe\"")
    parser.add_argument("--deep", action="store_true", help="Enable deep checks using Playwright + Chromium")
    args = parser.parse_args()

    username = args.username
    email = args.email
    name=args.name
    deep=args.deep

    if not username and not name and not email:
        out(f"\n👁️  Little one, at least one arg is required : --username, --email, or --name.\n\n{get_help()}")
        return
    

    asyncio.run(run_scan(username=username, email=email, name=name, deep=deep))

if __name__ == "__main__":
    main()
