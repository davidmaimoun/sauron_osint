#!/usr/bin/env python3
import asyncio
import argparse
import json
import re
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

KEY_USERNAME = 'username'
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
        
        if key == KEY_USERNAME or key == KEY_USERNAMES_PROBABLES:
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
def load_sites():
    with open("data_test.json", "r", encoding="utf-8") as f:
        return json.load(f)


# ================= PLAYWRIGHT DEEP CHECK =================
async def check_platform_deep(platform_name: str, url:str, username: str, platform_config: dict, level, timeout: int = 15000):
    """
    Deep check using Playwright for any platform.
    
    platform_config should include:
    - url: str, the URL with {} placeholder for username
    - responseError: list[str], negative markers in rendered page
    - positiveSelectors: list[str] (optional), CSS/XPath selectors indicating existence
    - confidence: int
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        out(f"[!] Deep mode requested but Playwright is not installed. Skipping {platform_name}.", Colors.YELLOW)
        return None

    negative_markers = [m.lower() for m in platform_config.get("responseError", [])]
    positive_selectors = platform_config.get("positiveSelectors", [])
    level = get_confidence_level(level)
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0 Safari/537.36"
            )

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                await page.wait_for_timeout(3000) 

                content = (await page.content()).lower()
                title = (await page.title()).lower()

                
                for marker in negative_markers:
                    if marker in content or marker in title:
                        await browser.close()
                        return None

                for selector in positive_selectors:
                    if await page.locator(selector).count() > 0:
                        await browser.close()
                        return {
                            "found": True,
                            "platform": platform_name,
                            "username": username,
                            "url": url,
                            "level": level,
                            "method": "deep-js-selector"
                        }

                if username.lower() in title:
                    await browser.close()
                    return {
                        "found": True,
                        "platform": platform_name,
                        "username": username,
                        "url": url,
                        "level": level,
                        "method": "deep-js-title"
                    }

                if username.lower() in content:
                    await browser.close()
                    return {
                        "found": True,
                        "platform": platform_name,
                        "username": username,
                        "url": url,
                        "level": level,
                        "method": "deep-js-content"
                    }

            except Exception as e:
                out(f"[!] Deep check failed for {platform_name}: {e}", Colors.YELLOW)

            await browser.close()

    except Exception:
        out(f"[!] Chromium not installed or failed to launch. Skipping {platform_name}.", Colors.RED)

    return None


# ================= CHECK ENGINE =================
async def check_site(site_name, site_cfg, username, deep=False):
    if site_cfg.get("force_lowercase"):
        username = username.lower()

    url_display = site_cfg["url"].format(username)
    url_probe = site_cfg.get("urlProbe", site_cfg["url"]).format(username)
    scan_mode = site_cfg.get("scanMode", "")
    response_type = site_cfg.get("responseType", "")
    responses_error = site_cfg.get("responseError", [])
    responses_retry = site_cfg.get("responsesRetry", [])
    responses_success = site_cfg.get("responseSuccess", [])
    regex_check = site_cfg.get("regexCheck")
    conf = site_cfg.get("confidence", 1)
    request_method = site_cfg.get("requestMethod", "GET").upper()
    request_payload = site_cfg.get("requestPayload")

    if regex_check and not re.match(regex_check, username):
        return None

    # ===== DEEP PLAYWRIGHT CHECK =====
    if scan_mode == "deep" and deep:
        return await check_platform_deep(
            platform_name=site_name,
            username=username,
            url=url_probe,
            platform_config=site_cfg,
            level=conf
        )

    # ===== NORMAL HTTPX CHECK =====
    try:
        async with httpx.AsyncClient(timeout=10, headers={'User-Agent': 'Mozilla/5.0'}, follow_redirects=True) as client:
            if request_method == "POST" and request_payload:
                # remplacer le {} par le username dans le payload
                payload = {k: v.format(username) if isinstance(v, str) else v
                           for k, v in request_payload.items()}
                r = await client.post(url_probe, json=payload, headers=site_cfg.get("headers", {}))
            else:
                r = await client.get(url_probe, headers=site_cfg.get("headers", {}))


        
        # ===== RESPONSE CHECK =====
        if response_type == "status_code":
            valid_codes = site_cfg.get("validStatus", [200])
            if isinstance(valid_codes, int):
                valid_codes = [valid_codes]
            if r.status_code not in valid_codes:
                return None

        elif response_type == "json":
            try:
                data = r.json()  
            except Exception:
                return None
            
            if responses_retry and match_any(data, responses_retry):
                retry_message = extract_retry_message(
                    response_data=data,
                    patterns=responses_retry
                ) or "temporary error, retry later"
                
                return {
                    "platform": site_name,
                    "username": username,
                    "message":data,
                    "level": 'retry',
                    "confidence": -1,
                    "tags": []
                }

            if responses_error and match_any(data, responses_error):
                return None

            if responses_success and not match_any(data, responses_success):
                return None

        elif response_type == "message" or response_type == "html":
            text = r.text.lower()

            for err in responses_error:
                for v in err.values():
                    if isinstance(v, str) and v.lower() in text:
                        return None
          
        else:
            return None


        return {
            "platform": site_name,
            "username": username,
            "message": url_display,
            "level": get_confidence_level(conf),
            "confidence": conf,
            "tags": site_cfg.get("tags", [])
        }

    except Exception:
        return None


# =================  SCAN  ====================
async def scan_username(username, deep=False):
    sites = load_sites()
    tasks = [check_site(site, cfg, username, deep=deep) for site, cfg in sites.items()]

    results = await asyncio.gather(*tasks)

    return [r for r in results if r]


async def generate_and_scan(username=None, email=None, name=None, deep=False):
    results = {}
    if username:
        results["username"] = await scan_username(username, deep=deep)
    else:
        generated = []
        if name:
            generated.append(generate_username(name))
        if email:
            generated.extend(derive_usernames(email))
        results["usernames_probables"] = []
        for u in generated:
            res = await scan_username(u, deep=deep)
            results["usernames_probables"].extend(res)
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
