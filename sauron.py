#!/usr/bin/env python3
import asyncio
import argparse
import json
import datetime
import os
from collections import Counter

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

ERROR_LEXICON = [
    "page not found",
    "not found",
    "does not exist",
    "no such user",
    "user not available",
    "account suspended",
    "invalid username",
    "page could not be found",
    "404",
    "profile not found",
    "not available",
    "unavailable",
    "cannot be found",
    "no such account"
]

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/142.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-GB,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

NOT_FOUND_SITES = set()

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


# ================= PRINT =================
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
            "--data         By default, ./data.json\n"
            "--username     Username to scan\n"
            "--email        Email to scan\n"
            "--name         Ex: \"Jonh Doe\"\n"
            "--deep         Enable deep checks using Playwright + Chromium\n"
        )

def out_results(results: dict):
    if not results:
        out("No profile detected. Even my eye cannot see you.", Colors.YELLOW)
        return
    
    for key, val in results.items():
        if not val:
            out("No profile detected. Even my eye cannot see you.", Colors.YELLOW)
            continue
        out(f"\n\n{Colors.CYAN}[{key.upper()}]{Colors.RESET}  Found {len(val)}!\n", bold=True)
        
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
                
                print(f"{'-'*platform_width}---{'-'*level_width}---{'-'*url_width}\n")
            
def out_level_color(level: str):
    if level == Level.HIGH:
        return f'{Colors.BOLD}{Colors.GREEN}{Level.HIGH}{Colors.RESET}'
    elif level == Level.MEDIUM:
        return f'{Colors.BOLD}{Colors.ORANGE}{Level.MEDIUM}{Colors.RESET}'
    else:
        return f'{Colors.BOLD}{Colors.CYAN}{Level.LOW}{Colors.RESET}'

def out_profile_from_results(results: dict):
    """
    Generate and print a sarcastic Sauron-style digital profile
    from results dict containing lists under keys like 'username' or 'name'.
    Fractions are shown as counts/total rather than percentages.
    """
    if not results:
        out("No digital presence detected. Even my Eye cannot find you.", Colors.YELLOW)
        return

    # Collect all tags from all lists in the dict
    all_tags = []
    for key, entries in results.items():
        if not entries:
            continue
        for entry in entries:
            all_tags.extend(entry.get("tags", []))

    total = len(all_tags)
    if total == 0:
        out("No meaningful digital footprint… Orcs would say you're invisible.", Colors.YELLOW)
        return

    # Count tags
    counter = Counter(all_tags)

    out(f"\n\n{Colors.BLUE}[{"Profiling".upper()}]\n\nDigital profile analysis of the specimen (total tags: {total})\n", Colors.BLUE, bold=True)

    # Print distribution as count/total
    for tag, count in counter.items():
        out(f" - {tag.capitalize()}: {count}/{total}")

    # Sort by dominance
    ordered = sorted(counter.items(), key=lambda x: x[1], reverse=True)
    dominant, dom_count = ordered[0]
    secondary = ordered[1][0] if len(ordered) > 1 else None

    fun_profile = []

    # Sarcastic verdict
    # Start with dominant
    if dominant == "hacking":
        fun_profile.append(f"🧠 {dom_count}/{total} hacking → Future master of systems… or just a nerd clicking everywhere.")
    elif dominant == "tech":
        fun_profile.append(f"💻 {dom_count}/{total} tech → Obsessed with logic… pathetic yet strangely useful.")
    elif dominant == "social":
        fun_profile.append(f"📱 {dom_count}/{total} social → Active online, or so it seems…")

    if secondary:
        if secondary in ("tech", "hacking"):
            fun_profile.append("⚙️ Secondary technical interest: precision in destruction and tinkering.")
        elif secondary == "media":
            fun_profile.append("🎥 Fascination with content: even Sauron's Eye would be jealous.")
        elif secondary == "pro":
            fun_profile.append("🏢 Likely professional use: enslaved to work, alas.")

    # Surprise if media or social are very low
    if counter.get("social", 0) / total < 0.2 or counter.get("media", 0) / total < 0.2:
        fun_profile.append("😮 Low social/media activity… do you sure the specimen is really a hobbit?")

    # Nuances
    if counter.get("hacking", 0) / total > 0.4:
        fun_profile.append("🔐 'Offensive-thinking' mindset: testing limits is your sport, mortal.")
    if counter.get("ai", 0) / total > 0.15:
        fun_profile.append("🤖 Curious about AI: apprentice sorcerer of new technologies.")

    # Print verdict
    if fun_profile:
        out("\nVerdict:", Colors.BLUE, bold=True)
        for line in fun_profile:
            out(f"   {line}")

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

def is_forbidden_exception(site_name):
    s = site_name.lower()
    return s == 'reddit' or s == 'medium'

def get_confidence_level(conf):
    if conf == -1:
        return Level.UNKNOWN
    return (
        Level.HIGH if conf == 3
        else Level.MEDIUM if conf == 2
        else Level.LOW
    )

def match_any(data, patterns):
    for pattern in patterns:
        if isinstance(pattern, dict):
            for k, v in pattern.items():
                if k in data or v in data:
                    return True
        else:  # string
            if pattern in data:
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

def build_headers(site_cfg: dict) -> dict:
    """
    Merge DEFAULT_HEADERS with site-specific headers
    Site headers override defaults
    """
    headers = DEFAULT_HEADERS.copy()
    site_headers = site_cfg.get("headers", {})

    if site_headers:
        headers.update(site_headers)

    return headers


# ================= LOAD SITES =================
def load_data(data, input_type: str | None = None) -> dict:
    """
    Load site definitions from JSON and optionally filter by input_type.
    If a site has no 'inputType', it defaults to 'username'.
    :param input_type: "username", "email", "name", etc.
    :return: dict of sites matching the input_type (or all if None)
    """
    with open(data, "r", encoding="utf-8") as f:
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
    method = site_cfg.get("requestMethod", "GET").upper()
    # headers = site_cfg.get("headers", {'User-Agent': 'Mozilla/5.0'})
    headers = build_headers(site_cfg)


    # It ensures the User-Agent header is properly normalized to prevent malformed headers that can trigger 403 or bot-detection blocks
    # if "User-Agent" in headers:
    #     headers["User-Agent"] = " ".join(headers["User-Agent"].split())
    
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

    # A forbidden might hidding an user
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

        if responses_error and match_any(data, responses_error + ERROR_LEXICON):
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
        url_probe = site_cfg.get("urlProbe", site_cfg["url"]).format(username)

        payload = site_cfg.get("requestPayload")
        if payload:
            payload = {k: v.format(username) for k, v in payload.items()}
    else:
        fn, ln = name.split(" ", 1)
        url = site_cfg["url"].format(fn, ln)
        url_probe = site_cfg.get("urlProbe", site_cfg["url"]).format(fn, ln)

        payload = None
        username = name

    response = await fetch(
        site_cfg=site_cfg,
        url=url_probe,
        payload=payload,
        deep=deep and site_cfg.get("scanMode") == "deep"
    )

    results = analyze_response(
        site_name=site_name,
        site_cfg=site_cfg,
        username=username,
        url_display=url,
        response=response,
        conf=conf
    )
    if results:
        return results
    else:
        NOT_FOUND_SITES.add(site_name)
        return None


# =================  SCAN  ====================
async def scan(data, input_type, input_val, deep=False):
    sites = load_data(data, input_type)
    if input_type == "username":
        tasks = [check_site(site, cfg, username=input_val, name=None, deep=deep) for site, cfg in sites.items()]
    elif input_type == "name":
        tasks = [check_site(site, cfg, username=None, name=input_val, deep=deep) for site, cfg in sites.items()]

    results = await asyncio.gather(*tasks)

    return [r for r in results if r]


async def generate_and_scan(data, username=None, email=None, name=None,deep=False):
    results = {}
    
    if username:
        out(f"[>>>] Scanning the web for the username: {Colors.BLUE}{username}{Colors.RESET}")
        results["username"] = await scan(data, 'username', username, deep=deep)
    
    if name:
        out(f"[>>>] Scanning the web for the name: {Colors.BLUE}{name}{Colors.RESET}")
        results["name"] = await scan(data, 'name', name, deep=deep)
    return results


async def run_scan(data, username=None, email=None, name=None, deep=False):
    out("\n👁️  SAURON EYE STARTED\n", Colors.BOLD)
    if deep:
        out(get_disclaimer(),Colors.YELLOW,)

    results = await generate_and_scan(data, username=username, email=email, name=name, deep=deep)
    
    out_results(results)

    if len(NOT_FOUND_SITES) > 0:
        out(f"{Colors.RED}[x] {len(NOT_FOUND_SITES)} not Found:", bold=True)
        not_found_msg = ''
        for s in sorted(NOT_FOUND_SITES):
            not_found_msg += ' ** ' + s
        out(f"  {not_found_msg}")
    else:
        out(f"\n{Colors.GREEN}[+]  Your user is present in all platforms!\n", bold=True)


    out_profile_from_results(results)

    out("\n👁️  SAURON EYE DONE\n", Colors.BOLD)


# ================= ARGUMENTS =================
def main():
    parser = argparse.ArgumentParser(description="Sauron Eye OSINT Scanner")
    parser.add_argument("--data", required=True, default=DATA_JSON, help="By default, ./data.json")
    parser.add_argument("--username", type=str, help="Username to scan")
    parser.add_argument("--email", type=str, help="Email to scan")
    parser.add_argument("--name", type=str, help="ex: \"Jonh Doe\"")
    parser.add_argument("--deep", action="store_true", help="Enable deep checks using Playwright + Chromium")
    args = parser.parse_args()

    username = args.username
    email = args.email
    name = args.name
    data = args.data
    deep = args.deep

    if not data:
        out(f"\n👁️  Little one, you need the data file path : --data.\n\n{get_help()}")
        return
    if not username and not name and not email:
        out(f"\n👁️  Little one, at least one arg is required : --username, --email, or --name.\n\n{get_help()}")
        return
    
    asyncio.run(run_scan(username=username, email=email, name=name, data=data,deep=deep))

if __name__ == "__main__":
    main()
