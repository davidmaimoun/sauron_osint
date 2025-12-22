#!/usr/bin/env python3
import asyncio
import argparse
import json
import datetime
import os
import random
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

UA_POOL = [
    # Chrome – Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",

    # Chrome – Linux
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36",

    # Firefox – Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",

    # Safari – macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.0 Safari/605.1.15",
]

TAG_GROUPS = {
    "technical": {
        "tags": {"tech", "dev", "devops", "ai", "opensource"},
        "label": "Tech",
        "emoji": "💻"
    },
    "offensive": {
        "tags": {"hacking", "security", "bugbounty"},
        "label": "Hacking",
        "emoji": "🔐"
    },
    "social": {
        "tags": {"social", "media", "community", "culture", "art"},
        "label": "Social / Media",
        "emoji": "📱"
    },
    "professional": {
        "tags": {"pro", "startup"},
        "label": "Professional",
        "emoji": "🏢"
    },
    "competitive": {
        "tags": {"competitive"},
        "label": "Competitive",
        "emoji": "🏁"
    }
}

VERDICT_LINES = {
    "offensive": {
        "dominant": "🔐  Dominant offensive mindset — breaks systems with the confidence of a seasoned Ring-forger.",
        "strong":   "⚙️  Strong hacker instinct — sharp curiosity, not yet fully corrupted by the Dark Arts.",
        "medium":   "🛠️  Some offensive knowledge — knows where to cut, still learning how deep.",
        "low":      "🔍  Minor hacking traces — watches the Eye, but does not serve it."
    },

    "technical": {
        "dominant": "💻  Builder mind — thinks in systems, forges logic like steel in the fires of industry.",
        "strong":   "🧠  Strong technical inclination — structured, methodical, and quietly efficient.",
        "medium":   "⚙️  Technically comfortable — competent, but not sworn to the craft.",
        "low":      "📎  Uses technology as a tool — not as a calling."
    },

    "social": {
        "dominant": "📱  Highly visible presence — speaks often, sometimes loudly, always noticed.",
        "strong":   "🗣️  Strong online presence — enjoys being seen beyond the walls.",
        "medium":   "👥  Moderate social activity — present in the world, but not consumed by it.",
        "low":      "👤  Low social exposure — prefers the shadows over the crowd."
    },

    "professional": {
        "dominant": "🏢  Strong professional identity — the corporate realm has claimed its champion.",
        "strong":   "📊  Career-oriented presence — values order, progress, and measurable results.",
        "medium":   "📁  Professional traces detected — likely functional rather than passionate.",
        "low":      "🗃️   Minimal professional footprint — walks outside the established realms."
    },

    "ai": {
        "strong": "🤖  AI-curious — experiments with modern sorcery, cautiously and with interest.",
        "medium": "🧪  AI-aware — observes the new magic without fully embracing it."
    }
}


def build_default_headers():
    """
    Build realistic browser headers with UA rotation
    """
    return {
        "User-Agent": random.choice(UA_POOL),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
        ),
        "Accept-Language": "en-GB,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Referer": "https://www.google.com/",
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
def get_banner():
    return """  
［ S ］ ［ A ］ ［ U ］ ［ R ］ ［ O ］ ［ N ］ ［  ］ ［ E ］ ［ Y ］ ［ E ］    
"""
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

def get_dev_error_response(res, site_name):
    return f'[Dev] Required {res} for {site_name}'

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
                print(f"{ 'Platform'.ljust(platform_width)}       {'Level'.ljust(level_width)}   Message")
                print(f"{'-'*platform_width}      {'-'*level_width}   {'-'*url_width}")

                # Rows
                rows_count = 0
                for v in val:
                    rows_count +=1

                    platform = v[KEY_PLATFORM].capitalize().ljust(platform_width)
                    level_text = str(v[KEY_LEVEL]).ljust(level_width)
                    rows_count_text = f"{str(rows_count)}.".ljust(3)

                    if v[KEY_LEVEL] == Level.HIGH:
                        level_color = f"{Colors.BOLD}{Colors.GREEN}{level_text}{Colors.RESET}"
                    elif v[KEY_LEVEL] == Level.MEDIUM:
                        level_color = f"{Colors.BOLD}{Colors.ORANGE}{level_text}{Colors.RESET}"
                    else:
                        level_color = f"{Colors.BOLD}{Colors.CYAN}{level_text}{Colors.RESET}"

                    url = v[KEY_MESSAGE]
                    
                    print(f"{rows_count_text} {platform}   {level_color}  {Colors.BLUE}{url}{Colors.RESET}")
                
                print(f"{'-'*platform_width}---{'-'*level_width}---{'-'*url_width}\n")
            
def out_level_color(level: str):
    if level == Level.HIGH:
        return f'{Colors.BOLD}{Colors.GREEN}{Level.HIGH}{Colors.RESET}'
    elif level == Level.MEDIUM:
        return f'{Colors.BOLD}{Colors.ORANGE}{Level.MEDIUM}{Colors.RESET}'
    else:
        return f'{Colors.BOLD}{Colors.CYAN}{Level.LOW}{Colors.RESET}'

def out_profile_from_results(results: dict, username):
    if not results:
        out("No digital presence detected. Even my Eye cannot find you.", Colors.YELLOW)
        return

    def percent_bar(percent, width=20):
        filled = int(width * percent / 100)
        return "█" * filled + "░" * (width - filled)

    # Collect tags
    all_tags = []
    for entries in results.values():
        if entries:
            for entry in entries:
                all_tags.extend(entry.get("tags", []))

    total = len(all_tags)
    if total == 0:
        out("No meaningful digital footprint… Orcs would say you're invisible.", Colors.YELLOW)
        return

    counter = Counter(all_tags)

    # ---- GROUP COUNTS ----
    group_counts = {}
    for group, data in TAG_GROUPS.items():
        count = sum(counter.get(tag, 0) for tag in data["tags"])
        if count > 0:
            group_counts[group] = count

    # Normalize to 100%
    group_percent = {
        g: round((c / total) * 100)
        for g, c in group_counts.items()
    }

    # Fix rounding drift (force 100%)
    drift = 100 - sum(group_percent.values())
    if drift != 0:
        biggest = max(group_percent, key=group_percent.get)
        group_percent[biggest] += drift

    # Sort by dominance
    ordered = sorted(group_percent.items(), key=lambda x: x[1], reverse=True)

    # ---- OUTPUT ----
    out(
        f"\n\n{Colors.BLUE}[PROFILING]\n\n"
        f"Profile analysis of the ring bearer : {username} \n",
        Colors.BLUE,
        bold=True
    )

    for group, percent in ordered:
        meta = TAG_GROUPS[group]
        bar = percent_bar(percent)
        out(f" {bar} {percent:>3}% → {meta['label']}")

    # ---- VERDICT ----
    fun_profile = []
    levels = {
        "dominant": [],
        "strong": [],
        "medium": [],
        "low": []
    }

    for group, percent in ordered:
        lvl = strength_level(percent)  # dominant / fort / medium / bas
        if lvl == "dominant":
            levels["dominant"].append(group)
        elif lvl == "fort":
            levels["strong"].append(group)
        elif lvl == "medium":
            levels["medium"].append(group)
        elif lvl == "bas":
            levels["low"].append(group)

    # Build verdict lines
    for level_name, groups in levels.items():
        for group in groups:
            line = VERDICT_LINES.get(group, {}).get(level_name)
            if line:
                fun_profile.append(line)

    # Print verdict
    if fun_profile:
        out("\n[Sauron verdict]\n", Colors.BLUE, bold=True)
        for line in fun_profile:
            out(f"  {line}")



# ================= UTILITIES =================    
def test_response(res):
    for k,v in res.items():
            if k != "text":
                print(k,v)
                
def normalize_percentages(counter, total):
    raw = {
        tag: (count / total) * 100
        for tag, count in counter.items()
    }

    rounded = {tag: int(val) for tag, val in raw.items()}
    remainder = 100 - sum(rounded.values())

    # Sort tags by largest decimal remainder
    remainders = sorted(
        raw.items(),
        key=lambda x: x[1] - int(x[1]),
        reverse=True
    )

    # Distribute remaining %
    for tag, _ in remainders[:remainder]:
        rounded[tag] += 1

    return rounded

def strength_level(percent):
    if percent >= 75:
        return "dominant"
    elif percent >= 50:
        return "fort"
    elif percent >= 30:
        return "medium"
    else:
        return "bas"

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

def match_response(input_str: str, patterns: list[str], ) -> bool:
    if not isinstance(input_str, str):
        return False

    input_str = input_str.lower()
    for p in patterns:
        if isinstance(p, str) and p.lower() in input_str:
            return True

    return False


def json_to_text(data) -> str:
    """
    Flatten any JSON (dict / list) into a searchable text string.
    """
    if data is None:
        return ""

    if isinstance(data, str):
        return data.lower()

    if isinstance(data, dict):
        return " ".join(
            json_to_text(v) for v in data.values()
        )

    if isinstance(data, list):
        return " ".join(
            json_to_text(item) for item in data
        )

    return str(data).lower()

def extract_retry_message(response_data, patterns) -> str | None:
    """
    Return the REAL retry message from response_data
    if it matches any retry pattern.
    """
    if not isinstance(response_data, str):
        return ''

    response_data = response_data.lower()
    for p in patterns:
        if isinstance(p, str) and p.lower() in response_data:
            return p

    return ''

def build_headers(site_cfg: dict) -> dict:
  
    headers = build_default_headers()
    site_headers = site_cfg.get("headers", {})

    if site_headers:
        headers.update(site_headers)

    return headers

def is_binary_garbage(text: str) -> bool:
    if not text:
        return False

    # Count non printable characters
    bad = sum(1 for c in text if ord(c) < 9 or ord(c) > 126)
    ratio = bad / len(text)

    return ratio > 0.3

def success_response(site_name, username, url_display, conf, tags):
    return {
        "platform": site_name,
        "username": username,
        "message": url_display,
        "level": get_confidence_level(conf),
        "confidence": conf,
        "tags": tags
    }


def retry_response(site_name, username, message="retry"):
    return {
        "platform": site_name,
        "username": username,
        "message": message,
        "level": "retry",
        "confidence": -1,
        "tags": []
    }


def forbidden_response(site_name, username, tags):
    return {
        "platform": site_name,
        "username": username,
        "message": (
            "access forbidden : retry later - might indicate that the user exists — or blocked by anti-bot protection."
        ),
        "level": "forbidden",
        "confidence": 1,
        "tags": tags
    }

def get_target(response, response_target):
    if response_target == "title":
        return response.get("title", "")
    return response.get("text", "")

def analyze_meta(
    text,
    site_name,
    username,
    url_display,
    conf,
    tags,
    error_meta,
    success_meta
):
    text = text[:10000]

    if error_meta:
        return None if error_meta in text else success_response(
            site_name, username, url_display, conf, tags
        )

    if success_meta:
        return success_response(
            site_name, username, url_display, conf, tags
        ) if success_meta in text else None

    exit(get_dev_error_response("responseMeta<Success/Error>Content", site_name))



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

    
    # ===== DEEP (Playwright) =====
    if deep:
        from playwright.async_api import async_playwright

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page(user_agent=headers.get("User-Agent"))

            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                await page.wait_for_timeout(3000)
            except TimeoutError:
                print("Page took too long to load, skipping or retrying...")

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

        content_type = r.headers.get("content-type", "").lower()

        json_data = None
        text_data = None

        if "application/json" in content_type:
            try:
                json_data = r.json()
            except Exception:
                text_data = r.text.lower()
        else:
            text_data = r.text.lower()

        # convert json into text (make the match easier)
        if json_data is not None:
            text_data = json_to_text(json_data)

        return {
            "status": r.status_code,
            "json": json_data,   # opt : to debug
            "text": text_data,   # str 
            "title": "",
            "page": None
        }

def analyze_response(site_name, site_cfg, username, url_display, response, conf):
    response_type = site_cfg.get("responseType")
    response_target = site_cfg.get("responseTarget")
    tags = site_cfg.get("tags", [])

    if not response_type:
        exit(get_dev_error_response("responseType", site_name))
    if response_type == "html" and not response_target:
        exit(get_dev_error_response("responseTarget", site_name))

    # ===== STATUS ONLY =====
    if response_type == "status_code":
        status = map_status_code(response["status"])

        if status == Status.GOOD:
            return success_response(site_name, username, url_display, conf, tags)
        if status == Status.FORBIDDEN:
            return forbidden_response(site_name, username, tags)
        return None

    # ===== HTML / MESSAGE =====
    text = response.get("text", "")
    # test_response(response)
    if is_binary_garbage(text):
        return retry_response(site_name, username, "blocked by anti-bot protection")

    # META MODE
    if response_target == "meta":
        return analyze_meta(
            text=text,
            site_name=site_name,
            username=username,
            url_display=url_display,
            conf=conf,
            tags=tags,
            error_meta=site_cfg.get("responseErrorMetaContent"),
            success_meta=site_cfg.get("responseSuccessMetaContent"),
        )

    # TEXT / TITLE MODE
    target = get_target(response, response_target)

    if match_response(target, site_cfg.get("responsesRetry", [])):
        msg = extract_retry_message(target, site_cfg["responsesRetry"])
        return retry_response(site_name, username, msg or "retry")

    if match_response(target, site_cfg.get("responsesSuccess", [])):
        return success_response(site_name, username, url_display, conf, tags)

    if match_response(target, site_cfg.get("responsesError", [])):
        return None

    # FALLBACK → optimistic success
    return success_response(site_name, username, url_display, conf, tags)

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
    if not input_type or input_type == "username":
        tasks = [check_site(site, cfg, username=input_val, name=None, deep=deep) for site, cfg in sites.items()]

    # TODO: name, email

    results = await asyncio.gather(*tasks)

    return [r for r in results if r]


async def generate_and_scan(data, username,deep=False):
    results = {}
    
   
    out(f"[>>>] The Eye turns its gaze upon {Colors.BLUE}{username}{Colors.RESET}, scanning the digital lands…")
    results["username"] = await scan(data, 'username', username, deep=deep)
    
    return results


async def run_scan(data, username, deep=False):
    print(get_banner())
    out("\n👁️  The Great Eye opens, scanning the digital realms.\n", Colors.BOLD)
    if deep:
        out(get_disclaimer(),Colors.YELLOW,)

    results = await generate_and_scan(data, username=username, deep=deep)
    
    out_results(results)

    if len(NOT_FOUND_SITES) > 0:
        out(f"{Colors.RED}[x] {len(NOT_FOUND_SITES)} not Found:", bold=True)
        not_found_msg = ''
        for s in sorted(NOT_FOUND_SITES):
            not_found_msg += ' ** ' + s
        out(f"  {not_found_msg}")
    else:
        out(f"\n{Colors.GREEN}[+]  Your user is present in all platforms!\n", bold=True)


    out_profile_from_results(results, username)

    out("\n👁️  Sauron Eye closes, secrets recorded.\n", Colors.BOLD)


# ================= ARGUMENTS =================
def main():
    parser = argparse.ArgumentParser(description="Sauron Eye OSINT Scanner")
    parser.add_argument("--data", required=True, default=DATA_JSON, help="By default, ./data.json")
    parser.add_argument("--username", required=True, type=str, help="Username to scan")
    # parser.add_argument("--email", type=str, help="Email to scan")
    # parser.add_argument("--name", type=str, help="ex: \"Jonh Doe\"")
    parser.add_argument("--deep", action="store_true", help="Enable deep checks using Playwright + Chromium")
    args = parser.parse_args()

    username = args.username
    data = args.data
    deep = args.deep

    if not data:
        out(f"\n👁️  Little one, you need the data file path : --data.\n\n{get_help()}")
        return
    if not username:
        out(f"\n👁️  Little one, at least one arg is required : --username, --email, or --name.\n\n{get_help()}")
        return
    
    asyncio.run(run_scan(username=username, data=data,deep=deep))

if __name__ == "__main__":
    main()
