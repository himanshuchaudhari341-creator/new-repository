"""
ShealdX — Professional Hybrid Phishing Analyzer
"""
import json
import os
import re
import socket
import ssl
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
import streamlit as st
from bs4 import BeautifulSoup

try:
    from dotenv import load_dotenv
    _ENV_PATH = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=_ENV_PATH, override=True)
except ImportError:
    pass

try:
    from google import genai
    from google.genai import types as genai_types
    GENAI_SDK_AVAILABLE = True
except ImportError:
    GENAI_SDK_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================

APP_TITLE = "🛡️ ShealdX Professional"
AI_MODEL = "gemini-3.6-flash"
REQUEST_TIMEOUT = 12
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "wallet", "suspend", "unlock", "recover",
    "billing", "invoice", "urgent", "authenticate", "webscr", "support",
]

IP_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

FREE_HOSTING_SUFFIXES = [
    "vercel.app", "netlify.app", "github.io", "herokuapp.com", "weebly.com",
    "wixsite.com", "firebaseapp.com", "web.app", "repl.co", "replit.app",
    "glitch.me", "pages.dev", "workers.dev", "appspot.com", "azurewebsites.net",
    "surge.sh", "000webhostapp.com", "blogspot.com", "wordpress.com",
    "sites.google.com", "ngrok.io", "ngrok-free.app", "onrender.com",
    "codesandbox.io", "s3.amazonaws.com", "myshopify.com",
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    from math import log2
    probs = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * log2(p) for p in probs)


# ============================================================================
# HELPER: LOAD STATIC HTML (header banner)
# ============================================================================

def load_html(filename: str) -> str:
    """Load a static HTML/CSS snippet (the header banner) from the project folder."""
    path = Path(__file__).parent / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


# ============================================================================
# HELPER: GET GEO LOCATION & IP DATA
# ============================================================================

def get_ip_and_location(domain):
    """Resolves IP + geo/hosting info with a fallback chain across three free
    providers — since any single free IP-geolocation API can rate-limit or
    go down temporarily, relying on just one made results inconsistent
    (e.g. 'Unknown, Unknown' on some scans and full data on others for the
    exact same domain). Trying providers in sequence makes results reliable."""
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {"ip": "N/A", "location": "N/A", "org": "N/A"}

    # Provider 1: ipapi.co
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        if not r.get("error"):
            city = r.get("city") or "Unknown"
            country = r.get("country_name") or "Unknown"
            org = r.get("org") or "Unknown"
            if city != "Unknown" or country != "Unknown":
                return {"ip": ip, "location": f"{city}, {country}", "org": org}
    except Exception:
        pass

    # Provider 2: ip-api.com (different rate-limit pool — good fallback)
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if r.get("status") == "success":
            city = r.get("city") or "Unknown"
            country = r.get("country") or "Unknown"
            org = r.get("isp") or r.get("org") or "Unknown"
            return {"ip": ip, "location": f"{city}, {country}", "org": org}
    except Exception:
        pass

    # Provider 3: ipwho.is (no API key required, separate rate-limit pool)
    try:
        r = requests.get(f"https://ipwho.is/{ip}", timeout=5).json()
        if r.get("success", True):
            city = r.get("city") or "Unknown"
            country = r.get("country") or "Unknown"
            org = (r.get("connection") or {}).get("isp") or "Unknown"
            return {"ip": ip, "location": f"{city}, {country}", "org": org}
    except Exception:
        pass

    # All three providers failed/rate-limited — return the IP itself at
    # least, which we always have from the DNS lookup above.
    return {"ip": ip, "location": "Unknown", "org": "Unknown"}


# ============================================================================
# LAYER 1 — URL / DOMAIN HEURISTIC FEATURE EXTRACTION
# ============================================================================

def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if not re.match(r"^https?://", raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url
    return raw_url


def extract_url_features(url: str) -> dict:
    parsed = urlparse(url)
    netloc = parsed.netloc
    domain = netloc.split(":")[0] if ":" in netloc else netloc

    is_free_hosting = any(
        domain.lower() == suf or domain.lower().endswith("." + suf)
        for suf in FREE_HOSTING_SUFFIXES
    )
    first_label = domain.split(".")[0] if domain else ""
    subdomain_entropy = shannon_entropy(first_label)

    return {
        "full_url": url,
        "domain": domain,
        "scheme": parsed.scheme,
        "is_https": parsed.scheme == "https",
        "url_length": len(url),
        "has_at_symbol": "@" in url,
        "has_ip_address": bool(IP_REGEX.match(domain)),
        "dot_count": domain.count("."),
        "hyphen_count": domain.count("-"),
        "subdomain_count": max(domain.count(".") - 1, 0),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "has_port": parsed.port is not None,
        "suspicious_keyword_hit": [
            kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()
        ],
        "is_free_hosting_platform": is_free_hosting,
        "subdomain_entropy": round(subdomain_entropy, 2),
        "subdomain_looks_random": subdomain_entropy > 2.8 and len(first_label) >= 8,
    }


# ============================================================================
# LAYER 2 — SSL / TLS CERTIFICATE VERIFICATION
# ============================================================================

def check_ssl_certificate(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        not_after = cert.get("notAfter")

        expired = False
        if not_after:
            try:
                expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expired = expiry_dt < datetime.utcnow()
            except ValueError:
                expired = False

        return {
            "valid": True,
            "expired": expired,
            "issuer": issuer.get("organizationName", "Unknown"),
            "subject": subject.get("commonName", domain),
            "not_after": not_after,
        }
    except Exception as e:
        return {"valid": False, "error": f"SSL error: {e}"}


# ============================================================================
# LAYER 3 — LIVE CONTENT SCRAPING
# ============================================================================

def scrape_site_content(url: str) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        response.encoding = response.apparent_encoding

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.get_text(strip=True) if soup.title else ""

        for tag in soup(["script", "style", "noscript", "svg", "head"]):
            tag.decompose()

        # NOTE: soup.get_text() alone joins EVERY text node verbatim,
        # including duplicate nav items that appear twice in the raw HTML
        # (once for desktop menu, once for a hidden mobile menu — e.g.
        # "Home Explore Wallet Video ... Home Explore Wallet Video" back to
        # back). We instead walk stripped_strings and deduplicate, and
        # separate short nav/button labels from real sentence-like content
        # so the preview shown to the user is clean and non-repetitive.
        raw_strings = [s.strip() for s in soup.stripped_strings if s.strip()]

        seen = set()
        content_points = []
        nav_labels = []
        for s in raw_strings:
            key = s.lower()
            if len(s) < 3 or key in seen:
                continue
            seen.add(key)
            if len(s) >= 18 and len(s.split()) >= 4:
                if len(content_points) < 25:
                    content_points.append(s)
            else:
                if len(nav_labels) < 25:
                    nav_labels.append(s)

        visible_text = " ".join(raw_strings)
        text_sample = visible_text[:3000]
        # Clean, deduplicated preview used for display — this is what fixes
        # the "Install Home Explore ... Home Explore Wallet Video More..."
        # repeated-junk problem in the UI.
        clean_preview = " • ".join(content_points) if content_points else " • ".join(nav_labels[:15])

        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", attrs={"type": "password"})
        all_inputs = soup.find_all("input")
        iframes = soup.find_all("iframe")

        return {
            "success": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "redirected": response.url != url,
            "title": title,
            "text_sample": text_sample,
            "content_points": content_points,
            "nav_labels": nav_labels,
            "clean_preview": clean_preview,
            "form_count": len(forms),
            "password_field_count": len(password_inputs),
            "total_input_count": len(all_inputs),
            "iframe_count": len(iframes),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============================================================================
# HEURISTIC SCORING ENGINE
# ============================================================================

def compute_heuristic_score(features: dict, ssl_info: dict, content: dict) -> dict:
    score = 0
    broken_rules = []

    if not features["is_https"]:
        score += 10
        broken_rules.append("Missing HTTPS (Insecure HTTP protocol used)")
    if features["has_at_symbol"]:
        score += 15
        broken_rules.append("URL contains suspicious '@' symbol")
    if features["has_ip_address"]:
        score += 20
        broken_rules.append("Domain uses raw IP address instead of domain name")
    if features["dot_count"] > 3:
        score += 10
        broken_rules.append(f"Excessive dots in domain ({features['dot_count']} dots)")
    if features["hyphen_count"] > 2:
        score += 10
        broken_rules.append(f"Excessive hyphens in domain ({features['hyphen_count']} hyphens)")
    if features["url_length"] > 75:
        score += 10
        broken_rules.append(f"Abnormally long URL length ({features['url_length']} characters)")
    if features["subdomain_count"] > 3:
        score += 10
        broken_rules.append("Too many subdomains detected")
    if features["suspicious_keyword_hit"]:
        score += 10
        broken_rules.append(f"Contains suspicious keywords: {', '.join(features['suspicious_keyword_hit'])}")
    if features["has_port"]:
        score += 5
        broken_rules.append("URL contains a non-standard network port")
    if features.get("is_free_hosting_platform"):
        score += 10
        broken_rules.append("Hosted on a free/shared hosting platform")
    if features.get("subdomain_looks_random"):
        score += 15
        broken_rules.append("High entropy/random-looking characters in subdomain")
    if not ssl_info.get("valid"):
        score += 15
        broken_rules.append("Invalid or unverified SSL certificate")
    elif ssl_info.get("expired"):
        score += 10
        broken_rules.append("SSL certificate has expired")

    if content.get("success"):
        if content["password_field_count"] > 0 and not features["is_https"]:
            score += 20
            broken_rules.append("Password input field found on an unencrypted HTTP connection")
        if content["form_count"] > 0 and content["password_field_count"] > 0:
            score += 25
            broken_rules.append("Contains sensitive login/credential collection forms")
    else:
        score += 5
        broken_rules.append("Could not fully scan live web page content")

    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {"score": score, "risk_level": risk_level, "broken_rules": broken_rules}


# ============================================================================
# LAYER 4 — AI CONTEXTUAL ANALYSIS ENGINE
# ============================================================================

SYSTEM_INSTRUCTION = """You are a senior cybersecurity threat analyst in the year 2026, \
specializing in phishing detection, brand impersonation, and social engineering analysis. \
IMPORTANT: Regardless of the source website language or foreign text, you MUST analyze the content \
and provide your summary, red flags, and recommendations IN ENGLISH ONLY. \
Respond with STRICT JSON ONLY, no markdown fences, matching exactly this schema:
{
  "risk_level": "High" | "Medium" | "Low",
  "confidence": <integer 0-100>,
  "summary": "<2-3 sentence plain-English verdict>",
  "red_flags": ["<short flag>", "..."],
  "impersonated_brand": "<brand name if suspected, else 'None detected'>",
  "recommendation": "<one actionable sentence for the end user>"
}"""


def build_ai_prompt(features: dict, ssl_info: dict, content: dict, heuristic: dict) -> str:
    text_sample = content.get("text_sample", "")[:2000] if content.get("success") else "N/A"
    payload = {
        "url": features["full_url"],
        "domain": features["domain"],
        "heuristic_features": features,
        "ssl_certificate": ssl_info,
        "scraped_page": {"success": content.get("success"), "title": content.get("title"), "text_sample": text_sample},
        "preliminary_heuristic_score": heuristic["score"],
    }
    return "Analyze the following target for phishing risk. Data:\n\n" + json.dumps(payload, indent=2, default=str)


def analyze_with_ai(api_key: str, prompt: str, max_retries: int = 3):
    if not GENAI_SDK_AVAILABLE or not api_key:
        return None, "AI engine dependency or API key not available."

    client = genai.Client(api_key=api_key)
    config = genai_types.GenerateContentConfig(
        system_instruction=SYSTEM_INSTRUCTION,
        response_mime_type="application/json",
        max_output_tokens=2048,
    )

    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=AI_MODEL, contents=prompt, config=config
            )
            raw_text = (getattr(response, "text", None) or "").strip()
            cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_text, flags=re.MULTILINE).strip()
            data = json.loads(cleaned)
            return data, None
        except Exception as e:
            if attempt == max_retries - 1:
                return None, str(e)
            time.sleep(2)
    return None, "AI analysis failed."


def combine_verdict(heuristic: dict, ai_result: dict | None) -> dict:
    if ai_result is None:
        return {
            "final_risk_level": heuristic["risk_level"],
            "final_confidence": heuristic["score"],
            "basis": "Deterministic Security Audit — URL structure, SSL/TLS validation, and live content inspection.",
        }

    ai_confidence = ai_result.get("confidence", 95)
    return {
        "final_risk_level": ai_result.get("risk_level", heuristic["risk_level"]),
        "final_confidence": ai_confidence,
        "basis": "Multi-Layered Threat Assessment — powered by contextual AI intelligence and security heuristics.",
    }


# ============================================================================
# STREAMLIT UI
# ============================================================================

def risk_badge(risk_level: str):
    if risk_level == "High":
        st.error("🔴 **HIGH RISK** — This site shows strong indicators of phishing.")
    elif risk_level == "Medium":
        st.warning("🟠 **MEDIUM RISK** — Proceed with caution; some suspicious indicators found.")
    else:
        st.success("🟢 **LOW RISK** — No strong phishing indicators detected.")


def get_api_key() -> str:
    api_key = os.environ.get("SHEALDX_API_KEY", "").strip()
    if api_key:
        return api_key
    try:
        return str(st.secrets.get("SHEALDX_API_KEY", "")).strip()
    except Exception:
        return ""


def main():
    st.set_page_config(page_title="ShealdX", page_icon="🛡️", layout="wide")

    api_key = get_api_key()

    header_html = load_html("header.html")
    if header_html:
        st.markdown(header_html, unsafe_allow_html=True)
    else:
        st.title(APP_TITLE)
        st.caption("Welcome to ShealdX — your trusted shield against phishing threats.")

    url_input = st.text_input("🔗 Enter a target URL to analyze", placeholder="e.g. https://example.com/login")
    analyze_clicked = st.button("🔍 Analyze URL", type="primary")

    if not analyze_clicked:
        st.info("Paste a URL above and click **Analyze URL** to begin.")
        return

    if not url_input.strip():
        st.error("Please enter a URL before analyzing.")
        return

    url = normalize_url(url_input)
    parsed_check = urlparse(url)
    if not parsed_check.netloc:
        st.error("The URL entered is not valid.")
        return

    with st.spinner("Extracting URL & domain features..."):
        features = extract_url_features(url)

    with st.spinner("Verifying SSL/TLS certificate..."):
        ssl_info = check_ssl_certificate(features["domain"])

    with st.spinner("Scraping live page content..."):
        content = scrape_site_content(url)

    with st.spinner("Running heuristic risk scoring..."):
        heuristic = compute_heuristic_score(features, ssl_info, content)

    with st.spinner("Consulting ShealdX AI engine for contextual analysis..."):
        prompt = build_ai_prompt(features, ssl_info, content, heuristic)
        ai_result, ai_error = analyze_with_ai(api_key, prompt)

    verdict = combine_verdict(heuristic, ai_result)
    geo = get_ip_and_location(features["domain"])

    st.divider()
    st.subheader("📊 Final Verdict")
    risk_badge(verdict["final_risk_level"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Final Risk Level", verdict["final_risk_level"])
    col2.metric("Confidence Score", f"{verdict['final_confidence']}%")
    col3.metric("Heuristic Score", f"{heuristic['score']}%")
    col4.metric("SSL Valid", "Yes" if ssl_info.get("valid") else "No")
    st.caption(f"🧾 **Assessment Basis:** {verdict['basis']}")

    st.divider()

    # --- PROFESSIONAL CHECKPHISH STYLE GRID LAYOUT ---
    st.subheader("📊 Scan Results")
    res_col1, res_col2 = st.columns(2)

    with res_col1:
        st.markdown(f"**Source URL:** `{url}`")
        st.markdown(f"**Brand:** {ai_result.get('impersonated_brand', 'None detected') if ai_result else 'N/A'}")
        st.markdown(f"**IP Address:** `{geo['ip']}`")
        st.markdown(f"**Detection Date:** {datetime.now().strftime('%B %d %Y, %H:%M:%S')}")

    with res_col2:
        st.markdown(f"**TLD:** {features['domain'].split('.')[-1] if '.' in features['domain'] else features['domain']}")
        st.markdown(f"**Location:** {geo['location']}")
        st.markdown(f"**Hosting Provider:** {geo['org']}")
        st.markdown(f"**Certificate Details:** {ssl_info.get('issuer', 'N/A')}: {ssl_info.get('subject', features['domain'])}")

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("🧬 URL & Domain Heuristics")
        st.write(f"**Domain:** `{features['domain']}`")
        st.write(f"**HTTPS:** {'✅ Yes' if features['is_https'] else '❌ No'}")
        st.write(f"**URL Length:** {features['url_length']} characters")

        if heuristic["score"] > 0 and heuristic["broken_rules"]:
            st.markdown("#### ⚠️ Broken Heuristic Rules / Violated Points:")
            for rule in heuristic["broken_rules"]:
                st.markdown(f"- ❌ {rule}")

        st.markdown("---")
        st.subheader("🔒 SSL Certificate")
        if ssl_info.get("valid"):
            st.success("Valid SSL handshake established.")
            st.write(f"**Issued to:** {ssl_info.get('subject')}")
            st.write(f"**Issuer:** {ssl_info.get('issuer')}")
        else:
            st.error(f"SSL verification failed: {ssl_info.get('error')}")

    with right:
        st.subheader("🌐 Live Content Scan")
        if content.get("success"):
            st.success("Page fetched successfully.")

            with st.expander("ℹ️ Click here for detailed URL & Page Information"):
                st.markdown(f"**Target URL:** `{features['full_url']}`")
                st.markdown(f"**Final Destination:** `{content.get('final_url', features['full_url'])}`")
                st.markdown(f"**Page Title:** {content.get('title') or 'N/A'}")
                st.markdown(f"**Forms Detected:** {content['form_count']} | **Password Fields:** {content['password_field_count']}")
                st.markdown("**Page Content / Purpose Preview:**")
                preview = content.get("clean_preview") or "No textual content could be identified on this page."
                st.info(preview[:600] + ("..." if len(preview) > 600 else ""))
        else:
            st.warning(f"Could not scrape live content: {content.get('error')}")

    st.divider()
    st.subheader("🤖 ShealdX AI Threat Intelligence")
    if ai_result:
        risk_badge(ai_result["risk_level"])
        st.write(f"**Summary:** {ai_result.get('summary', 'N/A')}")
        st.write(f"**Suspected impersonated brand:** {ai_result.get('impersonated_brand', 'None detected')}")

        st.markdown("### JSON Format")
        with st.expander("📋 View Structured Response Data"):
            st.code(json.dumps(ai_result, indent=4), language="json")

        st.info(f"💡 **Recommendation:** {ai_result.get('recommendation', 'N/A')}")
    else:
        st.warning(f"AI analysis unavailable: {ai_error}")

    st.divider()
    st.caption("Analysis completed successfully.")


if __name__ == "__main__":
    main()