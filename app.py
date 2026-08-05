"""
ShealdX — AI-Powered Phishing Website Analyzer
================================================
A production-ready Streamlit application that evaluates any URL for phishing
risk using a multi-layered hybrid pipeline.
"""

import json
import os
import re
import socket
import ssl
import time
from datetime import datetime, timezone
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

APP_TITLE = "🛡️ ShealdX"
AI_MODEL = "gemini-2.5-flash"
REQUEST_TIMEOUT = 8
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuardBot/1.0"
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
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {"valid": False, "error": f"Connection failed: {e}"}
    except ssl.SSLError as e:
        return {"valid": False, "error": f"SSL handshake failed: {e}"}
    except Exception as e:
        return {"valid": False, "error": f"Unexpected SSL error: {e}"}


# ============================================================================
# LAYER 3 — LIVE CONTENT SCRAPING
# ============================================================================

def scrape_site_content(url: str) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    try:
        response = requests.get(
            url, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True
        )
        soup = BeautifulSoup(response.text, "html.parser")

        title = soup.title.get_text(strip=True) if soup.title else ""

        for tag in soup(["script", "style", "noscript", "svg", "head"]):
            tag.decompose()

        raw_strings = [s.strip() for s in soup.stripped_strings]
        raw_strings = [s for s in raw_strings if s]
        visible_text = " ".join(raw_strings)

        seen = set()
        content_points = []
        nav_labels = []
        for s in raw_strings:
            key = s.lower()
            if len(s) < 3 or key in seen:
                continue
            seen.add(key)
            if len(s) >= 18 and len(s.split()) >= 4:
                content_points.append(s[:180])
                if len(content_points) >= 20:
                    continue
            else:
                nav_labels.append(s[:40])
                if len(nav_labels) >= 20:
                    continue

        text_sample = visible_text[:3000]

        forms = soup.find_all("form")
        password_inputs = soup.find_all("input", attrs={"type": "password"})
        all_inputs = soup.find_all("input")
        iframes = soup.find_all("iframe")
        external_scripts = [
            s.get("src") for s in soup.find_all("script") if s.get("src")
        ]

        return {
            "success": True,
            "status_code": response.status_code,
            "final_url": response.url,
            "redirected": response.url != url,
            "title": title,
            "text_sample": text_sample,
            "content_points": content_points,
            "nav_labels": nav_labels,
            "text_length": len(visible_text),
            "form_count": len(forms),
            "password_field_count": len(password_inputs),
            "total_input_count": len(all_inputs),
            "iframe_count": len(iframes),
            "external_script_count": len(external_scripts),
        }
    except requests.exceptions.SSLError as e:
        return {"success": False, "error": f"SSL error during scrape: {e}"}
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timed out — site may be blocking bots or is unreachable."}
    except requests.exceptions.TooManyRedirects:
        return {"success": False, "error": "Too many redirects."}
    except requests.exceptions.ConnectionError as e:
        return {"success": False, "error": f"Connection error: {e}"}
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Request failed: {e}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected scraping error: {e}"}


# ============================================================================
# HEURISTIC SCORING ENGINE
# ============================================================================

def compute_heuristic_score(features: dict, ssl_info: dict, content: dict) -> dict:
    score = 0
    flags = []

    if not features["is_https"]:
        score += 10
        flags.append("Site does not use HTTPS.")

    if features["has_at_symbol"]:
        score += 15
        flags.append("URL contains an '@' symbol (common cloaking trick).")

    if features["has_ip_address"]:
        score += 20
        flags.append("Domain is a raw IP address instead of a hostname.")

    if features["dot_count"] > 3:
        score += 10
        flags.append(f"Unusually high number of dots in domain ({features['dot_count']}).")

    if features["hyphen_count"] > 2:
        score += 10
        flags.append(f"Excessive hyphens in domain ({features['hyphen_count']}).")

    if features["url_length"] > 75:
        score += 10
        flags.append(f"URL is unusually long ({features['url_length']} characters).")

    if features["subdomain_count"] > 3:
        score += 10
        flags.append(f"Excessive subdomain nesting ({features['subdomain_count']}).")

    if features["suspicious_keyword_hit"]:
        score += 10
        flags.append(
            "URL contains sensitive/urgency keywords: "
            + ", ".join(features["suspicious_keyword_hit"][:5])
        )

    if features["has_port"]:
        score += 5
        flags.append("Non-standard port explicitly specified in URL.")

    if features.get("is_free_hosting_platform"):
        score += 10
        flags.append("Hosted on a free/instant-deploy platform (commonly abused for throwaway phishing infrastructure).")

    if features.get("subdomain_looks_random"):
        score += 15
        flags.append(
            f"Subdomain looks auto-generated / random (entropy={features.get('subdomain_entropy')}), "
            "a pattern typical of automated phishing kit deployments."
        )

    if not ssl_info.get("valid"):
        score += 15
        flags.append("SSL certificate could not be validated or handshake failed.")
    elif ssl_info.get("expired"):
        score += 10
        flags.append("SSL certificate is expired.")

    if content.get("success"):
        has_credential_form = content["form_count"] > 0 and content["password_field_count"] > 0

        if content["password_field_count"] > 0 and not features["is_https"]:
            score += 20
            flags.append("Password field submitted over an insecure (non-HTTPS) connection.")

        if has_credential_form:
            score += 25
            flags.append("Page contains a live login/credential-harvesting form with a password field.")

        if not content.get("title"):
            score += 5
            flags.append("Page has no title tag — common on hastily deployed phishing pages.")

        if content["iframe_count"] > 2:
            score += 5
            flags.append("Multiple embedded iframes detected (possible clickjacking/cloaking).")
    else:
        score += 5
        flags.append("Live content could not be scraped — reduced visibility into page behavior.")

    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {"score": score, "risk_level": risk_level, "flags": flags}


# ============================================================================
# LAYER 4 — AI CONTEXTUAL ANALYSIS ENGINE
# ============================================================================

SYSTEM_INSTRUCTION = """You are a senior cybersecurity threat analyst in the year 2026, \
specializing in phishing detection, brand impersonation, and social engineering analysis. \
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
        "scraped_page": {"success": content.get("success"), "title": content.get("title")},
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
    
    risk_to_num = {"Low": 20, "Medium": 55, "High": 85}
    ai_numeric = risk_to_num.get(ai_result["risk_level"], 50)
    ai_confidence = ai_result.get("confidence", 50)
    ai_weight = 0.3 + 0.4 * (ai_confidence / 100)
    combined_score = (heuristic["score"] * (1 - ai_weight)) + (ai_numeric * ai_weight)
    
    thresholds = [(60, "High"), (30, "Medium"), (0, "Low")]
    final_risk = "Low"
    for th, lbl in thresholds:
        if combined_score >= th:
            final_risk = lbl
            break

    return {
        "final_risk_level": final_risk,
        "final_confidence": round(combined_score, 1),
        "basis": "Multi-Layered Threat Assessment — combines heuristics and contextual AI reasoning.",
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


def load_html(filename: str) -> str:
    """Load the static header.html file from the project folder."""
    path = Path(__file__).parent / filename
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


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

    # Load and display header.html
    header_html = load_html("header.html")
    if header_html:
        st.markdown(header_html, unsafe_allow_html=True)
    else:
        st.title(APP_TITLE)
        st.caption("Welcome to ShealdX — your trusted shield against phishing threats.")

    if not api_key:
        st.warning("No AI engine key found — running in heuristics-only mode. Add `SHEALDX_API_KEY` to Streamlit Cloud Secrets.")
    else:
        masked = api_key[:4] + "…" + api_key[-4:] if len(api_key) > 8 else "••••"
        st.caption(f"✅ AI engine key loaded ({masked})")

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

    left, right = st.columns(2)

    with left:
        st.subheader("🧬 URL & Domain Heuristics")
        st.write(f"**Domain:** `{features['domain']}`")
        st.write(f"**HTTPS:** {'✅ Yes' if features['is_https'] else '❌ No'}")
        st.write(f"**URL Length:** {features['url_length']} characters")
        if features["suspicious_keyword_hit"]:
            st.write(f"**Suspicious keywords:** {', '.join(features['suspicious_keyword_hit'])}")

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
            st.success(f"Page fetched successfully (HTTP {content['status_code']}).")
            st.write(f"**Page Title:** {content.get('title') or 'N/A'}")
            st.write(f"**Forms detected:** {content['form_count']}")
            st.write(f"**Password fields:** {content['password_field_count']}")
        else:
            st.warning(f"Could not scrape live content: {content.get('error')}")

        st.markdown("---")
        st.subheader("🚩 Heuristic Red Flags")
        if heuristic["flags"]:
            for flag in heuristic["flags"]:
                st.write(f"- {flag}")
        else:
            st.write("No heuristic red flags triggered.")

    st.divider()
    st.subheader("🤖 ShealdX AI Threat Intelligence")
    if ai_result:
        risk_badge(ai_result["risk_level"])
        st.write(f"**Summary:** {ai_result.get('summary', 'N/A')}")
        st.write(f"**Suspected impersonated brand:** {ai_result.get('impersonated_brand', 'None detected')}")
        if ai_result.get("red_flags"):
            st.write("**AI-identified red flags:**")
            for flag in ai_result["red_flags"]:
                st.write(f"- {flag}")
        st.info(f"💡 **Recommendation:** {ai_result.get('recommendation', 'N/A')}")
    else:
        st.warning(f"AI analysis unavailable: {ai_error}")

    st.divider()
    st.caption("Analysis completed successfully.")


if __name__ == "__main__":
    main()