import os
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
import streamlit as st

# Automatic .env loader
try:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=True)
except ImportError:
    pass

# Google GenAI SDK
try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False


# ==============================================================================
# 1. STREAMLIT CONFIG & UI STYLING
# ==============================================================================
st.set_page_config(
    page_title="AEGIS-AI | Cyber Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-title { font-size: 2.2rem; font-weight: 800; color: #0F172A; }
    .sub-title { font-size: 1rem; color: #475569; margin-bottom: 1.5rem; }
    .verdict-banner-safe { background-color: #059669; color: white; padding: 1rem; border-radius: 8px; font-weight: 700; text-align: center; }
    .verdict-banner-danger { background-color: #DC2626; color: white; padding: 1rem; border-radius: 8px; font-weight: 700; text-align: center; }
    .verdict-banner-warning { background-color: #D97706; color: white; padding: 1rem; border-radius: 8px; font-weight: 700; text-align: center; }
    </style>
""",
    unsafe_allow_html=True,
)


# ==============================================================================
# 2. LAYER 1: HEURISTICS (Instant)
# ==============================================================================
def analyze_url_heuristics(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path.lower()

    indicators = []
    heuristic_score = 0

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        indicators.append("IP Address used as host domain.")
        heuristic_score += 35

    if "@" in url:
        indicators.append("Contains '@' symbol.")
        heuristic_score += 25

    domain_parts = domain.split(".")
    sub_count = max(0, len(domain_parts) - 2)
    if sub_count > 2:
        indicators.append(f"Excessive Subdomains ({sub_count}).")
        heuristic_score += 20

    suspicious_tlds = [".zip", ".mov", ".top", ".xyz", ".work", ".click", ".kim"]
    if any(domain.endswith(tld) for tld in suspicious_tlds):
        indicators.append("Suspicious TLD Extension.")
        heuristic_score += 20

    keywords = ["login", "verify", "account", "update", "banking", "secure", "signin"]
    found_keywords = [kw for kw in keywords if kw in domain or kw in path]
    if found_keywords:
        indicators.append(f"Target Keywords: {', '.join(found_keywords)}")
        heuristic_score += 10 * len(found_keywords)

    return {
        "url": url,
        "domain": domain,
        "heuristic_score": min(heuristic_score, 100),
        "indicators": indicators,
    }


# ==============================================================================
# 3. LAYER 2: FAST SSL CHECK (Timeout Reduced to 1.5s)
# ==============================================================================
def check_ssl_certificate(domain: str) -> dict:
    try:
        context = ssl.create_default_context()
        # Fast 1.5 second socket timeout
        with socket.create_connection((domain, 443), timeout=1.5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                issuer_name = issuer.get("organizationName", issuer.get("commonName", "Valid Authority"))
                return {"valid": True, "issuer": issuer_name, "status": "Secure HTTPS"}
    except Exception:
        return {"valid": False, "issuer": "Unverified", "status": "Insecure / Failed"}


# ==============================================================================
# 4. LAYER 3: FAST DOM SCRAPER (Timeout Reduced to 2.0s)
# ==============================================================================
def scrape_webpage_content(url: str) -> dict:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    try:
        # Fast 2.0 second HTTP timeout
        res = requests.get(url, headers=headers, timeout=2.0, allow_redirects=True)
        soup = BeautifulSoup(res.text, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else "N/A"
        forms = len(soup.find_all("form"))
        passwords = len(soup.find_all("input", {"type": "password"}))

        return {
            "scraped": True,
            "title": title[:50],
            "forms": forms,
            "passwords": passwords,
            "snippet": soup.get_text(strip=True)[:300]
        }
    except Exception:
        return {
            "scraped": False,
            "title": "Timeout / Unreachable",
            "forms": 0,
            "passwords": 0,
            "snippet": "None"
        }


# ==============================================================================
# 5. LAYER 4: FAST GEMINI THREAT REASONING
# ==============================================================================
def analyze_with_gemini(api_key: str, url: str, heur: dict, ssl_info: dict, dom: dict) -> dict:
    if not GENAI_AVAILABLE or not api_key:
        return {"error": "API Key missing in .env"}

    try:
        client = genai.Client(api_key=api_key)

        # Ultra-short concise prompt for fast execution
        prompt = f"""
        Act as a Cyber Threat Engine. Fast analyze URL: {url}
        Heuristic Score: {heur['heuristic_score']}/100
        SSL: {ssl_info['status']} ({ssl_info['issuer']})
        Title: {dom['title']} | Pass Inputs: {dom['passwords']}

        Return response in EXACT short format:
        VERDICT: [SAFE / SUSPICIOUS / MALICIOUS]
        RISK_SCORE: [0-100]
        SUMMARY: [1 short line]
        INDICATORS: [Bullet points or None]
        ACTION: [1 line recommendation]
        """

        config = types.GenerateContentConfig(
            temperature=0.0,
            max_output_tokens=250  # Limits long response generation delay
        )

        response = client.models.generate_content(
            model="gemini-3.6-flash", contents=prompt, config=config
        )

        return {"success": True, "output": response.text}
    except Exception as e:
        return {"error": str(e)}


# ==============================================================================
# 6. STREAMLIT APP LAYOUT
# ==============================================================================
def main():
    api_key = os.getenv("GEMINI_API_KEY", "").strip()

    with st.sidebar:
        st.markdown("### 🛡️ AEGIS-AI Core")
        if api_key:
            st.success("🟢 .env Active")
        else:
            st.error("🔴 Key Missing in .env")
        st.divider()
        st.caption("Mode: Ultra-Fast Security Pipeline")

    st.markdown('<div class="main-title">🛡️ AEGIS-AI</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Real-Time Threat Prevention Engine</div>', unsafe_allow_html=True)

    url_input = st.text_input("Enter Web URL for Deep Security Audit:", placeholder="https://www.google.com")

    if st.button("🚀 Audit Target URL", use_container_width=True, type="primary"):
        if not url_input.strip():
            st.error("Please enter a URL.")
            return

        if not api_key:
            st.error("GEMINI_API_KEY missing in .env")
            return

        with st.spinner("Analyzing threat signals..."):
            heur = analyze_url_heuristics(url_input)
            ssl_info = check_ssl_certificate(heur["domain"])
            dom = scrape_webpage_content(heur["url"])
            ai_res = analyze_with_gemini(api_key, heur["url"], heur, ssl_info, dom)

        st.markdown("---")

        if ai_res.get("success"):
            text = ai_res["output"]
            
            if "VERDICT: SAFE" in text or "SAFE" in text:
                st.markdown('<div class="verdict-banner-safe">🟢 VERDICT: SAFE WEBSITE</div>', unsafe_allow_html=True)
            elif "VERDICT: MALICIOUS" in text or "MALICIOUS" in text:
                st.markdown('<div class="verdict-banner-danger">🚨 VERDICT: MALICIOUS / PHISHING</div>', unsafe_allow_html=True)
            else:
                st.markdown('<div class="verdict-banner-warning">⚠️ VERDICT: SUSPICIOUS</div>', unsafe_allow_html=True)

            col1, col2, col3 = st.columns(3)
            col1.metric("Heuristic Score", f"{heur['heuristic_score']}/100")
            col2.metric("SSL Status", "Valid" if ssl_info["valid"] else "Invalid")
            col3.metric("Password Fields", dom["passwords"])

            st.markdown("### 🤖 Intelligence Report")
            st.info(text)
        else:
            st.error(f"Error: {ai_res.get('error')}")


if __name__ == "__main__":
    main()
