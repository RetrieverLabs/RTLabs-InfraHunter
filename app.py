import streamlit as st
import socket
import ssl
import requests
import whois
import mmh3
import pandas as pd
import ipaddress
import tldextract
from urllib.parse import urlparse
from datetime import datetime
from collections import defaultdict

# =========================
# UI
# =========================

st.set_page_config(page_title="Infrastructure Explorer", layout="wide")

st.title("🧠 RTL Infrastructure Explorer")
st.caption("RetrieverLabs: Live Infrastructure Signals + Correlation Engine (No storage, no APIs required)")

mode = st.radio("Mode", ["Single IOC", "Batch IOCs"])

# =========================
# NORMALIZATION LAYER
# =========================

def normalize_ioc(ioc):

    raw = ioc.strip()

    if raw.startswith("http://") or raw.startswith("https://"):
        host = urlparse(raw).netloc
    else:
        host = raw

    host = host.split(":")[0].lower().strip()

    try:
        ipaddress.ip_address(host)
        return {"type": "ip", "value": host}
    except:
        pass

    ext = tldextract.extract(host)

    if not ext.domain or not ext.suffix:
        return {"type": "invalid", "value": None}

    full = ".".join([p for p in [ext.subdomain, ext.domain, ext.suffix] if p])

    return {"type": "domain", "value": full}


# =========================
# ENRICHMENT LAYER
# =========================

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def fetch_whois(domain):
    try:
        return whois.whois(domain)
    except:
        return None


def fetch_cert(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert()
    except:
        return None


def fetch_favicon(domain):
    try:
        r = requests.get(f"http://{domain}/favicon.ico", timeout=5)
        if r.status_code == 200:
            return mmh3.hash(r.content)
    except:
        return None


# =========================
# SAFE WHOIS
# =========================

def safe_whois(w):

    if not w:
        return {}

    def f(x):
        if isinstance(x, list):
            return x[0] if x else None
        return x

    return {
        "registrar": f(getattr(w, "registrar", None)),
        "creation_date": f(getattr(w, "creation_date", None))
    }


# =========================
# SIGNAL ENGINE
# =========================

def signals(age, cert, favicon):

    s = []

    if favicon:
        s.append("favicon")

    if cert:
        s.append("cert")

    if age is not None and age < 30:
        s.append("new_domain")

    return s


def score(sig):
    weights = {
        "favicon": 5,
        "cert": 4,
        "new_domain": 3
    }
    return sum(weights.get(x, 0) for x in sig)


# =========================
# CORRELATION ENGINE (REAL)
# =========================

def correlate(results):

    clusters = defaultdict(list)

    for r in results:

        if "error" in r:
            continue

        keys = []

        if r.get("ip"):
            keys.append(f"ip:{r['ip']}")

        if r.get("favicon"):
            keys.append(f"fav:{r['favicon']}")

        if r.get("cert") and isinstance(r["cert"], dict):
            issuer = r["cert"].get("issuer")
            if issuer:
                keys.append(f"cert:{issuer}")

        key = "|".join(keys) if keys else "isolated"

        clusters[key].append(r)

    return clusters


# =========================
# PIVOTS (SAFE CLICKABLE OUTPUT ONLY HERE)
# =========================

def pivots(r):

    links = []

    if r.get("ip"):
        links.append(("Shodan IP Search", f"https://www.shodan.io/search?query={r['ip']}"))
        links.append(("AbuseIPDB", f"https://www.abuseipdb.com/check/{r['ip']}"))

    if r.get("domain"):
        links.append(("crt.sh", f"https://crt.sh/?q={r['domain']}"))
        links.append(("VirusTotal", f"https://www.virustotal.com/gui/domain/{r['domain']}"))

    return links


# =========================
# ANALYSIS PIPELINE
# =========================

def analyze(ioc):

    norm = normalize_ioc(ioc)

    if norm["type"] == "invalid":
        return {"ioc": ioc, "error": True}

    domain = None
    ip = None

    if norm["type"] == "ip":
        ip = norm["value"]
    else:
        domain = norm["value"]
        ip = resolve_ip(domain)

    who = fetch_whois(domain) if domain else None
    cert = fetch_cert(domain) if domain else None
    fav = fetch_favicon(domain) if domain else None

    who = safe_whois(who)

    creation = who.get("creation_date")

    age = None
    try:
        if creation:
            age = (datetime.utcnow() - creation).days
    except:
        age = None

    sig = signals(age, cert, fav)

    return {
        "ioc": ioc,
        "type": norm["type"],
        "domain": domain,
        "ip": ip,
        "registrar": who.get("registrar"),
        "age": age,
        "favicon": fav,
        "cert": cert,
        "signals": sig,
        "score": score(sig)
    }


# =========================
# SINGLE MODE
# =========================

if mode == "Single IOC":

    ioc = st.text_input("Enter IOC")

    if ioc:

        r = analyze(ioc)

        if r.get("error"):
            st.error("Invalid IOC")
        else:

            st.subheader("Profile")

            c1, c2, c3 = st.columns(3)
            c1.metric("Type", r["type"])
            c2.metric("IP", r["ip"] or "N/A")
            c3.metric("Score", r["score"])

            st.divider()

            # SAFE TABLE (NO URL INTERPRETATION POSSIBLE)
            st.subheader("Core Data")

            df = pd.DataFrame([{
                "Field": "Domain",
                "Value": str(r["domain"])
            },{
                "Field": "Registrar",
                "Value": str(r["registrar"])
            },{
                "Field": "Age",
                "Value": str(r["age"])
            },{
                "Field": "Cert Present",
                "Value": str(r["cert"] is not None)
            }])

            st.dataframe(df, use_container_width=True, hide_index=True)

            st.subheader("Signals")
            st.write(r["signals"])

            st.subheader("Pivots (SAFE LINKS)")
            for name, url in pivots(r):
                st.markdown(f"- **{name}** → {url}")


# =========================
# BATCH MODE
# =========================

if mode == "Batch IOCs":

    raw = st.text_area("Paste IOCs", height=200)

    if raw:

        iocs = [x.strip() for x in raw.split("\n") if x.strip()]

        results = []

        prog = st.progress(0)
        status = st.empty()

        for i, ioc in enumerate(iocs):

            status.text(f"{i+1}/{len(iocs)}")
            results.append(analyze(ioc))
            prog.progress((i+1)/len(iocs))

        status.text("Complete")

        st.subheader("Results")

        df = pd.DataFrame([
            {
                "IOC": r["ioc"],
                "Type": r["type"],
                "Domain": r["domain"],
                "IP": r["ip"],
                "Score": r["score"]
            }
            for r in results if not r.get("error")
        ])

        st.dataframe(df, use_container_width=True, hide_index=True)

        # =========================
        # CORRELATION VIEW
        # =========================

        st.subheader("Correlation Clusters")

        clusters = correlate(results)

        for k, items in clusters.items():

            st.markdown("---")
            st.write(f"### Cluster: {k}")
            st.write(f"Count: {len(items)}")

            for r in items:
                st.write(f"- {r['ioc']} (Score: {r['score']})")

        # =========================
        # PIVOTS PER IOC
        # =========================

        st.subheader("Pivot Map")

        for r in results:

            if r.get("error"):
                continue

            st.markdown("---")
            st.write(r["ioc"])

            for name, url in pivots(r):
                st.markdown(f"- **{name}** → {url}")