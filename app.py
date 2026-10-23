import sys
import os
import subprocess
from streamlit import runtime

# If user runs 'python app.py' directly, automatically launch it with Streamlit
if not runtime.exists():
    subprocess.run([sys.executable, "-m", "streamlit", "run", os.path.abspath(__file__)])
    sys.exit(0)

import streamlit as st
import socket
import time
import os
import base64
from datetime import datetime
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Set Page Configuration
st.set_page_config(
    page_title="PortSentinel | Network Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Helper function to render HTML cleanly without markdown indentation triggering <pre><code> blocks
def render_html(html_str):
    clean_lines = [line.strip() for line in html_str.strip().splitlines()]
    st.markdown("\n".join(clean_lines), unsafe_allow_html=True)

# Helper to encode image to base64
def get_base64_image(image_path):
    if os.path.exists(image_path):
        with open(image_path, "rb") as f:
            return base64.b64encode(f.read()).decode()
    return ""

# Common Port Signatures & Security Classification
COMMON_SERVICES = {
    20: ("FTP-DATA", "File Transfer", "Low"),
    21: ("FTP", "File Transfer", "Medium (Cleartext)"),
    22: ("SSH", "Remote Administration", "Secure / Standard"),
    23: ("Telnet", "Remote Shell", "HIGH RISK (Cleartext)"),
    25: ("SMTP", "Email Routing", "Low"),
    53: ("DNS", "Domain Resolution", "Low"),
    67: ("DHCP", "Network Config", "Low"),
    68: ("DHCP", "Network Config", "Low"),
    69: ("TFTP", "Trivial FTP", "Medium"),
    80: ("HTTP", "Web Service", "Cleartext Web"),
    110: ("POP3", "Email Retrieval", "Medium (Cleartext)"),
    119: ("NNTP", "Network News", "Low"),
    123: ("NTP", "Network Time", "Low"),
    135: ("RPC / MS-RPC", "Microsoft Endpoint Mapper", "High (Often targeted)"),
    139: ("NetBIOS-SSN", "Windows File Sharing", "High (SMB/NetBIOS)"),
    143: ("IMAP", "Email Retrieval", "Medium (Cleartext)"),
    161: ("SNMP", "Network Monitoring", "Medium"),
    194: ("IRC", "Internet Relay Chat", "Low"),
    389: ("LDAP", "Directory Services", "Medium"),
    443: ("HTTPS", "Encrypted Web", "Secure / Standard"),
    445: ("SMB", "Microsoft Directory / Files", "CRITICAL (EternalBlue vector)"),
    465: ("SMTPS", "Secure SMTP", "Low"),
    514: ("Syslog", "System Logs", "Low"),
    587: ("SMTP-Submission", "Mail Submission", "Low"),
    636: ("LDAPS", "Secure LDAP", "Low"),
    993: ("IMAPS", "Secure IMAP", "Secure / Standard"),
    995: ("POP3S", "Secure POP3", "Secure / Standard"),
    1433: ("MSSQL", "Microsoft SQL Server", "High (Database Exposure)"),
    1521: ("Oracle-DB", "Oracle Database", "High (Database Exposure)"),
    2049: ("NFS", "Network File System", "Medium"),
    3306: ("MySQL", "MySQL Database", "High (Database Exposure)"),
    3389: ("RDP", "Remote Desktop Protocol", "High (Brute-force target)"),
    5432: ("PostgreSQL", "Postgres Database", "High (Database Exposure)"),
    5900: ("VNC", "Virtual Network Computing", "High (Screen Sharing)"),
    6379: ("Redis", "In-Memory Key-Value Store", "CRITICAL (Default no-auth)"),
    8000: ("HTTP-Alt / Dev", "Web Dev / Django / FastAPI", "Informational"),
    8080: ("HTTP-Proxy / Alt", "Tomcat / Spring / Proxies", "Web Service"),
    8443: ("HTTPS-Alt", "Web Admin / Management", "Secure Web"),
    8888: ("HTTP-Alt", "Jupyter / Web Alternate", "Informational"),
    9000: ("SonarQube / PHP-FPM", "Management / App server", "Informational"),
    9200: ("Elasticsearch", "Search Cluster API", "High (Data Exposure)"),
    27017: ("MongoDB", "NoSQL Database", "CRITICAL (Default no-auth risk)"),
}

# Session State Initialization
if "scan_history" not in st.session_state:
    st.session_state["scan_history"] = []

banner_img_path = os.path.join(os.path.dirname(__file__), "assets", "hero_banner.jpg")
hero_b64 = get_base64_image(banner_img_path)

# Custom Cyberpunk UI Styling CSS
render_html(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Outfit:wght@300;400;500;600;700;800&display=swap');

* {{
    box-sizing: border-box;
}}

html, body, [class*="css"], .stApp {{
    font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif !important;
    color: #f1f5f9 !important;
}}

.stApp {{
    background: radial-gradient(circle at 50% 12%, #0c1a3b 0%, #060b18 55%, #03060d 100%) !important;
    background-attachment: fixed !important;
}}

code, pre, .terminal-text, .stCodeBlock {{
    font-family: 'JetBrains Mono', monospace !important;
}}

header[data-testid="stHeader"] {{
    background: transparent !important;
}}

#MainMenu, footer {{
    visibility: hidden;
}}

.block-container {{
    padding-top: 1.2rem !important;
    padding-bottom: 2rem !important;
    max-width: 1350px !important;
}}

/* ======================================================== */
/* SIDEBAR STYLING                                          */
/* ======================================================== */
section[data-testid="stSidebar"] {{
    background: linear-gradient(180deg, rgba(8, 14, 28, 0.96) 0%, rgba(5, 9, 19, 0.98) 100%) !important;
    border-right: 1px solid rgba(56, 189, 248, 0.18) !important;
    box-shadow: 10px 0 35px rgba(0, 0, 0, 0.6) !important;
    backdrop-filter: blur(20px) !important;
}}

section[data-testid="stSidebar"] .block-container {{
    padding-top: 1.2rem !important;
    padding-left: 1.1rem !important;
    padding-right: 1.1rem !important;
}}

.sidebar-brand {{
    display: flex;
    align-items: center;
    gap: 12px;
    padding-bottom: 16px;
    margin-bottom: 12px;
    border-bottom: 1px solid rgba(56, 189, 248, 0.12);
}}

.sidebar-logo-icon {{
    width: 36px;
    height: 36px;
    filter: drop-shadow(0 0 10px #38bdf8);
}}

.sidebar-brand-name {{
    font-size: 1.45rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    margin: 0;
    color: #ffffff;
}}

.sidebar-brand-name span {{
    color: #38bdf8;
    text-shadow: 0 0 12px rgba(56, 189, 248, 0.6);
}}

/* Transform Streamlit Radio into Modern Navigation Pills */
div[data-testid="stRadio"] > label {{
    display: none !important;
}}

div[data-testid="stRadio"] [role="radiogroup"] {{
    display: flex !important;
    flex-direction: column !important;
    gap: 6px !important;
    width: 100% !important;
    margin-bottom: 16px !important;
}}

div[data-testid="stRadio"] label {{
    background: transparent !important;
    padding: 10px 14px !important;
    border-radius: 10px !important;
    cursor: pointer !important;
    transition: all 0.2s ease !important;
    border: 1px solid transparent !important;
    width: 100% !important;
    margin: 0 !important;
    display: flex !important;
    align-items: center !important;
}}

/* Completely hide standard radio circle/dot indicator */
div[data-testid="stRadio"] label > div:first-child,
div[data-testid="stRadio"] label input,
div[data-testid="stRadio"] label svg,
div[data-testid="stRadio"] label [data-baseweb="radio"] {{
    display: none !important;
    visibility: hidden !important;
    width: 0 !important;
    height: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}}

div[data-testid="stRadio"] label div[data-testid="stMarkdownContainer"] p {{
    font-size: 0.95rem !important;
    font-weight: 500 !important;
    color: #94a3b8 !important;
    margin: 0 !important;
    transition: color 0.2s ease !important;
}}

div[data-testid="stRadio"] label:hover {{
    background: rgba(56, 189, 248, 0.08) !important;
}}

div[data-testid="stRadio"] label:hover div[data-testid="stMarkdownContainer"] p {{
    color: #f8fafc !important;
}}

/* Active / Checked Navigation Item */
div[data-testid="stRadio"] label:has(input:checked),
div[data-testid="stRadio"] label[data-checked="true"] {{
    background: linear-gradient(90deg, #1e40af 0%, #2563eb 50%, #3b82f6 100%) !important;
    border: 1px solid rgba(96, 165, 250, 0.45) !important;
    box-shadow: 0 0 18px rgba(37, 99, 235, 0.5), inset 0 1px 1px rgba(255, 255, 255, 0.2) !important;
}}

div[data-testid="stRadio"] label:has(input:checked) div[data-testid="stMarkdownContainer"] p,
div[data-testid="stRadio"] label[data-checked="true"] div[data-testid="stMarkdownContainer"] p {{
    color: #ffffff !important;
    font-weight: 600 !important;
}}

/* Sidebar Section Headers */
.section-header {{
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.98rem;
    font-weight: 700;
    color: #e2e8f0;
    margin-top: 14px;
    margin-bottom: 12px;
    letter-spacing: 0.02em;
}}

.section-header span.icon {{
    color: #38bdf8;
}}

.custom-label {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.85rem;
    font-weight: 600;
    color: #cbd5e1;
    margin-bottom: 6px;
}}

.custom-label .info-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 1px solid rgba(148, 163, 184, 0.4);
    color: #94a3b8;
    font-size: 0.7rem;
    cursor: help;
}}

/* Dark Inputs with glowing cyan focus */
section[data-testid="stSidebar"] div[data-testid="stTextInput"] input,
section[data-testid="stSidebar"] div[data-baseweb="input"] input,
section[data-testid="stSidebar"] input {{
    background-color: rgba(13, 23, 44, 0.9) !important;
    border: 1px solid rgba(56, 189, 248, 0.3) !important;
    border-radius: 10px !important;
    color: #ffffff !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.95rem !important;
    padding: 10px 14px !important;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.5) !important;
}}

section[data-testid="stSidebar"] div[data-testid="stTextInput"] input:focus,
section[data-testid="stSidebar"] input:focus {{
    border-color: #38bdf8 !important;
    box-shadow: 0 0 16px rgba(56, 189, 248, 0.45) !important;
    outline: none !important;
}}

section[data-testid="stSidebar"] div[data-baseweb="select"] > div {{
    background-color: rgba(13, 23, 44, 0.9) !important;
    border: 1px solid rgba(56, 189, 248, 0.3) !important;
    border-radius: 10px !important;
    color: #ffffff !important;
}}

/* Sliders */
div[data-testid="stSlider"] {{
    margin-top: 4px;
    margin-bottom: 12px;
}}

div[data-testid="stSlider"] div[role="slider"] {{
    background-color: #38bdf8 !important;
    border: 2px solid #ffffff !important;
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.9) !important;
}}

/* Start Scan Primary Button */
button[kind="primary"], div.stButton > button {{
    background: linear-gradient(90deg, #6366f1 0%, #3b82f6 50%, #06b6d4 100%) !important;
    color: #ffffff !important;
    border: 1px solid rgba(255, 255, 255, 0.25) !important;
    border-radius: 9999px !important;
    padding: 12px 28px !important;
    font-size: 1.05rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.03em !important;
    box-shadow: 0 0 25px rgba(56, 189, 248, 0.55), 0 4px 15px rgba(0, 0, 0, 0.4) !important;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
    width: 100% !important;
    margin-top: 10px !important;
    cursor: pointer !important;
}}

button[kind="primary"]:hover, div.stButton > button:hover {{
    transform: translateY(-2px) scale(1.01) !important;
    box-shadow: 0 0 35px rgba(56, 189, 248, 0.85), 0 6px 22px rgba(0, 0, 0, 0.6) !important;
    border-color: rgba(255, 255, 255, 0.5) !important;
}}

/* ======================================================== */
/* HERO BANNER CARD                                         */
/* ======================================================== */
.hero-banner {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(135deg, rgba(8, 16, 36, 0.92) 0%, rgba(12, 23, 49, 0.85) 100%);
    border: 1.5px solid rgba(56, 189, 248, 0.32);
    border-radius: 18px;
    padding: 24px 28px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
    box-shadow: 0 12px 35px rgba(0, 0, 0, 0.5), 0 0 30px rgba(56, 189, 248, 0.12);
    backdrop-filter: blur(16px);
}}

.hero-banner::before {{
    content: '';
    position: absolute;
    top: -40px;
    left: -40px;
    width: 180px;
    height: 180px;
    background: radial-gradient(circle, rgba(56, 189, 248, 0.25), transparent 70%);
    pointer-events: none;
}}

.hero-left {{
    display: flex;
    align-items: center;
    gap: 22px;
    z-index: 2;
    max-width: 60%;
}}

.hero-shield-icon {{
    width: 82px;
    height: 82px;
    flex-shrink: 0;
    filter: drop-shadow(0 0 16px rgba(56, 189, 248, 0.8));
}}

.hero-content {{
    display: flex;
    flex-direction: column;
    gap: 6px;
}}

.hero-title {{
    font-size: 2.5rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    margin: 0;
    color: #ffffff;
    line-height: 1.1;
}}

.hero-title span {{
    color: #38bdf8;
    text-shadow: 0 0 18px rgba(56, 189, 248, 0.7);
}}

.hero-subtitle {{
    color: #94a3b8;
    font-size: 0.98rem;
    line-height: 1.4;
    margin: 0;
}}

.hero-badges {{
    display: flex;
    gap: 10px;
    margin-top: 10px;
    flex-wrap: wrap;
}}

.hero-badge {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: rgba(14, 165, 233, 0.08);
    border: 1px solid rgba(56, 189, 248, 0.28);
    border-radius: 9999px;
    padding: 5px 14px;
    font-size: 0.84rem;
    font-weight: 600;
    color: #e2e8f0;
    backdrop-filter: blur(8px);
}}

.hero-badge .b-icon {{
    color: #38bdf8;
}}

.hero-right {{
    position: relative;
    width: 40%;
    height: 160px;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    overflow: hidden;
}}

.hero-bg-art {{
    height: 160px;
    width: 100%;
    object-fit: cover;
    object-position: center right;
    border-radius: 12px;
    mask-image: linear-gradient(to right, transparent 0%, rgba(0,0,0,0.85) 30%, black 100%);
    -webkit-mask-image: linear-gradient(to right, transparent 0%, rgba(0,0,0,0.85) 30%, black 100%);
    filter: contrast(1.1) brightness(1.05);
}}

/* ======================================================== */
/* METRICS ROW CARDS                                        */
/* ======================================================== */
.metrics-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 20px;
}}

.metric-card {{
    background: linear-gradient(135deg, rgba(10, 19, 40, 0.8) 0%, rgba(14, 25, 52, 0.75) 100%);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 14px;
    padding: 16px 20px;
    display: flex;
    align-items: center;
    gap: 16px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4), inset 0 1px 1px rgba(255, 255, 255, 0.08);
    transition: all 0.25s ease;
    backdrop-filter: blur(12px);
}}

.metric-card:hover {{
    border-color: rgba(56, 189, 248, 0.45);
    transform: translateY(-2px);
    box-shadow: 0 12px 28px rgba(0, 0, 0, 0.5), 0 0 20px rgba(56, 189, 248, 0.15);
}}

.metric-icon-wrap {{
    width: 48px;
    height: 48px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
}}

.metric-icon-target {{
    background: rgba(56, 189, 248, 0.12);
    border: 1px solid rgba(56, 189, 248, 0.35);
    color: #38bdf8;
    box-shadow: 0 0 12px rgba(56, 189, 248, 0.3);
}}

.metric-icon-ip {{
    background: rgba(168, 85, 247, 0.12);
    border: 1px solid rgba(168, 85, 247, 0.35);
    color: #c084fc;
    box-shadow: 0 0 12px rgba(168, 85, 247, 0.3);
}}

.metric-icon-ports {{
    background: rgba(20, 184, 166, 0.12);
    border: 1px solid rgba(20, 184, 166, 0.35);
    color: #2dd4bf;
    box-shadow: 0 0 12px rgba(20, 184, 166, 0.3);
}}

.metric-info {{
    display: flex;
    flex-direction: column;
}}

.metric-label {{
    font-size: 0.8rem;
    font-weight: 600;
    color: #94a3b8;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}}

.metric-value {{
    font-size: 1.25rem;
    font-weight: 700;
    color: #ffffff;
    font-family: 'JetBrains Mono', monospace;
}}

/* ======================================================== */
/* WORKSPACE SECTION (CENTER + RIGHT)                       */
/* ======================================================== */
.workspace-row {{
    display: grid;
    grid-template-columns: 2.1fr 1fr;
    gap: 20px;
    margin-bottom: 24px;
}}

.center-hud-card {{
    background: linear-gradient(145deg, rgba(8, 15, 32, 0.92) 0%, rgba(12, 22, 46, 0.88) 100%);
    border: 1.5px solid rgba(99, 102, 241, 0.32);
    border-radius: 18px;
    min-height: 480px;
    position: relative;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 24px;
    box-shadow: 0 14px 40px rgba(0, 0, 0, 0.6), 0 0 35px rgba(99, 102, 241, 0.12);
    backdrop-filter: blur(16px);
}}

.floating-terminal {{
    background: rgba(4, 9, 20, 0.85);
    border: 1px solid rgba(56, 189, 248, 0.22);
    border-radius: 10px;
    padding: 12px 18px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.84rem;
    color: #38bdf8;
    line-height: 1.6;
    width: fit-content;
    max-width: 380px;
    z-index: 5;
    backdrop-filter: blur(10px);
    box-shadow: 0 6px 18px rgba(0, 0, 0, 0.4);
}}

.floating-terminal .term-line {{
    margin: 2px 0;
    display: flex;
    align-items: center;
    gap: 6px;
}}

.floating-terminal .term-green {{
    color: #10b981;
}}

.floating-terminal .term-dim {{
    color: #64748b;
}}

.radar-wrapper {{
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin-top: 10px;
    margin-bottom: 20px;
    z-index: 5;
}}

.radar-circles {{
    position: relative;
    width: 190px;
    height: 190px;
    display: flex;
    align-items: center;
    justify-content: center;
}}

.radar-ring {{
    position: absolute;
    border-radius: 50%;
    border: 1px dashed rgba(56, 189, 248, 0.35);
    animation: spin-radar 20s linear infinite;
}}

.radar-ring.ring-1 {{
    width: 190px;
    height: 190px;
    border: 1.5px dashed rgba(56, 189, 248, 0.4);
    box-shadow: 0 0 25px rgba(56, 189, 248, 0.15);
}}

.radar-ring.ring-2 {{
    width: 140px;
    height: 140px;
    border: 1px solid rgba(99, 102, 241, 0.4);
    animation: spin-radar-rev 15s linear infinite;
}}

.radar-ring.ring-3 {{
    width: 95px;
    height: 95px;
    border: 1.5px solid rgba(56, 189, 248, 0.6);
    box-shadow: 0 0 15px rgba(56, 189, 248, 0.4);
}}

.radar-sweep {{
    position: absolute;
    width: 190px;
    height: 190px;
    border-radius: 50%;
    background: conic-gradient(from 0deg, rgba(56, 189, 248, 0.35) 0deg, transparent 60deg, transparent 360deg);
    animation: spin-radar 4s linear infinite;
}}

.radar-center-shield {{
    width: 58px;
    height: 58px;
    z-index: 10;
    filter: drop-shadow(0 0 18px rgba(56, 189, 248, 0.95));
    animation: pulse-shield 2.5s ease-in-out infinite;
}}

@keyframes spin-radar {{
    0% {{ transform: rotate(0deg); }}
    100% {{ transform: rotate(360deg); }}
}}

@keyframes spin-radar-rev {{
    0% {{ transform: rotate(360deg); }}
    100% {{ transform: rotate(0deg); }}
}}

@keyframes pulse-shield {{
    0%, 100% {{ transform: scale(1); filter: drop-shadow(0 0 16px rgba(56, 189, 248, 0.9)); }}
    50% {{ transform: scale(1.08); filter: drop-shadow(0 0 26px rgba(56, 189, 248, 1)); }}
}}

.hud-title {{
    font-size: 2.1rem;
    font-weight: 800;
    color: #ffffff;
    margin-top: 18px;
    margin-bottom: 6px;
    letter-spacing: -0.01em;
    text-shadow: 0 0 25px rgba(56, 189, 248, 0.65);
}}

.hud-subtitle {{
    color: #94a3b8;
    font-size: 0.96rem;
    text-align: center;
    max-width: 480px;
    margin: 0;
    line-height: 1.4;
}}

.cyber-grid-container {{
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 180px;
    perspective: 280px;
    overflow: hidden;
    pointer-events: none;
    z-index: 1;
}}

.cyber-grid-plane {{
    position: absolute;
    top: 0;
    left: -50%;
    width: 200%;
    height: 250%;
    background-image: 
        linear-gradient(rgba(56, 189, 248, 0.35) 1.5px, transparent 1.5px),
        linear-gradient(90deg, rgba(56, 189, 248, 0.35) 1.5px, transparent 1.5px);
    background-size: 38px 38px;
    transform: rotateX(68deg);
    transform-origin: top center;
    mask-image: linear-gradient(to bottom, rgba(0,0,0,0.9) 0%, transparent 80%);
    -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,0.9) 0%, transparent 80%);
    animation: grid-scroll 8s linear infinite;
}}

@keyframes grid-scroll {{
    0% {{ background-position: 0 0; }}
    100% {{ background-position: 0 38px; }}
}}

/* ======================================================== */
/* RIGHT COLUMN CARDS                                       */
/* ======================================================== */
.right-sidebar-col {{
    display: flex;
    flex-direction: column;
    gap: 16px;
}}

.tech-panel {{
    background: linear-gradient(135deg, rgba(10, 19, 40, 0.85) 0%, rgba(13, 24, 49, 0.8) 100%);
    border: 1px solid rgba(56, 189, 248, 0.22);
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
    backdrop-filter: blur(12px);
}}

.tech-panel-header {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
    font-weight: 700;
    color: #38bdf8;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    justify-content: space-between;
}}

.tech-panel-header .indicator-dot {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #10b981;
    box-shadow: 0 0 8px #10b981;
}}

.map-container {{
    width: 100%;
    height: 95px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}}

.equalizer-wrap {{
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    height: 70px;
    padding: 4px 6px;
    gap: 4px;
}}

.eq-bar {{
    flex: 1;
    border-radius: 4px 4px 0 0;
    background: linear-gradient(to top, #0284c7, #38bdf8, #818cf8, #c084fc);
    box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
    animation: eq-pulse 2s ease-in-out infinite alternate;
}}

@keyframes eq-pulse {{
    0% {{ transform: scaleY(0.75); opacity: 0.8; }}
    100% {{ transform: scaleY(1.0); opacity: 1; }}
}}

.security-check-list {{
    display: flex;
    flex-direction: column;
    gap: 10px;
}}

.check-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 0.88rem;
    color: #e2e8f0;
    font-weight: 500;
}}

.check-icon-box {{
    width: 20px;
    height: 20px;
    border-radius: 5px;
    background: rgba(56, 189, 248, 0.15);
    border: 1.5px solid #38bdf8;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #38bdf8;
    font-size: 0.75rem;
    box-shadow: 0 0 8px rgba(56, 189, 248, 0.4);
}}

/* Telemetry & Results */
.telemetry-row {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px;
    margin-top: 14px;
    margin-bottom: 14px;
}}

.telemetry-card {{
    background: rgba(10, 18, 38, 0.85);
    border: 1px solid rgba(56, 189, 248, 0.22);
    border-radius: 12px;
    padding: 14px;
    text-align: center;
    backdrop-filter: blur(10px);
}}

.telemetry-label {{
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #94a3b8;
    font-weight: 600;
    margin-bottom: 4px;
}}

.telemetry-val {{
    font-size: 1.6rem;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
}}

div[data-testid="stDataFrame"] {{
    background: rgba(8, 15, 32, 0.85);
    border: 1px solid rgba(56, 189, 248, 0.2);
    border-radius: 12px;
    padding: 6px;
}}
</style>
""")

# SVG Icons
SHIELD_KEYHOLE_SVG = """
<svg viewBox="0 0 100 120" fill="none" xmlns="http://www.w3.org/2000/svg" class="hero-shield-icon">
    <defs>
        <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#00f0ff"/>
            <stop offset="50%" stop-color="#0284c7"/>
            <stop offset="100%" stop-color="#1e1b4b"/>
        </linearGradient>
        <linearGradient id="strokeGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#38bdf8"/>
            <stop offset="100%" stop-color="#818cf8"/>
        </linearGradient>
        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="5" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
    </defs>
    <path d="M50 8L88 24V58C88 84 50 110 50 110C50 110 12 84 12 58V24L50 8Z" fill="url(#shieldGrad)" fill-opacity="0.3" stroke="url(#strokeGrad)" stroke-width="3" filter="url(#glow)"/>
    <path d="M50 18L80 30V56C80 77 50 98 50 98C50 98 20 77 20 56V30L50 18Z" fill="rgba(8, 20, 48, 0.6)" stroke="#38bdf8" stroke-width="1.5" stroke-opacity="0.8"/>
    <circle cx="50" cy="50" r="8" fill="#38bdf8" filter="url(#glow)"/>
    <path d="M46 54L43 68H57L54 54Z" fill="#38bdf8" filter="url(#glow)"/>
</svg>
"""

SMALL_SHIELD_SVG = """
<svg viewBox="0 0 100 120" fill="none" xmlns="http://www.w3.org/2000/svg" class="sidebar-logo-icon">
    <path d="M50 8L88 24V58C88 84 50 110 50 110C50 110 12 84 12 58V24L50 8Z" fill="rgba(14, 165, 233, 0.2)" stroke="#38bdf8" stroke-width="3"/>
    <circle cx="50" cy="50" r="7" fill="#38bdf8"/>
    <path d="M46 54L43 66H57L54 54Z" fill="#38bdf8"/>
</svg>
"""

RADAR_LIGHTNING_SHIELD_SVG = """
<svg viewBox="0 0 100 120" fill="none" xmlns="http://www.w3.org/2000/svg" class="radar-center-shield">
    <defs>
        <filter id="shieldNeonGlow" x="-30%" y="-30%" width="160%" height="160%">
            <feGaussianBlur stdDeviation="6" result="blur"/>
            <feComposite in="SourceGraphic" in2="blur" operator="over"/>
        </filter>
    </defs>
    <path d="M50 8L88 24V58C88 84 50 110 50 110C50 110 12 84 12 58V24L50 8Z" fill="rgba(12, 32, 70, 0.75)" stroke="#38bdf8" stroke-width="3.5" filter="url(#shieldNeonGlow)"/>
    <path d="M54 34L36 58H50L46 84L66 56H52L56 34Z" fill="#38bdf8" filter="url(#shieldNeonGlow)"/>
</svg>
"""

WORLD_MAP_SVG = """
<svg viewBox="0 0 240 100" fill="none" xmlns="http://www.w3.org/2000/svg" style="width:100%; height:100%;">
    <path d="M30 25C35 20 50 22 65 30C60 40 50 45 42 42C32 45 28 35 30 25Z" fill="rgba(56, 189, 248, 0.2)" stroke="rgba(56, 189, 248, 0.45)" stroke-width="1"/>
    <path d="M45 52C50 50 58 55 56 68C52 75 46 82 42 80C40 72 42 60 45 52Z" fill="rgba(56, 189, 248, 0.2)" stroke="rgba(56, 189, 248, 0.45)" stroke-width="1"/>
    <path d="M85 22C95 18 115 20 125 32C120 42 110 40 105 38C98 42 90 35 85 22Z" fill="rgba(56, 189, 248, 0.25)" stroke="rgba(56, 189, 248, 0.5)" stroke-width="1"/>
    <path d="M92 45C102 42 112 50 110 65C105 75 98 72 94 65C90 55 90 48 92 45Z" fill="rgba(56, 189, 248, 0.2)" stroke="rgba(56, 189, 248, 0.45)" stroke-width="1"/>
    <path d="M135 20C155 18 190 22 205 38C198 52 175 50 160 45C148 48 140 38 135 20Z" fill="rgba(56, 189, 248, 0.25)" stroke="rgba(56, 189, 248, 0.5)" stroke-width="1"/>
    <path d="M175 60C185 58 200 62 195 72C190 78 180 78 174 72C172 66 174 62 175 60Z" fill="rgba(56, 189, 248, 0.2)" stroke="rgba(56, 189, 248, 0.45)" stroke-width="1"/>
    <path d="M45 32 Q 90 10 145 28" stroke="rgba(56, 189, 248, 0.6)" stroke-width="1.2" stroke-dasharray="3,3"/>
    <path d="M145 28 Q 170 45 185 65" stroke="rgba(168, 85, 247, 0.6)" stroke-width="1.2" stroke-dasharray="3,3"/>
    <path d="M48 65 Q 100 85 185 65" stroke="rgba(56, 189, 248, 0.4)" stroke-width="1" stroke-dasharray="2,2"/>
    <circle cx="45" cy="32" r="3" fill="#38bdf8" filter="drop-shadow(0 0 5px #38bdf8)"/>
    <circle cx="105" cy="30" r="3" fill="#38bdf8" filter="drop-shadow(0 0 5px #38bdf8)"/>
    <circle cx="145" cy="28" r="3.5" fill="#c084fc" filter="drop-shadow(0 0 6px #c084fc)"/>
    <circle cx="185" cy="65" r="3" fill="#38bdf8" filter="drop-shadow(0 0 5px #38bdf8)"/>
    <circle cx="48" cy="65" r="2.5" fill="#38bdf8"/>
</svg>
"""

def scan_single_port(target_ip, port, socket_timeout):
    t_start = time.perf_counter()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(socket_timeout)
    try:
        res = s.connect_ex((target_ip, port))
        latency = (time.perf_counter() - t_start) * 1000
        if res == 0:
            return True, port, latency
        return False, port, latency
    except Exception:
        return False, port, 0.0
    finally:
        s.close()


# ========================================================
# SIDEBAR
# ========================================================
with st.sidebar:
    render_html(f"""
        <div class="sidebar-brand">
            {SMALL_SHIELD_SVG}
            <h1 class="sidebar-brand-name">Port<span>Sentinel</span></h1>
        </div>
    """)

    selected_view = st.radio(
        "Navigation",
        ["🔍 Scanner", "🕒 Scan History", "📄 Reports", "⚙️ Settings"],
        label_visibility="collapsed",
        key="nav_selection"
    )

    render_html("""<div style="height: 10px;"></div>""")

    render_html("""
        <div class="section-header">
            <span class="icon">⚙️</span> Scanner Configuration
        </div>
    """)

    render_html("""
        <div class="custom-label">
            <span>Target Host / Domain / IP</span>
            <span class="info-badge" title="Enter a valid hostname, domain (e.g. 192.168.1.1, example.com), or IPv4 address.">?</span>
        </div>
    """)
    
    target_input = st.text_input(
        "Target Host / Domain / IP",
        value="",
        placeholder="e.g. 192.168.1.1, example.com, localhost",
        label_visibility="collapsed",
        key="target_host_input"
    ).strip()

    render_html("""
        <div class="custom-label" style="margin-top: 12px;">
            <span>Port Selection Mode</span>
        </div>
    """)

    scan_preset = st.selectbox(
        "Port Selection Mode",
        [
            "⚡ Common Core Ports (Top 25)",
            "🌐 Web & Remote Management",
            "🗄️ Database Ports",
            "🔢 Custom Port Range",
            "✍️ Manual Port List",
        ],
        label_visibility="collapsed",
        key="port_preset_select"
    )

    ports_to_scan = []
    if scan_preset == "⚡ Common Core Ports (Top 25)":
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
        render_html("""<div style="font-size: 0.8rem; color: #64748b; margin-top: 5px;">Will scan 25 most frequently exploited & used ports.</div>""")

    elif scan_preset == "🌐 Web & Remote Management":
        ports_to_scan = [21, 22, 23, 80, 443, 3389, 5900, 8000, 8080, 8443, 8888, 9000]
        render_html(f"""<div style="font-size: 0.8rem; color: #64748b; margin-top: 5px;">Will scan {len(ports_to_scan)} web and administration ports.</div>""")

    elif scan_preset == "🗄️ Database Ports":
        ports_to_scan = [1433, 1521, 3306, 5432, 6379, 9200, 27017]
        render_html(f"""<div style="font-size: 0.8rem; color: #64748b; margin-top: 5px;">Will scan {len(ports_to_scan)} database & cache ports.</div>""")

    elif scan_preset == "🔢 Custom Port Range":
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            start_p = st.number_input("Start", min_value=1, max_value=65535, value=20, step=1)
        with col_r2:
            end_p = st.number_input("End", min_value=1, max_value=65535, value=100, step=1)
        if start_p <= end_p:
            ports_to_scan = list(range(int(start_p), int(end_p) + 1))
            st.caption(f"Total ports: **{len(ports_to_scan):,}**")
        else:
            st.error("Start must be <= End")

    elif scan_preset == "✍️ Manual Port List":
        custom_input = st.text_input("Ports (comma-separated)", value="22, 80, 443, 8080, 3306")
        try:
            ports_to_scan = sorted(list(set(int(p.strip()) for p in custom_input.split(",") if p.strip().isdigit() and 1 <= int(p.strip()) <= 65535)))
            st.caption(f"Parsed ports: **{len(ports_to_scan)}**")
        except Exception:
            st.error("Please enter valid comma-separated integers.")

    render_html("""<div style="height: 14px;"></div>""")

    render_html("""
        <div class="section-header">
            <span class="icon">🚀</span> Performance Tuning
        </div>
    """)

    render_html("""
        <div class="custom-label">
            <span>Concurrency Threads</span>
            <span class="info-badge" title="Number of parallel asynchronous sockets used during scan.">?</span>
        </div>
    """)
    threads = st.slider("Concurrency Threads", min_value=5, max_value=200, value=50, step=5, label_visibility="collapsed")

    render_html("""
        <div class="custom-label" style="margin-top: 8px;">
            <span>Socket Timeout (seconds)</span>
            <span class="info-badge" title="TCP connection timeout before considering port closed or filtered.">?</span>
        </div>
    """)
    timeout = st.slider("Socket Timeout", min_value=0.10, max_value=2.00, value=0.40, step=0.05, format="%.2f", label_visibility="collapsed")

    render_html("""<div style="height: 12px;"></div>""")

    scan_triggered = st.button("▶ Start Scan", key="btn_start_scan", type="primary")

    render_html("""
        <div style="font-size: 0.72rem; color: #475569; margin-top: 24px; line-height: 1.4; text-align: center;">
            🔒 <b>Security Notice:</b> Only scan networks & systems with explicit authorized permission.
        </div>
    """)


# Host Resolution
target_ip = None
hostname_valid = False

if target_input:
    try:
        target_ip = socket.gethostbyname(target_input)
        hostname_valid = True
    except socket.gaierror:
        target_ip = "Unable to resolve"
        hostname_valid = False
else:
    target_ip = "N/A"
    hostname_valid = False


# ========================================================
# MAIN WORKSPACE
# ========================================================
if selected_view == "🔍 Scanner":
    # 1. Top Hero Card
    bg_img_html = f'<img src="data:image/jpeg;base64,{hero_b64}" class="hero-bg-art" alt="Cyber Grid Map" />' if hero_b64 else '<div style="width:100%; height:100%; background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.1));"></div>'

    render_html(f"""
        <div class="hero-banner">
            <div class="hero-left">
                {SHIELD_KEYHOLE_SVG}
                <div class="hero-content">
                    <h1 class="hero-title">Port<span>Sentinel</span></h1>
                    <p class="hero-subtitle">High-Performance Asynchronous Network Reconnaissance & Port Security Analyzer</p>
                    <div class="hero-badges">
                        <span class="hero-badge"><span class="b-icon">🎯</span> Fast Scanning</span>
                        <span class="hero-badge"><span class="b-icon">🛡️</span> Security Focused</span>
                        <span class="hero-badge"><span class="b-icon">📊</span> Detailed Reports</span>
                    </div>
                </div>
            </div>
            <div class="hero-right">
                {bg_img_html}
            </div>
        </div>
    """)

    # 2. Metrics Row (3 cards)
    display_target = target_input if target_input else "No Target Set"
    display_ip = target_ip if hostname_valid else ("Unresolved" if target_input else "N/A")
    display_ports = len(ports_to_scan) if ports_to_scan else 25

    render_html(f"""
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-icon-wrap metric-icon-target">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="22" y1="12" x2="18" y2="12"></line>
                        <line x1="6" y1="12" x2="2" y2="12"></line>
                        <line x1="12" y1="6" x2="12" y2="2"></line>
                        <line x1="12" y1="22" x2="12" y2="18"></line>
                    </svg>
                </div>
                <div class="metric-info">
                    <span class="metric-label">Target</span>
                    <span class="metric-value">{display_target}</span>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon-wrap metric-icon-ip">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"></path>
                        <circle cx="12" cy="10" r="3"></circle>
                    </svg>
                </div>
                <div class="metric-info">
                    <span class="metric-label">IPv4 Address</span>
                    <span class="metric-value">{display_ip}</span>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon-wrap metric-icon-ports">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"></path>
                    </svg>
                </div>
                <div class="metric-info">
                    <span class="metric-label">Ports Queued</span>
                    <span class="metric-value">{display_ports}</span>
                </div>
            </div>
        </div>
    """)

    # 3. Main Workspace Row (HUD + Side Panels)
    if not scan_triggered and "last_scan_completed" not in st.session_state:
        render_html(f"""
            <div class="workspace-row">
                <div class="center-hud-card">
                    <div class="floating-terminal">
                        <div class="term-line"><span class="term-dim">></span> Resolving target...</div>
                        <div class="term-line"><span class="term-dim">></span> Loading port list...</div>
                        <div class="term-line"><span class="term-dim">></span> Initializing scanner...</div>
                        <div class="term-line"><span class="term-green">> Ready.</span></div>
                    </div>

                    <div class="radar-wrapper">
                        <div class="radar-circles">
                            <div class="radar-ring ring-1"></div>
                            <div class="radar-ring ring-2"></div>
                            <div class="radar-ring ring-3"></div>
                            <div class="radar-sweep"></div>
                            {RADAR_LIGHTNING_SHIELD_SVG}
                        </div>
                        <div class="hud-title">Ready to Scan</div>
                        <p class="hud-subtitle">Scan for open ports, detect potential vulnerabilities and secure your network.</p>
                    </div>

                    <div class="cyber-grid-container">
                        <div class="cyber-grid-plane"></div>
                    </div>
                </div>

                <div class="right-sidebar-col">
                    <div class="tech-panel">
                        <div class="tech-panel-header">
                            <span>Network Scan</span>
                            <span class="indicator-dot"></span>
                        </div>
                        <div class="map-container">
                            {WORLD_MAP_SVG}
                        </div>
                    </div>

                    <div class="tech-panel">
                        <div class="tech-panel-header">
                            <span>Port Analysis</span>
                            <span style="font-size: 0.72rem; color: #64748b;">ACTIVE</span>
                        </div>
                        <div class="equalizer-wrap">
                            <div class="eq-bar" style="height: 35%; animation-delay: 0.1s;"></div>
                            <div class="eq-bar" style="height: 55%; animation-delay: 0.4s;"></div>
                            <div class="eq-bar" style="height: 80%; animation-delay: 0.2s;"></div>
                            <div class="eq-bar" style="height: 40%; animation-delay: 0.6s;"></div>
                            <div class="eq-bar" style="height: 95%; animation-delay: 0.3s;"></div>
                            <div class="eq-bar" style="height: 60%; animation-delay: 0.5s;"></div>
                            <div class="eq-bar" style="height: 85%; animation-delay: 0.15s;"></div>
                            <div class="eq-bar" style="height: 50%; animation-delay: 0.7s;"></div>
                            <div class="eq-bar" style="height: 70%; animation-delay: 0.35s;"></div>
                            <div class="eq-bar" style="height: 90%; animation-delay: 0.45s;"></div>
                        </div>
                    </div>

                    <div class="tech-panel">
                        <div class="tech-panel-header">
                            <span>Security Check</span>
                            <span style="font-size: 0.72rem; color: #38bdf8;">OK</span>
                        </div>
                        <div class="security-check-list">
                            <div class="check-item">
                                <div class="check-icon-box">✓</div>
                                <span>Scan Engine Ready</span>
                            </div>
                            <div class="check-item">
                                <div class="check-icon-box">✓</div>
                                <span>Port Database Loaded</span>
                            </div>
                            <div class="check-item">
                                <div class="check-icon-box">✓</div>
                                <span>Awaiting Target</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        """)

    # 4. Active Scan Execution
    if scan_triggered:
        if not target_input:
            st.error("❌ Please enter a target host, domain, or IP address before scanning.")
        elif not hostname_valid or not target_ip:
            st.error(f"❌ Target resolution failed: `{target_input}` could not be resolved.")
        elif not ports_to_scan:
            st.warning("⚠️ No ports selected. Please configure port presets.")
        else:
            render_html(f"""
                <div class="workspace-row">
                    <div class="center-hud-card" style="min-height: 380px;">
                        <div class="floating-terminal" style="max-width: 100%; width: 100%;">
                            <div class="term-line"><span class="term-green">></span> Probing {len(ports_to_scan)} ports on {display_target} ({target_ip})...</div>
                            <div class="term-line"><span class="term-dim">> Concurrency: {threads} threads | Timeout: {timeout:.2f}s</span></div>
                        </div>
                        <div class="radar-wrapper" style="margin-top: 15px;">
                            <div class="radar-circles" style="width: 140px; height: 140px;">
                                <div class="radar-ring ring-1" style="width: 140px; height: 140px;"></div>
                                <div class="radar-sweep" style="width: 140px; height: 140px; animation-duration: 1.5s;"></div>
                                {RADAR_LIGHTNING_SHIELD_SVG}
                            </div>
                            <div class="hud-title" style="font-size: 1.7rem; margin-top: 10px;">Scanning In Progress...</div>
                        </div>
                        <div class="cyber-grid-container" style="height: 120px;">
                            <div class="cyber-grid-plane"></div>
                        </div>
                    </div>

                    <div class="right-sidebar-col">
                        <div class="tech-panel">
                            <div class="tech-panel-header">
                                <span>Live Probe</span>
                                <span class="indicator-dot" style="background: #38bdf8; box-shadow: 0 0 10px #38bdf8;"></span>
                            </div>
                            <div class="security-check-list">
                                <div class="check-item"><div class="check-icon-box">⚡</div> Socket Pool Dispatched</div>
                                <div class="check-item"><div class="check-icon-box">🔍</div> Banner Grabbing Active</div>
                                <div class="check-item"><div class="check-icon-box">🛡️</div> Security Risk Profiler On</div>
                            </div>
                        </div>
                        <div class="tech-panel">
                            <div class="tech-panel-header">
                                <span>Telemetry</span>
                            </div>
                            <div class="equalizer-wrap" style="height: 80px;">
                                <div class="eq-bar" style="height: 65%;"></div>
                                <div class="eq-bar" style="height: 90%;"></div>
                                <div class="eq-bar" style="height: 45%;"></div>
                                <div class="eq-bar" style="height: 100%;"></div>
                                <div class="eq-bar" style="height: 80%;"></div>
                                <div class="eq-bar" style="height: 55%;"></div>
                                <div class="eq-bar" style="height: 95%;"></div>
                            </div>
                        </div>
                    </div>
                </div>
            """)

            telemetry_placeholder = st.empty()
            progress_bar = st.progress(0.0)
            status_text = st.empty()

            open_ports_data = []
            total_ports = len(ports_to_scan)
            scanned_count = 0
            scan_start_time = time.time()
            log_messages = []

            with ThreadPoolExecutor(max_workers=threads) as executor:
                future_to_port = {
                    executor.submit(scan_single_port, target_ip, p, timeout): p 
                    for p in ports_to_scan
                }

                for future in as_completed(future_to_port):
                    scanned_count += 1
                    is_open, port, latency = future.result()

                    if is_open:
                        service_info, category, risk = COMMON_SERVICES.get(
                            port, ("Unknown Service", "General / Custom", "Low")
                        )
                        open_ports_data.append({
                            "Port": port,
                            "Service": service_info,
                            "Category": category,
                            "Risk Level": risk,
                            "Latency (ms)": round(latency, 1),
                            "Status": "OPEN"
                        })
                        log_messages.append(f"[+] OPEN: Port {port:<5} | {service_info} ({category}) ~ {latency:.1f}ms")

                    if scanned_count % max(1, total_ports // 25) == 0 or scanned_count == total_ports:
                        elapsed = max(0.001, time.time() - scan_start_time)
                        rate = scanned_count / elapsed
                        fraction = scanned_count / total_ports

                        progress_bar.progress(fraction)
                        status_text.markdown(f"""
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #38bdf8;">
                                🛰️ Checking: {scanned_count}/{total_ports} ports probed ({fraction * 100:.1f}%) | Speed: {rate:.1f} ports/s
                            </div>
                        """, unsafe_allow_html=True)

                        telemetry_placeholder.markdown(f"""
                            <div class="telemetry-row">
                                <div class="telemetry-card">
                                    <div class="telemetry-label">Open Ports</div>
                                    <div class="telemetry-val" style="color: #34d399;">{len(open_ports_data)}</div>
                                </div>
                                <div class="telemetry-card">
                                    <div class="telemetry-label">Probed / Total</div>
                                    <div class="telemetry-val" style="color: #38bdf8;">{scanned_count} / {total_ports}</div>
                                </div>
                                <div class="telemetry-card">
                                    <div class="telemetry-label">Scan Speed</div>
                                    <div class="telemetry-val" style="color: #c084fc;">{rate:.1f} p/s</div>
                                </div>
                                <div class="telemetry-card">
                                    <div class="telemetry-label">Elapsed Time</div>
                                    <div class="telemetry-val" style="color: #facc15;">{elapsed:.1f}s</div>
                                </div>
                            </div>
                        """, unsafe_allow_html=True)

            total_elapsed = time.time() - scan_start_time
            progress_bar.progress(1.0)
            status_text.markdown(f"""
                <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; color: #34d399; margin-bottom: 15px;">
                    ✅ Scan Completed in {total_elapsed:.2f}s ({total_ports} ports checked at {(total_ports/max(0.01, total_elapsed)):.1f} ports/sec).
                </div>
            """, unsafe_allow_html=True)

            st.session_state["last_scan_completed"] = True
            st.session_state["open_ports"] = open_ports_data
            st.session_state["last_target"] = target_input
            st.session_state["last_ip"] = target_ip
            st.session_state["scan_duration"] = total_elapsed
            st.session_state["total_ports"] = total_ports

            st.session_state["scan_history"].append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": target_input,
                "ip": target_ip,
                "open_count": len(open_ports_data),
                "total_scanned": total_ports,
                "duration": f"{total_elapsed:.2f}s",
                "results": open_ports_data
            })

    # 5. Results Display
    if "open_ports" in st.session_state and st.session_state["open_ports"] is not None:
        open_ports_data = st.session_state["open_ports"]
        
        render_html("""
            <div style="margin-top: 25px; margin-bottom: 15px; display: flex; align-items: center; justify-content: space-between;">
                <h3 style="margin: 0; font-size: 1.4rem; font-weight: 800; color: #ffffff;">
                    📊 Scan Intelligence & Findings
                </h3>
            </div>
        """)

        if len(open_ports_data) == 0:
            st.info("ℹ️ No open ports were discovered for the selected range and socket timeout.")
        else:
            df = pd.DataFrame(open_ports_data).sort_values(by="Port").reset_index(drop=True)

            tab_table, tab_analysis, tab_export = st.tabs(["📋 Open Ports Analysis", "📈 Category & Risk Breakdown", "💾 Export Intelligence Report"])

            with tab_table:
                st.dataframe(
                    df,
                    use_container_width=True,
                    column_config={
                        "Port": st.column_config.NumberColumn(format="%d"),
                        "Latency (ms)": st.column_config.NumberColumn(format="%.1f ms"),
                    }
                )

            with tab_analysis:
                col_c1, col_c2 = st.columns([1, 1])
                with col_c1:
                    st.markdown("#### Service Categories")
                    cat_counts = df['Category'].value_counts()
                    st.bar_chart(cat_counts)

                with col_c2:
                    st.markdown("#### Security Risk Guidance")
                    for item in open_ports_data:
                        p = item["Port"]
                        s = item["Service"]
                        r = item["Risk Level"]
                        if "CRITICAL" in r:
                            st.error(f"🚨 **Port {p} ({s})** — **{r}**: Immediate action required! Restrict access or apply mandatory authentication.")
                        elif "HIGH" in r:
                            st.warning(f"⚠️ **Port {p} ({s})** — **{r}**: Ensure this service is firewalled or bound to internal interfaces only.")
                        else:
                            st.info(f"ℹ️ **Port {p} ({s})** — {r}")

            with tab_export:
                col_e1, col_e2 = st.columns(2)
                with col_e1:
                    csv_data = df.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="📥 Download CSV Intelligence Report",
                        data=csv_data,
                        file_name=f"portsentinel_{st.session_state.get('last_ip', 'target')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv",
                        use_container_width=True
                    )
                with col_e2:
                    export_dict = {
                        "tool": "PortSentinel Network Scanner",
                        "timestamp": datetime.now().isoformat(),
                        "target_host": st.session_state.get("last_target"),
                        "target_ip": st.session_state.get("last_ip"),
                        "total_probed": st.session_state.get("total_ports"),
                        "duration_seconds": round(st.session_state.get("scan_duration", 0), 2),
                        "open_ports": open_ports_data
                    }
                    st.download_button(
                        label="📥 Download JSON Security Intelligence",
                        data=json.dumps(export_dict, indent=2).encode('utf-8'),
                        file_name=f"portsentinel_{st.session_state.get('last_ip', 'target')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )


# ========================================================
# SCAN HISTORY VIEW
# ========================================================
elif selected_view == "🕒 Scan History":
    render_html("""
        <div class="hero-banner" style="padding: 20px 24px;">
            <div class="hero-left">
                <div style="font-size: 2.5rem;">🕒</div>
                <div class="hero-content">
                    <h1 class="hero-title">Scan <span>History</span></h1>
                    <p class="hero-subtitle">Chronological audit log of all target scans executed in this session.</p>
                </div>
            </div>
        </div>
    """)

    if not st.session_state["scan_history"]:
        st.info("ℹ️ No scans recorded in this session yet. Launch a scan from the Scanner tab.")
    else:
        history_df = pd.DataFrame([
            {
                "Timestamp": h["timestamp"],
                "Target": h["target"],
                "IPv4": h["ip"],
                "Open Ports": h["open_count"],
                "Total Ports": h["total_scanned"],
                "Duration": h["duration"]
            }
            for h in reversed(st.session_state["scan_history"])
        ])
        st.dataframe(history_df, use_container_width=True)


# ========================================================
# REPORTS VIEW
# ========================================================
elif selected_view == "📄 Reports":
    render_html("""
        <div class="hero-banner" style="padding: 20px 24px;">
            <div class="hero-left">
                <div style="font-size: 2.5rem;">📄</div>
                <div class="hero-content">
                    <h1 class="hero-title">Security <span>Reports</span></h1>
                    <p class="hero-subtitle">Consolidated vulnerability intelligence dossiers and threat posture analysis.</p>
                </div>
            </div>
        </div>
    """)

    if not st.session_state.get("open_ports"):
        st.info("ℹ️ No active scan data available to generate a report. Please run a scan first.")
    else:
        open_data = st.session_state["open_ports"]
        render_html(f"""
            <div class="tech-panel" style="margin-bottom: 20px;">
                <h4 style="color: #38bdf8; margin-top:0;">Dossier: {st.session_state.get('last_target')} ({st.session_state.get('last_ip')})</h4>
                <p style="color: #94a3b8; font-size: 0.9rem;">
                    Scan completed in <b>{st.session_state.get('scan_duration', 0):.2f}s</b>. 
                    Detected <b>{len(open_data)}</b> open ports across <b>{st.session_state.get('total_ports', 0)}</b> scanned endpoints.
                </p>
            </div>
        """)
        st.dataframe(pd.DataFrame(open_data), use_container_width=True)


# ========================================================
# SETTINGS VIEW
# ========================================================
elif selected_view == "⚙️ Settings":
    render_html("""
        <div class="hero-banner" style="padding: 20px 24px;">
            <div class="hero-left">
                <div style="font-size: 2.5rem;">⚙️</div>
                <div class="hero-content">
                    <h1 class="hero-title">Scanner <span>Settings</span></h1>
                    <p class="hero-subtitle">Configure operational parameters, DNS resolvers, and default scan profiles.</p>
                </div>
            </div>
        </div>
    """)

    col_s1, col_s2 = st.columns(2)
    with col_s1:
        st.markdown("#### Scanner Presets & Probes")
        st.checkbox("Enable Automatic Reverse DNS Lookup", value=True)
        st.checkbox("Highlight High-Risk & Critical CVE Vectors", value=True)
        st.checkbox("Show Monospace Live Terminal Telemetry", value=True)
    with col_s2:
        st.markdown("#### Network Socket Limits")
        st.number_input("Maximum Thread Pool Size", min_value=10, max_value=500, value=100)
        st.number_input("Default Socket Connect Timeout (s)", min_value=0.05, max_value=5.0, value=0.40, step=0.05)
