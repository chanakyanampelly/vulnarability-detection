from flask import Flask, render_template, request
from markupsafe import Markup
import re
import tldextract
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# --- Keyword Lists ---
suspicious_keywords = [
    "verify your account", "login now", "click here", "update password",
    "account suspended", "urgent action", "confirm identity",
    "unauthorized access", "validate account", "reset your password"
]

malware_keywords = [
    "malware", "virus", "trojan", "ransomware", "spyware",
    "keylogger", "rootkit", "worm", "payload", "backdoor"
]

trojan_keywords = [
    "trojan", "trojan horse", "remote access tool", "rat",
    "dropper", "botnet", "zombie", "exploit", "payload"
]

# --- Detection Functions ---
def detect_keywords(text):
    return [kw for kw in suspicious_keywords if kw.lower() in text.lower()]

def detect_malware_keywords(text):
    return [kw for kw in malware_keywords if kw.lower() in text.lower()]

def detect_trojan_keywords(text):
    return [kw for kw in trojan_keywords if kw.lower() in text.lower()]

def extract_urls(text):
    return re.findall(r'https?://[^\s,)<>"\']+', text)

def is_suspicious_url(url):
    suspicious_words = ['login', 'secure', 'verify', 'paypal', 'bank', 'signin']
    domain = tldextract.extract(url).domain
    return any(word in domain.lower() for word in suspicious_words)

def get_url_details(url):
    parsed = tldextract.extract(url)
    domain = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
    path = urlparse(url).path
    return {
        "url": url,
        "domain": domain,
        "path": path if path else "/"
    }

def detect_suspicious_urls(text):
    urls = extract_urls(text)
    suspicious_urls = [url for url in urls if is_suspicious_url(url)]
    return [get_url_details(url) for url in suspicious_urls]

# --- Scoring & Classification ---
def phishing_score(keywords, urls, malware_kw, trojan_kw):
    return len(keywords) * 2 + len(urls) * 3 + len(malware_kw) * 4 + len(trojan_kw) * 5

def classify_email(score):
    if score >= 6:
        return "⚠️ Likely Phishing"
    elif score >= 3:
        return "⚠️ Suspicious"
    else:
        return "✅ Likely Safe"

# --- Highlight Function ---
def highlight_text(content, keywords, urls):
    highlighted = content
    # Highlight keywords longest first
    for kw in sorted(set(keywords), key=len, reverse=True):
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda match: f"<mark class='highlight-keyword'>{match.group(0)}</mark>",
            highlighted
        )
    # Highlight URLs
    for url in urls:
        highlighted = highlighted.replace(url, f"<mark class='highlight-url'>{url}</mark>")
    return highlighted

# --- Main Route ---
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    highlighted_content = ""
    if request.method == "POST":
        content = request.form.get("email_content", "").strip()

        keywords = detect_keywords(content)
        detailed_urls = detect_suspicious_urls(content)
        malware_kw = detect_malware_keywords(content)
        trojan_kw = detect_trojan_keywords(content)

        score = phishing_score(keywords, detailed_urls, malware_kw, trojan_kw)
        verdict = classify_email(score)

        all_keywords = keywords + malware_kw + trojan_kw
        highlighted_content = highlight_text(content, all_keywords, [d['url'] for d in detailed_urls])

        result = {
            "verdict": verdict,
            "keywords": keywords,
            "urls": detailed_urls,
            "score": score,
            "highlighted": Markup(highlighted_content),
            "malware_keywords": malware_kw,
            "trojan_keywords": trojan_kw,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    return render_template("index.html", result=result)

# --- Run App ---
if __name__ == "__main__":
    app.run(debug=True)
