import tkinter as tk
from tkinter import scrolledtext, messagebox
import re
from urllib.parse import urlparse
import tldextract

# --- Detection Logic ---
suspicious_keywords = [
    "verify your account", "login now", "click here", "update password",
    "account suspended", "urgent action", "confirm identity",
    "unauthorized access", "validate account", "reset your password"
]

def detect_keywords(text):
    return [kw for kw in suspicious_keywords if kw.lower() in text.lower()]

def extract_urls(text):
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def is_suspicious_url(url):
    suspicious_words = ['login', 'secure', 'verify', 'paypal', 'bank', 'signin']
    domain = tldextract.extract(url).domain
    return any(word in domain.lower() for word in suspicious_words)

def detect_suspicious_urls(text):
    urls = extract_urls(text)
    return [url for url in urls if is_suspicious_url(url)]

def phishing_score(keywords, urls):
    return len(keywords) * 2 + len(urls) * 3

def classify_email(score):
    if score >= 6:
        return "⚠️ Likely Phishing"
    elif score >= 3:
        return "⚠️ Suspicious"
    else:
        return "✅ Likely Safe"

# --- GUI App ---
def scan_email():
    content = email_input.get("1.0", tk.END)
    if not content.strip():
        messagebox.showwarning("Empty Input", "Please paste email content to scan.")
        return

    keywords = detect_keywords(content)
    urls = detect_suspicious_urls(content)
    score = phishing_score(keywords, urls)
    verdict = classify_email(score)

    result_output.config(state="normal")
    result_output.delete("1.0", tk.END)
    result_output.insert(tk.END, f"Verdict: {verdict}\n\n")
    result_output.insert(tk.END, f"Suspicious Keywords: {keywords}\n")
    result_output.insert(tk.END, f"Suspicious URLs: {urls}\n")
    result_output.insert(tk.END, f"Score: {score}\n")
    result_output.config(state="disabled")

# GUI layout
root = tk.Tk()
root.title("Phishing Email Detector")
root.geometry("600x600")

tk.Label(root, text="Paste Email Content Below:", font=("Arial", 12)).pack(pady=5)
email_input = scrolledtext.ScrolledText(root, height=15, width=70)
email_input.pack(pady=5)

tk.Button(root, text="Scan Email", font=("Arial", 12), command=scan_email).pack(pady=10)

tk.Label(root, text="Scan Result:", font=("Arial", 12)).pack(pady=5)
result_output = scrolledtext.ScrolledText(root, height=10, width=70, state="disabled", bg="#f0f0f0")
result_output.pack(pady=5)

root.mainloop()
