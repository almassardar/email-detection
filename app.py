from flask import Flask, request, jsonify, render_template
import re
import math

app = Flask(__name__)

# --- Rule-based spam detection engine ---

SPAM_KEYWORDS = [
    "free", "win", "winner", "won", "prize", "claim", "urgent", "act now",
    "limited time", "offer expires", "click here", "buy now", "order now",
    "100% free", "guaranteed", "no risk", "risk free", "satisfaction guaranteed",
    "million dollars", "billion dollars", "lottery", "jackpot", "congratulations",
    "selected", "chosen", "exclusive deal", "make money", "earn money",
    "work from home", "extra income", "passive income", "financial freedom",
    "credit card", "debt", "loan", "mortgage", "investment opportunity",
    "double your", "triple your", "increase your", "online pharmacy",
    "weight loss", "diet pills", "miracle", "cure", "treatment",
    "enlargement", "enhancement", "adult", "xxx", "hot singles",
    "password", "verify your account", "suspended", "confirm your",
    "bank account", "social security", "ssn", "tax refund",
    "nigerian prince", "inheritance", "transfer funds", "wire transfer",
    "gift card", "itunes", "amazon gift", "google play gift",
    "you have been selected", "dear friend", "dear customer",
    "unsubscribe", "remove me", "opt out", "do not reply",
]

URGENCY_PHRASES = [
    "act now", "act immediately", "respond immediately", "reply now",
    "limited time", "expires soon", "offer ends", "last chance",
    "today only", "24 hours", "48 hours", "time sensitive",
    "urgent", "immediately", "asap", "right away",
]

SUSPICIOUS_PATTERNS = [
    r'\$[\d,]+',               # dollar amounts
    r'\d+%\s*(off|discount)',  # percentage discounts
    r'https?://\S+',           # URLs
    r'[A-Z]{5,}',              # ALL CAPS words
    r'!{2,}',                  # multiple exclamation marks
    r'\?{2,}',                 # multiple question marks
    r'[\$£€]{2,}',             # multiple currency symbols
    r'(.)\1{4,}',              # repeated characters (aaaa...)
    r'\b(free|FREE)\b',        # FREE keyword
]

PHISHING_INDICATORS = [
    "verify your", "confirm your", "update your", "validate your",
    "account suspended", "account locked", "account compromised",
    "click the link", "click here to", "follow this link",
    "login to", "sign in to", "access your account",
    "your password", "reset your password", "forgot password",
    "dear user", "dear account holder", "dear valued customer",
    "paypal", "ebay", "amazon", "netflix", "apple", "microsoft",
    "google", "facebook", "bank of", "chase bank", "wells fargo",
]


def analyze_email(subject: str, body: str, sender: str = "") -> dict:
    text = f"{subject} {body} {sender}".lower()
    full_text = f"{subject} {body}"
    word_count = len(full_text.split()) if full_text.strip() else 1

    signals = []
    score = 0

    # 1. Spam keywords
    found_keywords = [kw for kw in SPAM_KEYWORDS if kw in text]
    if found_keywords:
        kw_score = min(35, len(found_keywords) * 5)
        score += kw_score
        signals.append({
            "type": "warning",
            "category": "Spam keywords",
            "text": f"Found {len(found_keywords)} spam keyword(s): {', '.join(found_keywords[:5])}{'...' if len(found_keywords) > 5 else ''}"
        })

    # 2. Urgency phrases
    found_urgency = [p for p in URGENCY_PHRASES if p in text]
    if found_urgency:
        score += min(15, len(found_urgency) * 5)
        signals.append({
            "type": "warning",
            "category": "Urgency tactics",
            "text": f"Urgency language detected: {', '.join(found_urgency[:3])}"
        })

    # 3. Suspicious patterns
    pattern_hits = []
    for pattern in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, full_text)
        if matches:
            pattern_hits.extend(matches[:2])

    if pattern_hits:
        score += min(20, len(pattern_hits) * 3)
        signals.append({
            "type": "warning",
            "category": "Suspicious formatting",
            "text": f"Suspicious patterns found: {', '.join(str(h) for h in pattern_hits[:4])}"
        })

    # 4. Phishing indicators
    found_phishing = [p for p in PHISHING_INDICATORS if p in text]
    if found_phishing:
        score += min(25, len(found_phishing) * 6)
        signals.append({
            "type": "warning",
            "category": "Phishing indicators",
            "text": f"Possible phishing attempt — mimics legitimate services or requests credentials"
        })

    # 5. ALL CAPS ratio
    caps_words = re.findall(r'\b[A-Z]{3,}\b', full_text)
    total_words = len(full_text.split())
    if total_words > 0:
        caps_ratio = len(caps_words) / total_words
        if caps_ratio > 0.15:
            score += 10
            signals.append({
                "type": "warning",
                "category": "Excessive caps",
                "text": f"{len(caps_words)} ALL-CAPS words detected ({caps_ratio*100:.0f}% of content)"
            })

    # 6. Exclamation mark abuse
    excl_count = full_text.count('!')
    if excl_count >= 3:
        score += min(10, excl_count * 2)
        signals.append({
            "type": "warning",
            "category": "Punctuation abuse",
            "text": f"{excl_count} exclamation marks — typical of spam formatting"
        })

    # 7. URL count
    urls = re.findall(r'https?://\S+', full_text)
    if len(urls) > 2:
        score += min(10, (len(urls) - 2) * 3)
        signals.append({
            "type": "warning",
            "category": "Excessive links",
            "text": f"{len(urls)} URLs found — high link density is a spam signal"
        })
    elif len(urls) == 0 and word_count > 30:
        signals.append({
            "type": "info",
            "category": "No external links",
            "text": "No URLs detected in the email body"
        })

    # 8. Subject line analysis
    if subject:
        subj_lower = subject.lower()
        if re.search(r're:|fwd:', subj_lower) and not any(k in subj_lower for k in ["free", "win", "prize"]):
            signals.append({
                "type": "info",
                "category": "Reply/forward chain",
                "text": "Subject line appears to be part of a reply or forward chain"
            })
        if len(subject) > 80:
            score += 5
            signals.append({
                "type": "warning",
                "category": "Long subject",
                "text": f"Subject line is {len(subject)} characters — unusually long"
            })

    # 9. Sender analysis
    if sender:
        if re.search(r'\d{4,}', sender):
            score += 8
            signals.append({
                "type": "warning",
                "category": "Suspicious sender",
                "text": "Sender address contains many numbers — common in spam accounts"
            })
        if not re.search(r'@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', sender):
            score += 5
            signals.append({
                "type": "warning",
                "category": "Invalid sender format",
                "text": "Sender address format appears invalid or malformed"
            })

    # 10. Positive signals
    if not found_keywords and not found_urgency and not found_phishing:
        signals.append({
            "type": "ok",
            "category": "Clean language",
            "text": "No spam keywords, urgency phrases, or phishing indicators found"
        })

    if len(urls) <= 2 and len(urls) >= 0:
        if not found_phishing:
            signals.append({
                "type": "ok",
                "category": "Normal link density",
                "text": "Link count is within normal range"
            })

    # Cap score at 100
    score = min(100, max(0, score))

    # Determine verdict
    if score >= 60:
        verdict = "spam"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    # Confidence level
    if score >= 75 or score <= 15:
        confidence = "High"
    elif score >= 50 or score <= 30:
        confidence = "Medium"
    else:
        confidence = "Low"

    # Summary
    if verdict == "spam":
        summary = f"This email shows strong spam characteristics (score: {score}/100). It is likely unsolicited or malicious and should not be trusted."
    elif verdict == "suspicious":
        summary = f"This email has some suspicious characteristics (score: {score}/100). Exercise caution before clicking links or responding."
    else:
        summary = f"This email appears legitimate (score: {score}/100). No significant spam signals were detected."

    return {
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "summary": summary,
        "signals": signals,
        "stats": {
            "word_count": word_count,
            "url_count": len(urls),
            "exclamation_count": excl_count,
            "caps_words": len(caps_words),
            "spam_keywords": len(found_keywords),
        }
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    subject = data.get("subject", "").strip()
    body = data.get("body", "").strip()
    sender = data.get("sender", "").strip()

    if not subject and not body:
        return jsonify({"error": "Please provide a subject or body to analyze."}), 400

    result = analyze_email(subject, body, sender)
    return jsonify(result)


@app.route("/examples", methods=["GET"])
def examples():
    return jsonify([
        {
            "name": "Nigerian prince scam",
            "sender": "prince.alhaji44221@yahoo.com",
            "subject": "URGENT: Confidential Business Proposal - $15,000,000 USD",
            "body": "Dear Friend, I am a Nigerian prince seeking to transfer $15,000,000 USD. You have been SELECTED to help me. This is 100% FREE and GUARANTEED. ACT NOW!! Click here immediately to claim your share. Limited time offer expires in 24 hours!!!"
        },
        {
            "name": "Phishing — PayPal",
            "sender": "security@paypa1-support.com",
            "subject": "Your PayPal account has been suspended",
            "body": "Dear valued customer, Your PayPal account has been suspended due to suspicious activity. Please verify your account immediately by clicking the link below. Failure to confirm your account within 24 hours will result in permanent suspension. Click here to restore your account."
        },
        {
            "name": "Legitimate email",
            "sender": "alice@company.com",
            "subject": "Re: Project update for Q3",
            "body": "Hi team, Just wanted to share the latest update on the project. We're on track for the deadline next Friday. Please review the attached document and let me know if you have any questions. Thanks, Alice"
        },
        {
            "name": "Promotional spam",
            "subject": "YOU WON!!! Claim your FREE iPhone 15 NOW!!!",
            "sender": "noreply@promo-deals99923.biz",
            "body": "CONGRATULATIONS!!! You have been SELECTED as our lucky winner! Claim your FREE iPhone 15 and $500 gift card NOW!!! Limited time offer — only 10 remaining! BUY NOW and get 100% satisfaction guaranteed! No risk! Click here immediately!!!"
        }
    ])


import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)