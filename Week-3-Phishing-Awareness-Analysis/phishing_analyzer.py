
# =====================================================
#       PHISHING TRIAGE TOOLKIT
#       Cybersecurity Internship - Week 3
# =====================================================

import re
import ipaddress
import json
import os

from urllib.parse import urlparse
from email.utils import parseaddr
from datetime import datetime

# -----------------------------------------------------
# MODULE 1: EMAIL INPUT
# -----------------------------------------------------

def get_email_input():

    print("=" * 55)
    print("             PHISHING TRIAGE TOOLKIT")
    print("=" * 55)

    print("\nEnter the suspicious email details below.\n")

    sender = input("Sender Email Address: ").strip()
    return_path = input("Return-Path Address: ").strip()
    subject = input("Email Subject: ").strip()
    body = input("Email Message Body: ").strip()

    attachments_input = input(
        "Attachment Names (comma separated, or press Enter): "
    ).strip()

    attachments = [
        item.strip()
        for item in attachments_input.split(",")
        if item.strip()
    ]

    email_data = {
        "sender": sender,
        "return_path": return_path,
        "subject": subject,
        "body": body,
        "attachments": attachments
    }

    return email_data


# -----------------------------------------------------
# MODULE 2: EMAIL ADDRESS VALIDATION
# -----------------------------------------------------

def get_email_address(address):

    display_name, email_address = parseaddr(address)

    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"

    if re.match(pattern, email_address):
        return email_address.lower()

    return None


# -----------------------------------------------------
# MODULE 3: HEADER ANALYSIS
# -----------------------------------------------------

def analyze_headers(email_data):

    red_flags = []

    sender = get_email_address(email_data["sender"])
    return_path = get_email_address(email_data["return_path"])

    print("\n" + "=" * 55)
    print("                 HEADER ANALYSIS")
    print("=" * 55)

    # Check sender address

    if sender is None:
        red_flags.append(
            "Sender address is missing or has an invalid format."
        )
        print("[WARNING] Invalid sender email address.")

    else:
        print("[INFO] Sender address:", sender)

    # Check Return-Path address

    if return_path is None:
        red_flags.append(
            "Return-Path is missing or has an invalid format."
        )
        print("[WARNING] Invalid or missing Return-Path.")

    else:
        print("[INFO] Return-Path:", return_path)

    # Compare sender and Return-Path domains

    if sender and return_path:

        sender_domain = sender.split("@")[-1]
        return_domain = return_path.split("@")[-1]

        if sender_domain != return_domain:

            red_flags.append(
                "Sender domain and Return-Path domain do not match."
            )

            print("[WARNING] Sender and Return-Path domains differ.")

        else:
            print("[INFO] Sender and Return-Path domains match.")

    print("\nHeader analysis completed.")

    return red_flags


# -----------------------------------------------------
# MODULE 4: SUSPICIOUS URL ANALYSIS
# -----------------------------------------------------

def analyze_urls(message):

    url_flags = []

    # Find URLs inside the email message
    url_pattern = re.compile(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        re.IGNORECASE
    )

    urls = url_pattern.findall(message)

    # Common URL shorteners
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "shorturl.at"
    }

    # Common brand domains for basic lookalike checks
    brand_domains = {
        "microsoft": ["microsoft.com"],
        "google": ["google.com"],
        "paypal": ["paypal.com"],
        "amazon": ["amazon.com"]
    }

    print("\n" + "=" * 55)
    print("                 URL ANALYSIS")
    print("=" * 55)

    if not urls:
        print("[INFO] No URLs found in the message.")
        return url_flags

    for url in urls:

        # Remove punctuation at the end of a URL
        url = url.rstrip(".,!?;:)]}")

        # Add a scheme if the URL starts with www
        if url.lower().startswith("www."):
            parsed = urlparse("http://" + url)
        else:
            parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            url_flags.append(
                f"Could not identify the hostname in: {url}"
            )
            continue

        hostname = hostname.lower()

        print("\n[INFO] URL found:", url)
        print("[INFO] Hostname:", hostname)

        # Check for IP-based URLs
        try:
            ipaddress.ip_address(hostname)

            url_flags.append(
                f"URL uses an IP address instead of a domain: {url}"
            )

        except ValueError:
            pass

        # Check for URL username tricks
        if parsed.username is not None:
            url_flags.append(
                f"URL contains user information before the host: {url}"
            )

        # Check for punycode
        if any(label.startswith("xn--")
               for label in hostname.split(".")):

            url_flags.append(
                f"URL contains a punycode domain: {hostname}"
            )

        # Check for shortened URLs
        if hostname in shorteners:

            url_flags.append(
                f"URL uses a shortening service: {hostname}"
            )

        # Check for suspicious words in the hostname
        suspicious_words = [
            "login",
            "verify",
            "secure",
            "account",
            "update",
            "banking",
            "password"
        ]

        for word in suspicious_words:

            if word in hostname:

                url_flags.append(
                    f"Suspicious keyword '{word}' found "
                    f"in hostname: {hostname}"
                )

        # Check for brand names outside configured official domains
        for brand, official_domains in brand_domains.items():

            if brand in hostname:

                is_official = any(
                    hostname == domain
                    or hostname.endswith("." + domain)
                    for domain in official_domains
                )

                if not is_official:

                    url_flags.append(
                        f"Brand name '{brand}' appears in a "
                        f"non-configured domain: {hostname}"
                    )

        # Check for unencrypted HTTP
        if parsed.scheme.lower() == "http":

            url_flags.append(
                f"URL uses unencrypted HTTP: {url}"
            )

    print("\nURL analysis completed.")

    return url_flags


# -----------------------------------------------------
# MODULE 5: PHISHING KEYWORD ANALYSIS
# -----------------------------------------------------

def analyze_keywords(subject, body):

    keyword_flags = []

    text = (subject + " " + body).lower()

    keyword_categories = {

        "Urgency": [
            "urgent",
            "immediately",
            "hurry",
            "act now",
            "expires today",
            "limited time"
        ],

        "Threats": [
            "suspended",
            "blocked",
            "terminated",
            "account closed",
            "legal action"
        ],

        "Credential Theft": [
            "verify your account",
            "confirm your password",
            "login credentials",
            "reset your password",
            "bank details"
        ],

        "Financial Fraud": [
            "payment required",
            "refund pending",
            "wire transfer",
            "credit card details",
            "bank account"
        ],

        "Fake Rewards": [
            "you are a winner",
            "claim your prize",
            "free gift",
            "congratulations",
            "reward waiting"
        ],

        "Social Engineering": [
            "action required",
            "do not share",
            "confidential",
            "avoid account closure",
            "immediate action"
        ]
    }

    print("\n" + "=" * 55)
    print("          PHISHING KEYWORD ANALYSIS")
    print("=" * 55)

    for category, keywords in keyword_categories.items():

        detected = []

        for keyword in keywords:

            if keyword in text:
                detected.append(keyword)

        if detected:

            print(f"\n[WARNING] {category} indicators:")

            for keyword in detected:

                print(" -", keyword)

                keyword_flags.append(
                    f"{category} indicator detected: {keyword}"
                )

    if not keyword_flags:

        print("\n[INFO] No configured phishing keywords detected.")

    print("\nKeyword analysis completed.")

    return keyword_flags


# -----------------------------------------------------
# MODULE 6: EMAIL ATTACHMENT ANALYSIS
# -----------------------------------------------------

def analyze_attachments(attachments):

    attachment_flags = []

    dangerous_extensions = {
        ".exe": "Executable file",
        ".bat": "Batch script",
        ".cmd": "Command script",
        ".vbs": "Visual Basic script",
        ".js": "JavaScript file",
        ".ps1": "PowerShell script",
        ".scr": "Screen saver executable",
        ".com": "Executable file",
        ".hta": "HTML application",
        ".docm": "Macro-enabled Word document",
        ".xlsm": "Macro-enabled Excel document",
        ".iso": "Disk image",
        ".img": "Disk image",
        ".jar": "Java executable archive"
    }

    archive_extensions = {
        ".zip",
        ".rar",
        ".7z"
    }

    print("\n" + "=" * 55)
    print("              ATTACHMENT ANALYSIS")
    print("=" * 55)

    if not attachments:
        print("[INFO] No email attachments found.")
        return attachment_flags

    for filename in attachments:

        filename = filename.strip().lower()

        print("\n[INFO] Checking:", filename)

        extension = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""

        if extension in dangerous_extensions:

            description = dangerous_extensions[extension]

            flag = (
                f"Potentially risky attachment: "
                f"{filename} ({description})"
            )

            attachment_flags.append(flag)

            print("[WARNING]", flag)

        elif extension in archive_extensions:

            flag = (
                f"Archive attachment requires inspection: {filename}"
            )

            attachment_flags.append(flag)

            print("[WARNING]", flag)

        else:

            print("[INFO] No configured risky extension detected.")

    print("\nAttachment analysis completed.")

    return attachment_flags


# -----------------------------------------------------
# MODULE 7: PHISHING THREAT SCORING
# -----------------------------------------------------

def calculate_risk_score(
    header_flags,
    url_flags,
    keyword_flags,
    attachment_flags
):

    score = 0

    # Header mismatch
    for flag in header_flags:
        if "domain" in flag.lower():
            score += 20

    # URL indicators
    score += len(url_flags) * 15

    # Keyword indicators
    score += len(keyword_flags) * 5

    # Attachment indicators
    for flag in attachment_flags:

        if "archive" in flag.lower():
            score += 10

        else:
            score += 20

    # Limit score to 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH RISK"

    elif score >= 30:
        risk_level = "MEDIUM RISK"

    else:
        risk_level = "LOW RISK"

    return score, risk_level


# -----------------------------------------------------
# MODULE 8: JSON REPORT GENERATION
# -----------------------------------------------------

def generate_report(
    email_data,
    header_flags,
    url_flags,
    keyword_flags,
    attachment_flags,
    risk_score,
    risk_level
):

    report = {

        "report_generated": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "email_details": {
            "sender": email_data["sender"],
            "return_path": email_data["return_path"],
            "subject": email_data["subject"]
        },

        "analysis_results": {

            "header_warnings": header_flags,

            "url_warnings": url_flags,

            "keyword_warnings": keyword_flags,

            "attachment_warnings": attachment_flags
        },

        "threat_assessment": {
            "risk_score": risk_score,
            "risk_level": risk_level
        }
    }

    # Create Reports folder if it does not exist
    os.makedirs("Reports", exist_ok=True)

    # Save report
    report_path = os.path.join(
        "Reports",
        "phishing_report.json"
    )

    with open(report_path, "w", encoding="utf-8") as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print("\n[INFO] JSON report generated successfully.")
    print("[INFO] Report location:", report_path)


# -----------------------------------------------------
# MAIN PROGRAM
# -----------------------------------------------------


def main():

    # Get email information
    email_data = get_email_input()

    # Perform header analysis
    header_flags = analyze_headers(email_data)

    # Perform URL analysis
    url_flags = analyze_urls(email_data["body"])
    keyword_flags = analyze_keywords(
    email_data["subject"],
    email_data["body"]
)
    attachment_flags = analyze_attachments(
    email_data["attachments"]
)
    risk_score, risk_level = calculate_risk_score(
    header_flags,
    url_flags,
    keyword_flags,
    attachment_flags
)
    generate_report(
    email_data,
    header_flags,
    url_flags,
    keyword_flags,
    attachment_flags,
    risk_score,
    risk_level
)

    # Display analysis summary
    print("\n" + "=" * 55)
    print("                 ANALYSIS SUMMARY")
    print("=" * 55)

    print("\nSender:", email_data["sender"])
    print("Subject:", email_data["subject"])

    # Display header warnings
    print("\nHEADER RED FLAGS:")

    if header_flags:
        for flag in header_flags:
            print(" -", flag)
    else:
        print("No header-related warning signs detected.")

    # Display URL warnings
    print("\nURL RED FLAGS:")

    if url_flags:
        for flag in url_flags:
            print(" -", flag)
    else:
        print("No URL-related warning signs detected.")

   
     # Display phishing keyword warnings
    print("\nPHISHING KEYWORD RED FLAGS:")

    if keyword_flags:
        for flag in keyword_flags:
            print(" -", flag)
    else:
        print("No phishing keyword indicators detected.")

    # Display attachment warnings
    print("\nATTACHMENT RED FLAGS:")

    if attachment_flags:
        for flag in attachment_flags:
            print(" -", flag)
    else:
        print("No attachment-related warning signs detected.")

    print("\n" + "=" * 55)
    print("              FINAL THREAT ASSESSMENT")
    print("=" * 55)

    print("Phishing Risk Score :", risk_score, "/ 100")
    print("Threat Classification:", risk_level)

    print("=" * 55)

    # Final completion message
    print("\n" + "=" * 55)
    print("             ANALYSIS COMPLETED")
    print("=" * 55)

# Execute the main program
if __name__ == "__main__":
    main()

