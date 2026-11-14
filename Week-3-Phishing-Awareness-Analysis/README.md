# Week 3 – Phishing Awareness Analysis 🔐

## Project Overview

Phishing Awareness Analysis is a Python-based cybersecurity project designed to identify potential phishing emails by examining different email characteristics and detecting suspicious indicators.

The program analyzes email headers, URLs, phishing-related keywords, and attachments to calculate a phishing risk score.

## Features

- **Email Header Analysis:** Detects mismatches between sender address and Return-Path.
- **URL Analysis:** Identifies suspicious URLs and misleading brand names in domains.
- **Keyword Detection:** Detects urgency, threats, credential theft, and social engineering indicators.
- **Attachment Analysis:** Identifies potentially risky file extensions and archives.
- **Risk Assessment:** Calculates a phishing risk score out of 100.
- **Threat Classification:** Classifies emails as Low Risk, Medium Risk, or High Risk.
- **JSON Reporting:** Automatically generates a structured JSON analysis report.

## Technologies Used

- Python 3
- Regular Expressions
- JSON
- Email Security Concepts

## Project Structure

```text
Week-3-Phishing-Awareness-Analysis/
│
├── Reports/
│   └── phishing_report.json
│
├── Samples/
│
├── .gitignore
├── phishing_analyzer.py
└── README.md
```

## Installation and Execution

1. Clone or download the repository.
2. Open the project folder in VS Code.
3. Create and activate a virtual environment.
4. Run the following command:

```bash
python phishing_analyzer.py
```

## Sample Results

The project was tested using both suspicious and legitimate synthetic email examples.

| Test | Risk Score | Classification |
|---|---:|---|
| Suspicious email | 100/100 | HIGH RISK |
| Legitimate test email | 0/100 | LOW RISK |

## Output

The program generates a JSON report automatically:

`Reports/phishing_report.json`

The report contains email details, detected warnings, analysis results, and the final threat assessment.

## Disclaimer

This project is developed for educational purposes as part of a cybersecurity internship. Its rule-based analysis provides warning indicators and should not be treated as a guarantee that an email is safe or malicious.

## Author

Mohammed Anas

Cybersecurity Internship – Week 3