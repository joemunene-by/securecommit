"""Sample file with intentional vulnerabilities for SecureCommit demo.

Run: securecommit scan examples/vulnerable_code.py
Expected: Multiple findings across all severity levels.
"""

import hashlib
import os
import pickle
import subprocess

import requests
import yaml

# ============================================================
# SECRET DETECTION EXAMPLES
# ============================================================

# AWS Access Key (CRITICAL)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub token (CRITICAL)
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"

# GitLab token (CRITICAL)
GITLAB_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"

# Private key (CRITICAL)
PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA04up8hoqzS1+APIB6RNXhEDMkMq8gHDPFB3JqOc/example
-----END RSA PRIVATE KEY-----
"""

# Database connection string (HIGH)
DATABASE_URL = "postgres://admin:supersecret@db.example.com:5432/production"

# Slack webhook (HIGH)
SLACK_WEBHOOK = "https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Stripe key (CRITICAL)
STRIPE_SECRET = "sk_test_EXAMPLE00000000000000001234"

# SendGrid key (HIGH)
SENDGRID_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

# Generic API key (HIGH)
api_key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

# JWT token (MEDIUM)
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


# ============================================================
# SECURITY ANTI-PATTERN EXAMPLES
# ============================================================

# SQL Injection (HIGH)
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return query


# Command Injection via os.system (CRITICAL)
def run_command(user_input):
    os.system("echo " + user_input)


# Command Injection via subprocess shell=True (HIGH)
def run_shell(cmd):
    subprocess.run(cmd, shell=True)


# Insecure deserialization — pickle (CRITICAL)
def load_data(data):
    return pickle.loads(data)


# Insecure YAML loading (HIGH)
def parse_yaml(content):
    return yaml.load(content)


# XSS via innerHTML (HIGH) — JavaScript-style but detectable in .py
js_snippet = 'document.getElementById("output").innerHTML = userInput;'

# Hardcoded password (HIGH)
password = "SuperS3cretP@ssw0rd!"
secret_key = "my-secret-key-do-not-share"

# Insecure hash — MD5 (MEDIUM)
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


# eval with user input (HIGH)
def calculate(expression):
    return eval(expression)


# Disabled TLS verification (MEDIUM)
def fetch_data(url):
    return requests.get(url, verify=False)
