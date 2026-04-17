"""Shared fixtures for SecureCommit tests."""

from __future__ import annotations

import textwrap

import pytest


# ---------------------------------------------------------------------------
# Sample code snippets containing secrets
# ---------------------------------------------------------------------------

@pytest.fixture
def aws_key_snippet() -> str:
    return 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'


@pytest.fixture
def aws_secret_snippet() -> str:
    return 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'


@pytest.fixture
def github_token_snippet() -> str:
    return 'GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"'


@pytest.fixture
def gitlab_token_snippet() -> str:
    return 'GITLAB_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"'


@pytest.fixture
def private_key_snippet() -> str:
    return "-----BEGIN RSA PRIVATE KEY-----"


@pytest.fixture
def db_connection_snippet() -> str:
    return 'DATABASE_URL = "postgres://admin:secret@db.example.com:5432/mydb"'


@pytest.fixture
def jwt_snippet() -> str:
    return 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"'


@pytest.fixture
def slack_webhook_snippet() -> str:
    return 'WEBHOOK = "https://hooks.example.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"'


@pytest.fixture
def stripe_key_snippet() -> str:
    return 'STRIPE_KEY = "sk_test_EXAMPLE00000000000000001234"'


@pytest.fixture
def sendgrid_key_snippet() -> str:
    return 'SG_KEY = "SG.xxxxxxxxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'


@pytest.fixture
def generic_api_key_snippet() -> str:
    return 'api_key = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"'


# ---------------------------------------------------------------------------
# Sample code with security anti-patterns
# ---------------------------------------------------------------------------

@pytest.fixture
def sql_injection_concat() -> str:
    return textwrap.dedent("""\
        def get_user(name):
            query = "SELECT * FROM users WHERE name = '" + name + "'"
            cursor.execute(query)
    """)


@pytest.fixture
def sql_injection_fstring() -> str:
    return textwrap.dedent("""\
        def get_user(user_id):
            cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    """)


@pytest.fixture
def xss_innerhtml() -> str:
    return 'document.getElementById("output").innerHTML = userInput;'


@pytest.fixture
def xss_dangerously() -> str:
    return '<div dangerouslySetInnerHTML={{__html: userContent}} />'


@pytest.fixture
def command_injection_os() -> str:
    return 'os.system("ls " + user_input)'


@pytest.fixture
def command_injection_subprocess() -> str:
    return 'subprocess.run(cmd, shell=True)'


@pytest.fixture
def pickle_loads_snippet() -> str:
    return 'data = pickle.loads(user_data)'


@pytest.fixture
def yaml_unsafe_snippet() -> str:
    return 'config = yaml.load(content)'


@pytest.fixture
def hardcoded_password_snippet() -> str:
    return 'password = "SuperS3cretP@ss!"'


@pytest.fixture
def md5_hash_snippet() -> str:
    return 'digest = hashlib.md5(data.encode()).hexdigest()'


@pytest.fixture
def eval_snippet() -> str:
    return 'result = eval(user_expression)'


# ---------------------------------------------------------------------------
# Safe code (should NOT trigger findings)
# ---------------------------------------------------------------------------

@pytest.fixture
def safe_sql_snippet() -> str:
    return textwrap.dedent("""\
        def get_user(user_id):
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    """)


@pytest.fixture
def safe_password_env() -> str:
    return 'password = os.environ.get("DB_PASSWORD")'


@pytest.fixture
def safe_yaml_snippet() -> str:
    return 'config = yaml.safe_load(content)'


# ---------------------------------------------------------------------------
# Full vulnerable file
# ---------------------------------------------------------------------------

@pytest.fixture
def vulnerable_file_content() -> str:
    return textwrap.dedent("""\
        import os
        import pickle
        AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
        password = "hunter2"
        os.system("echo " + user_input)
        data = pickle.loads(raw)
    """)
