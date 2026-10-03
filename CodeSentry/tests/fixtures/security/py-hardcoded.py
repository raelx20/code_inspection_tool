import os

# Hardcoded secrets - should be detected
API_KEY = "YOUR_API_KEY_HERE"
DB_PASSWORD = "YOUR_DB_PASSWORD_HERE"
AWS_SECRET_KEY = "YOUR_AWS_SECRET_HERE"
STRIPE_SECRET = "REPLACE_WITH_YOUR_STRIPE_KEY"

def get_config():
    return {
        "api_key": API_KEY,
        "db_password": DB_PASSWORD,
        "aws_secret": AWS_SECRET_KEY,
    }
