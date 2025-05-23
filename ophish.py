import boto3
import pandas as pd
import requests
from io import StringIO
from datetime import datetime

# --- Config ---
s3_bucket = "iosco-nalini"
input_key = "crtsh_nz_data/crtsh_common_name_2025-05-22.csv"
timestamp = datetime.now().strftime("%Y-%m-%d")
output_key = f"crtsh_nz_data/crtsh_nz_flagged_{timestamp}.csv"

# --- Step 1: Load crtsh CSV from S3 ---
s3 = boto3.client("s3")
obj = s3.get_object(Bucket=s3_bucket, Key=input_key)
df = pd.read_csv(obj['Body'])

# --- Step 2: Fetch OpenPhish Feed ---
print("🔄 Fetching OpenPhish live feed...")
response = requests.get("https://openphish.com/feed.txt", timeout=10)
response.raise_for_status()
phish_urls = set(line.strip().lower() for line in response.text.splitlines() if line.strip())

# --- Step 3: Match with crtsh Formatted URLs ---
def is_phishing(url):
    return any(url.lower() in phish_url for phish_url in phish_urls)

df["Is_Phishing"] = df["Formatted URL"].apply(is_phishing)

# --- Step 4: Save new CSV and upload ---
csv_buffer = StringIO()
df.to_csv(csv_buffer, index=False)
s3.put_object(Bucket=s3_bucket, Key=output_key, Body=csv_buffer.getvalue())

print(f"✅ Uploaded flagged results to s3://{s3_bucket}/{output_key}")
print(f"📊 {df['Is_Phishing'].sum()} domains flagged as phishing out of {len(df)} total.")
