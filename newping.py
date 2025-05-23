import boto3
import pandas as pd
import requests
from datetime import datetime
import pytz
import time
import os
import tldextract
from io import StringIO

def get_dns_tld(url):
    try:
        ext = tldextract.extract(url)
        return ext.suffix
    except:
        return 'Invalid'

# --- Configuration ---
bucket_name = "iosco-nalini"
iosco_prefix = "original_csv/"
crtsh_prefix = "crtsh_nz_data/"
s3_output_prefix = "ping_results/"
timestamp = datetime.now().strftime('%Y-%m-%d')
output_filename = f"ping_results_{timestamp}.csv"
local_output_path = f"/tmp/{output_filename}"

# --- S3 Setup ---
s3 = boto3.client('s3')

# --- Function to get latest CSV file from a prefix ---
def get_latest_csv(prefix):
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    csv_files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.csv')]
    if not csv_files:
        return None
    latest_file = sorted(csv_files, key=lambda x: x.split('_')[-1].replace('.csv', ''), reverse=True)[0]
    return latest_file

# --- Step 1: Load both IOSCO and CRTSH files ---
iosco_file = get_latest_csv(iosco_prefix)
crtsh_file = get_latest_csv(crtsh_prefix)

if not iosco_file or not crtsh_file:
    raise Exception("Missing one or both source CSV files.")

print(f"⬇ Downloading IOSCO file: {iosco_file}")
iosco_obj = s3.get_object(Bucket=bucket_name, Key=iosco_file)
iosco_data = iosco_obj['Body'].read().decode('utf-8')
iosco_df = pd.read_csv(StringIO(iosco_data))

print(f"⬇ Downloading CRTSH file: {crtsh_file}")
crtsh_obj = s3.get_object(Bucket=bucket_name, Key=crtsh_file)
crtsh_data = crtsh_obj['Body'].read().decode('utf-8')
crtsh_df = pd.read_csv(StringIO(crtsh_data))

# --- Step 2: Extract URLs from both datasets ---
url_rows = []

# From IOSCO
for _, row in iosco_df.iterrows():
    for col in ['url', 'other_urls']:
        raw = str(row[col]) if pd.notna(row[col]) else ''
        urls = [u.strip() for u in raw.split('|') if len(u.strip()) > 5]
        for u in urls:
            full_url = u if u.startswith('http') else f'https://{u}'
            url_rows.append({
                'URL': full_url.lower(),
                'nca_registration_date': row.get('nca_registration_date', ''),
                'modification_date': row.get('modification_date', '')
            })

# From CRTSH
for _, row in crtsh_df.iterrows():
    url = str(row.get("Formatted URL", "")).strip()
    if url.startswith("http"):
        url_rows.append({
            "URL": url.lower(),
            "nca_registration_date": "",
            "modification_date": ""
        })

# --- Step 3: Ping all URLs ---
results = []
nz_tz = pytz.timezone('Pacific/Auckland')

for row in url_rows:
    url = row['URL']
    try:
        response = requests.get(url, timeout=5)
        http_code = response.status_code
        status = "Alive" if http_code == 200 else f"Status {http_code}"
    except Exception:
        http_code = "Error"
        status = "Not Alive"

    ping_time_nz = datetime.now(nz_tz).strftime('%Y-%m-%d %H:%M:%S %Z')

    results.append({
        "Ping_Timestamp_NZ": ping_time_nz,
        "URL": url,
        "Status": status,
        "HTTP_Code": http_code,
        "DNS_TLD": get_dns_tld(url),
        "nca_registration_date": row['nca_registration_date'],
        "modification_date": row['modification_date']
    })

    time.sleep(0.5)

# --- Step 4: Save and Upload ---
ping_df = pd.DataFrame(results)
ping_df.to_csv(local_output_path, index=False)

print(f"⬆ Uploading ping results to S3: {s3_output_prefix}{output_filename}")
s3.upload_file(local_output_path, bucket_name, f"{s3_output_prefix}{output_filename}")
os.remove(local_output_path)

print(f"✅ Done: Uploaded to s3://{bucket_name}/{s3_output_prefix}{output_filename}")
