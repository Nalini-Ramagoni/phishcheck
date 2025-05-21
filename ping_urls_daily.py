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
        return ext.suffix  # This is the real DNS-level TLD (e.g., co.uk, com)
    except:
        return 'Invalid'

# --- Configuration ---
bucket_name = "iosco-nalini"
s3_original_prefix = "original_csv/"
s3_output_prefix = "ping_results/"
output_filename = f"ping_results_{datetime.now().strftime('%Y-%m-%d')}.csv"
local_output_path = f"/tmp/{output_filename}"

# --- S3 Setup ---
s3 = boto3.client('s3')

# Step 1: Find latest CSV file in original_csv/
response = s3.list_objects_v2(Bucket=bucket_name, Prefix=s3_original_prefix)
csv_files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.csv')]

if not csv_files:
    raise Exception(" No CSV files found in original_csv/")

# Sort by date in filename (assuming format contains yyyy-mm-dd)
latest_file = sorted(csv_files, key=lambda x: x.split('_')[-1].replace('.csv', ''), reverse=True)[0]
print(f"⬇ Downloading latest file: {latest_file}")

# Step 2: Download contents of latest CSV into memory
csv_obj = s3.get_object(Bucket=bucket_name, Key=latest_file)
csv_data = csv_obj['Body'].read().decode('utf-8')
df = pd.read_csv(StringIO(csv_data))

# Step 3: Extract and clean URLs
url_rows = []
for _, row in df.iterrows():
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

# Step 4: Ping each site
results = []
nz_tz = pytz.timezone('Pacific/Auckland')

for row in url_rows:
    url = row['URL']
    try:
        response = requests.get(url, timeout=5)
        http_code = response.status_code
        status = "Alive" if http_code == 200 else f"Status {http_code}"
    except Exception as e:
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

# Step 5: Save result and upload
ping_df = pd.DataFrame(results)
ping_df.to_csv(local_output_path, index=False)

print(f"⬆ Uploading ping results to S3: {s3_output_prefix}{output_filename}")
s3.upload_file(local_output_path, bucket_name, f"{s3_output_prefix}{output_filename}")

# Cleanup
os.remove(local_output_path)
print(f" Done: ploaded to s3://{bucket_name}/{s3_output_prefix}{output_filename}")
