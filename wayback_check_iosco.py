import boto3
import pandas as pd
import requests
from io import StringIO
from datetime import datetime
import os

# --- Configuration ---
bucket_name = "iosco-nalini"
iosco_prefix = "original_csv/"
wayback_prefix = "wayback/"
timestamp = datetime.now().strftime("%Y-%m-%d")
output_filename = f"wayback_results_{timestamp}.csv"
local_output_path = f"/tmp/{output_filename}"

# --- AWS S3 Setup ---
s3 = boto3.client("s3")

# --- Function to get the latest file in a prefix ---
def get_latest_csv(prefix):
    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    csv_files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.csv')]
    if not csv_files:
        return None
    latest_file = sorted(csv_files, key=lambda x: x.split('_')[-1].replace('.csv', ''), reverse=True)[0]
    return latest_file

# --- Load latest IOSCO file from S3 ---
iosco_file = get_latest_csv(iosco_prefix)
if not iosco_file:
    raise Exception("No IOSCO CSV files found.")

obj = s3.get_object(Bucket=bucket_name, Key=iosco_file)
df = pd.read_csv(StringIO(obj['Body'].read().decode('utf-8')))

# --- Extract and clean all URLs ---
url_set = set()
for _, row in df.iterrows():
    for col in ['url', 'other_urls']:
        raw = str(row[col]) if pd.notna(row[col]) else ''
        urls = [u.strip() for u in raw.split('|') if len(u.strip()) > 5]
        for u in urls:
            full_url = u if u.startswith('http') else f'https://{u}'
            url_set.add(full_url.lower())

# --- Query Wayback API for each URL ---
results = []

for url in sorted(url_set):
    try:
        api_url = f"https://archive.org/wayback/available?url={url}"
        r = requests.get(api_url, timeout=10)
        r.raise_for_status()
        data = r.json()

        snapshot = data.get("archived_snapshots", {}).get("closest", {})
        results.append({
            "URL": url,
            "Archived": snapshot.get("available", False),
            "Archive_URL": snapshot.get("url", ""),
            "Timestamp": snapshot.get("timestamp", ""),
            "HTTP_Status": snapshot.get("status", "")
        })

    except Exception as e:
        results.append({
            "URL": url,
            "Archived": False,
            "Archive_URL": "",
            "Timestamp": "",
            "HTTP_Status": f"ERROR: {str(e)}"
        })

# --- Save result locally and upload to S3 ---
result_df = pd.DataFrame(results)
result_df.to_csv(local_output_path, index=False)
s3.upload_file(local_output_path, bucket_name, f"{wayback_prefix}{output_filename}")
os.remove(local_output_path)

# --- Summary ---
print("✅ Wayback check complete")
print(f"🔍 Total URLs Checked: {len(url_set)}")
print(f"📦 Archived URLs: {result_df['Archived'].sum()}")
print(f"📁 S3 Output: s3://{bucket_name}/{wayback_prefix}{output_filename}")
