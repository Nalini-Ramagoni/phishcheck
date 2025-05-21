import boto3
import pandas as pd
import requests
import os
from io import StringIO
from datetime import datetime

# Configuration
bucket_name = "iosco-nalini"
csv_url = "https://www.iosco.org/i-scan/?export-to-csv&SUBSECTION=main&NCA_ID=64"
today = datetime.now().strftime("%Y-%m-%d")
clean_file = f"/tmp/nz_urls_{today}.csv"
original_file = f"/tmp/original_iosco_{today}.csv"

# Step 1: Download CSV with proper headers
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
response = requests.get(csv_url, headers=headers)
response.raise_for_status()

# Save original CSV content
with open(original_file, "w", encoding="utf-8") as f:
    f.write(response.text)

# Step 2: Read the CSV content into pandas
df = pd.read_csv(StringIO(response.text))

# Step 3: Extract and clean 'url' and 'other_urls'
columns_to_extract = [col for col in ['url', 'other_urls'] if col in df.columns]
if not columns_to_extract:
    raise Exception(" Columns 'url' or 'other_urls' not found in the CSV.")

raw_urls = pd.concat([df[col].dropna().astype(str).str.strip() for col in columns_to_extract])
split_urls = raw_urls.str.split('|').explode().str.strip()
urls = split_urls[split_urls.str.len() > 5].drop_duplicates().reset_index(drop=True)
urls = urls.apply(lambda x: x if x.startswith('http') else f'https://{x}')

# Save cleaned data
url_df = pd.DataFrame(urls, columns=["URL"])
url_df.to_csv(clean_file, index=False)

# Step 4: Upload to S3
s3 = boto3.client('s3')

# Upload original CSV
s3.upload_file(original_file, bucket_name, f"original_csv/{os.path.basename(original_file)}")

# Upload cleaned URLs
s3.upload_file(clean_file, bucket_name, f"urls/{os.path.basename(clean_file)}")

# Step 5: Clean up local temp files
os.remove(original_file)
os.remove(clean_file)

print(f"Success: {len(url_df)} cleaned URLs uploaded to 'urls/', original CSV uploaded to 'original_csv/' in bucket '{bucket_name}'.")
