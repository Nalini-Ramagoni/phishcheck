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
output_file = f"/tmp/nz_urls_{today}.csv"

# Step 1: Download CSV with proper headers to avoid 403
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

response = requests.get(csv_url, headers=headers)
response.raise_for_status()

# Step 2: Read the CSV content into pandas
df = pd.read_csv(StringIO(response.text))

# Step 3: Extract and clean 'url' and 'other_urls'
columns_to_extract = [col for col in ['url', 'other_urls'] if col in df.columns]
if not columns_to_extract:
    raise Exception("❌ Columns 'url' or 'other_urls' not found in the CSV.")

# Combine values from both columns
raw_urls = pd.concat([df[col].dropna().astype(str).str.strip() for col in columns_to_extract])

# Split entries with "|" into separate URLs
split_urls = raw_urls.str.split('|').explode().str.strip()

# Filter out empty strings or short garbage
urls = split_urls[split_urls.str.len() > 5].drop_duplicates().reset_index(drop=True)

# Add https:// if missing
urls = urls.apply(lambda x: x if x.startswith('http') else f'https://{x}')


# Add https:// if missing
urls = urls.apply(lambda x: x if x.startswith('http') else f'https://{x}')

# Save to dataframe
url_df = pd.DataFrame(urls, columns=["URL"])
url_df.to_csv(output_file, index=False)


# Step 5: Upload to S3
s3 = boto3.client('s3')
s3.upload_file(output_file, bucket_name, f"urls/{os.path.basename(output_file)}")

# Step 6: Clean up local file
os.remove(output_file)

print(f" Success: {len(url_df)} URLs extracted and uploaded to S3.")
