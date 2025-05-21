import boto3
import pandas as pd
import requests
import os
from datetime import datetime

bucket_name = "iosco-nalini"
s3 = boto3.client('s3')
today = datetime.now().strftime("%Y-%m-%d")
ping_file = f"/tmp/ping_results_{today}.csv"

# Download most recent URL file from S3
objects = s3.list_objects_v2(Bucket=bucket_name, Prefix="urls/")
latest = sorted(objects['Contents'], key=lambda x: x['LastModified'], reverse=True)[0]['Key']
local_file = f"/tmp/{os.path.basename(latest)}"
s3.download_file(bucket_name, latest, local_file)

# Load URLs
df = pd.read_csv(local_file)
results = []

for url in df['URL'].dropna():
    try:
        r = requests.get(url.strip(), timeout=5)
        status = 'Alive' if r.status_code < 400 else 'Not Alive'
    except:
        status = 'Not Alive'
    results.append({
        'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'URL': url,
        'Status': status
    })

# Save results
results_df = pd.DataFrame(results)
results_df.to_csv(ping_file, index=False)
s3.upload_file(ping_file, bucket_name, f"pings/{os.path.basename(ping_file)}")
os.remove(local_file)
os.remove(ping_file)

print(" Daily ping check complete and uploaded to S3.")
