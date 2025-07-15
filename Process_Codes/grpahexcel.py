import pandas as pd
import glob
import os
import re

def find_status_column(cols):
    # Try to find the status column in any case, by substring
    for c in cols:
        if 'status' in c.lower():
            return c
        if 'liveness' in c.lower():
            return c
        if 'alive' in c.lower():
            return c
    # If not found, return None
    return None

def find_url_column(cols):
    # Try common url column names
    for c in cols:
        if c.lower() == "url":
            return c
    # Try fuzzy
    for c in cols:
        if 'url' in c.lower():
            return c
    return None

# Find all CSVs in current dir
csv_files = glob.glob("liveness_check/*.csv")

all_data = {}

for file in csv_files:
    # Try to extract the date from the filename
    # Accepts any 8+ digit or yyyy-mm-dd
    m = re.search(r'(\d{4}[-_]?\d{2}[-_]?\d{2}|\d{8})', file)
    date = m.group(1) if m else os.path.splitext(file)[0]
    df = pd.read_csv(file)
    url_col = find_url_column(df.columns)
    status_col = find_status_column(df.columns)
    if url_col is None or status_col is None:
        print(f"Skipping {file}: Could not detect URL/status columns.")
        continue

    for _, row in df.iterrows():
        url = str(row[url_col]).strip()
        status = str(row[status_col]).strip().capitalize()  # e.g., "Alive" or "Not alive"
        if url not in all_data:
            all_data[url] = {}
        all_data[url][date] = status

# Now build output DataFrame
all_urls = sorted(all_data.keys())
all_dates = sorted({d for dmap in all_data.values() for d in dmap.keys()})

out_rows = []
for url in all_urls:
    row = {'URL': url}
    for date in all_dates:
        row[date] = all_data[url].get(date, "")
    out_rows.append(row)

out_df = pd.DataFrame(out_rows)
out_df.to_csv("master-url-status.csv", index=False)
print("Done! Output saved as master-url-status.csv")
