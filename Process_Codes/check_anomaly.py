import pandas as pd

# Load data
df = pd.read_csv("master-url-status.csv")
urls = df.iloc[:, 0]
date_columns = df.columns[1:]

output_rows = []
for i, url in enumerate(urls):
    statuses = df.iloc[i, 1:].fillna("").astype(str).str.lower().tolist()
    unique = set([s for s in statuses if s not in ["", "nan"]])
    if len(unique) <= 1:
        continue  # All same, skip

    row = [url]
    last_status = statuses[0]
    for j in range(len(statuses)):
        if j == 0:
            row.append("")  # First date can't have a transition
            continue
        if statuses[j] and statuses[j] != last_status:
            row.append(f"{last_status} → {statuses[j]}")
            last_status = statuses[j]
        else:
            row.append("")
    output_rows.append(row)

# Column headers: URL + dates
columns = ['URL'] + list(date_columns)
final_df = pd.DataFrame(output_rows, columns=columns)
final_df.to_excel("url_status_anomalies_matrix.xlsx", index=False)

print(f"Saved matrix-format anomaly report to url_status_anomalies_matrix.xlsx with {len(final_df)} URLs.")
