import pandas as pd
import numpy as np

# Updated mapping for all known statuses
status_map = {
    'alive': 1,
    'not alive': 0,
    'status 403': 2,
    'status 404': 3,
    'status 410': 4,
    'status 436': 5,
    'status 500': 6,
    'status 521': 7,
    'removed': -1,
    '': np.nan,
    'nan': np.nan
}

def get_new_status(transition, prev_state):
    # Handles 'alive→not alive', 'not alive→alive', etc.
    if '→' in transition:
        new_status = transition.split('→')[-1].strip().lower()
        return status_map.get(new_status, np.nan)
    elif transition.strip().lower() in status_map:
        return status_map.get(transition.strip().lower(), np.nan)
    else:
        return prev_state

df = pd.read_excel('url_status_anomalies_matrix.xlsx')
urls = df.iloc[:, 0]
date_columns = df.columns[1:]

hot_encoded_rows = []
for i, url in enumerate(urls):
    timeline = df.iloc[i, 1:].fillna("").astype(str).tolist()
    # Guess initial state from first transition
    prev_state = None
    for val in timeline:
        if '→' in val:
            prev = val.split('→')[0].strip().lower()
            prev_state = status_map.get(prev, np.nan)
            break
        elif val.strip().lower() in status_map:
            prev_state = status_map.get(val.strip().lower(), np.nan)
            break
    if prev_state is None:
        prev_state = np.nan

    encoded_row = [url]
    for val in timeline:
        if val.strip() == '':
            encoded_row.append(prev_state)
        else:
            curr_state = get_new_status(val, prev_state)
            encoded_row.append(curr_state)
            prev_state = curr_state
    hot_encoded_rows.append(encoded_row)

hot_df = pd.DataFrame(hot_encoded_rows, columns=['URL'] + list(date_columns))
hot_df.to_excel("url_status_hot_encoded_from_anomaly_matrix.xlsx", index=False)
print("Saved hot-encoded matrix to url_status_hot_encoded_from_anomaly_matrix.xlsx")
