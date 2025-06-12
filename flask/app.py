import re
import csv
from datetime import datetime, timedelta
from flask import Flask, render_template, request, url_for, redirect, send_file
import boto3
import hashlib
import plotly.graph_objs as go
import plotly.io as pio
import base64
from io import BytesIO, StringIO
import pandas as pd
import requests
import socket
from urllib.parse import urlparse
import io

app = Flask(__name__)

@app.template_filter('hash_md5')
def hash_md5_filter(s):
    return hashlib.md5(s.encode()).hexdigest()

AWS_REGION = 'us-east-2'
S3_BUCKET = 'iosco-nalini'
S3_PREFIX = 'ping_results/'
ABUSEIPDB_API_KEY = '6f9079b738a11ed6f771e8948ba3adecddcbbfb2b1f92ccd116e57fc248fdcf14d388296db1375c3'

def is_flagged_by_abuseipdb(url):
    try:
        domain = urlparse(url).netloc
        if ':' in domain:
            domain = domain.split(':')[0]
        ip = socket.gethostbyname(domain)
        endpoint = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        resp = requests.get(endpoint, headers=headers, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        score = result['data']['abuseConfidenceScore']
        return score >= 50  # Adjust threshold as needed
    except Exception as e:
        print(f"AbuseIPDB check error: {e}")
        return False

def extract_dates_from_s3():
    s3 = boto3.client('s3', region_name=AWS_REGION)
    paginator = s3.get_paginator('list_objects_v2')
    dates = set()
    pattern = re.compile(r'ping_results_(\d{4}-\d{2}-\d{2})\.csv')
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX):
        for obj in page.get('Contents', []):
            fname = obj['Key'].split('/')[-1]
            match = pattern.match(fname)
            if match:
                dates.add(datetime.strptime(match.group(1), "%Y-%m-%d").date())
    return dates

def get_months_available(dates):
    months = sorted({(d.year, d.month) for d in dates})
    return months

def get_month_dates(year, month, dates_set):
    from calendar import monthrange
    first_day = datetime(year, month, 1).date()
    last_day = datetime(year, month, monthrange(year, month)[1]).date()
    days = [first_day + timedelta(days=i) for i in range((last_day - first_day).days + 1)]
    valid_days = [d for d in days if d in dates_set]
    return days, set(valid_days)

def is_flagged_by_fca_uk(url):
    domain = urlparse(url).netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    api_url = f"https://register.fca.org.uk/secure/api/warningList?search={domain}"
    try:
        resp = requests.get(api_url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return data['length'] > 0
    except Exception as e:
        print(f"FCA UK check error: {e}")
        return False

@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow}

@app.route('/')
def index():
    dates_set = extract_dates_from_s3()
    if not dates_set:
        return render_template("calendar.html", calendar=[], week_days=[],
                               month_label='', left_enabled=False, right_enabled=False, current_month='', valid_days=set())

    months_available = get_months_available(dates_set)
    month_str = request.args.get('month')
    if month_str:
        current_year, current_month = map(int, month_str.split('-'))
    else:
        current_year, current_month = months_available[-1]

    days, valid_days = get_month_dates(current_year, current_month, dates_set)

    week_days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    calendar = []
    week = []
    first_weekday = days[0].weekday()
    if first_weekday != 0:
        week = [None] * first_weekday
    for day in days:
        week.append(day)
        if len(week) == 7:
            calendar.append(week)
            week = []
    if week:
        while len(week) < 7:
            week.append(None)
        calendar.append(week)

    months_index = months_available.index((current_year, current_month))
    left_enabled = months_index > 0
    right_enabled = months_index < len(months_available) - 1
    left_month = months_available[months_index - 1] if left_enabled else None
    right_month = months_available[months_index + 1] if right_enabled else None
    month_label = datetime(current_year, current_month, 1).strftime('%B %Y')
    return render_template(
        "calendar.html",
        calendar=calendar,
        week_days=week_days,
        month_label=month_label,
        left_enabled=left_enabled,
        right_enabled=right_enabled,
        left_month=left_month,
        right_month=right_month,
        current_month=f"{current_year:04d}-{current_month:02d}",
        valid_days=valid_days
    )

@app.route('/day/<date_str>')
def day_view(date_str):
    s3 = boto3.client('s3', region_name=AWS_REGION)
    fname = f"{S3_PREFIX}ping_results_{date_str}.csv"
    try:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=fname)
        csv_content = obj['Body'].read().decode('utf-8')
        f = StringIO(csv_content)
        reader = csv.DictReader(f)
        urls = []
        for row in reader:
            url = row.get("url") or row.get("URL") or row.get("Url")
            if url:
                urls.append(url)
    except Exception as e:
        print(f"Error loading file {fname}: {e}")
        urls = []
    return render_template("urls_for_day.html", date=date_str, urls=urls)

@app.route('/urlstats/<url_hash>')
def url_stats(url_hash):
    url = request.args.get('url')
    if not url:
        return "No URL specified.", 400

    s3 = boto3.client('s3', region_name=AWS_REGION)
    paginator = s3.get_paginator('list_objects_v2')
    pattern = re.compile(r'ping_results_(\d{4}-\d{2}-\d{2})\.csv')
    status_by_date = []
    for page in paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX):
        for obj in page.get('Contents', []):
            fname = obj['Key'].split('/')[-1]
            match = pattern.match(fname)
            if not match:
                continue
            date_str = match.group(1)
            obj_s3 = s3.get_object(Bucket=S3_BUCKET, Key=obj['Key'])
            csv_content = obj_s3['Body'].read().decode('utf-8')
            f = StringIO(csv_content)
            reader = csv.DictReader(f)
            found = False
            for row in reader:
                row_url = row.get("url") or row.get("URL") or row.get("Url")
                if row_url and hashlib.md5(row_url.encode()).hexdigest() == url_hash:
                    status = row.get('Status', 'Up')
                    up_values = ['up', 'alive', 'online', '200']
                    status_clean = str(status).strip().lower()
                    status_val = 1 if status_clean in up_values else 0
                    status_by_date.append((date_str, status_val))
                    found = True
                    break
            if not found:
                status_by_date.append((date_str, None))

    status_by_date.sort()
    dates = [d for d, v in status_by_date]
    values = [v if v is not None else None for d, v in status_by_date]

    # Find the latest non-None status (most recent day with data)
    current_status = None
    for v in reversed(values):
        if v is not None:
            current_status = 'UP' if v == 1 else 'DOWN'
            break

    # Scam flag checks
    fca_flag = "YES" if is_flagged_by_fca_uk(url) else "NO"
    abuseipdb_flag = "YES" if is_flagged_by_abuseipdb(url) else "NO"

    # Download mirror button check
    domain = urlparse(url).netloc
    if ':' in domain:
        domain = domain.split(':')[0]
    s3_key = f"mirrors/{domain}.zip"
    mirror_exists = False
    try:
        s3.head_object(Bucket=S3_BUCKET, Key=s3_key)
        mirror_exists = True
    except Exception:
        mirror_exists = False

    # Plotly 2D line chart
    df = pd.DataFrame({'date': pd.to_datetime(dates), 'status': values})

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df['date'],
        y=df['status'],
        mode='lines+markers',
        line=dict(color='lightblue', width=4),
        marker=dict(size=10, color='royalblue'),
        name='Status'
    ))
    fig.update_layout(
        title=f"Uptime/Downtime for {url}",
        xaxis_title="Date",
        yaxis=dict(
            title="Status (Up=1, Down=0)",
            tickvals=[0, 1],
            ticktext=['Down', 'Up'],
            range=[-0.2, 1.2],
            dtick=1
        ),
        height=450,
        width=950,
        plot_bgcolor='white',
        showlegend=False
    )

    img_bytes = pio.to_image(fig, format='png')
    img_b64 = base64.b64encode(img_bytes).decode('utf-8')

    return render_template(
        "url_stats.html",
        url=url,
        img_b64=img_b64,
        current_status=current_status,
        fca_flag=fca_flag,
        abuseipdb_flag=abuseipdb_flag,
        mirror_exists=mirror_exists
    )

@app.route('/download_mirror/<url_hash>')
def download_mirror(url_hash):
    url = request.args.get('url')
    if not url:
        return "No URL specified.", 400
    domain = urlparse(url).netloc
    if ':' in domain:
        domain = domain.split(':')[0]
    s3_key = f"mirrors/{domain}.zip"
    s3 = boto3.client('s3', region_name=AWS_REGION)
    try:
        s3_obj = s3.get_object(Bucket=S3_BUCKET, Key=s3_key)
        file_bytes = s3_obj['Body'].read()
        return send_file(
            io.BytesIO(file_bytes),
            mimetype='application/zip',
            as_attachment=True,
            download_name=f"{domain}.zip"
        )
    except Exception as e:
        print(f"Download mirror error: {e}")
        return "Mirror not found for this site.", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)
