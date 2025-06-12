import re
import csv
from datetime import datetime, timedelta
from flask import Flask, render_template, request, url_for, redirect
import boto3
from io import StringIO

app = Flask(__name__)

AWS_REGION = 'us-east-2'         # Update to your region
S3_BUCKET = 'iosco-nalini'
S3_PREFIX = 'ping_results/'

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
        current_year, current_month = months_available[-1]  # latest

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
    # date_str is YYYY-MM-DD
    # Fetch CSV from S3
    s3 = boto3.client('s3', region_name=AWS_REGION)
    fname = f"{S3_PREFIX}ping_results_{date_str}.csv"
    try:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=fname)
        csv_content = obj['Body'].read().decode('utf-8')
        f = StringIO(csv_content)
        reader = csv.DictReader(f)
        # Try to get columns called "url" or similar (adjust if needed)
        urls = []
        for row in reader:
            url = row.get("url") or row.get("URL") or row.get("Url")
            if url:
                urls.append(url)
    except Exception as e:
        print(f"Error loading file {fname}: {e}")
        urls = []
    return render_template("urls_for_day.html", date=date_str, urls=urls)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)