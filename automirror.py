import pandas as pd
import requests
from datetime import datetime
import time
import tldextract
import os
import subprocess
from io import StringIO
import openpyxl
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter
from pathlib import Path
from collections import Counter
import sys
import shutil

#Ignore Httrack files and folders during analysis

IGNORE_FOLDERS = {"hts-cache", "Analysis"}
IGNORE_EXTS = {
    "whtt", "delayed", "delay", "delaye", "dela", "del", "lst", "tmp"
}

def should_ignore_folder(path):
    parts = Path(path).parts
    return any(f in parts for f in IGNORE_FOLDERS)

def should_ignore_file(filename):
    ext = Path(filename).suffix.lower().lstrip('.')
    return ext in IGNORE_EXTS

#Suspicious temrs

suspicious_terms = [
    "login", "admin", "backup", "password", "private", "secret", "confidential",
    "config", "db", "database", "test", "old", "hidden", "user", "account",
    "auth", "restricted", "archive", "key", "token",
    "phone", "email", "contact", "whatsapp", "facebook", "linkedin", "@gmail.com", "@yahoo.com", "gmail",
    "+1", "+44", "+91", "telegram", "discord", "skype", "twitter.com", "t.me/", "instagram",
    "wallet address", "metamask", "usdt", "keylogger", "token grabber", "exe", "malware", "stealer",
    "ransomware", "shell", "backdoor", "payload", "exploit", "beef", "hook", "c2", "dll", "kernel",
    "daemon", "ip", "mac", "command and control", "dropper", "autoexec", "autorun", "shellcode",
    "system()", "exec(", "cmd", "cmd.exe", "powershell", "registry key", "validate", "credentials",
    "username", "password", "redirect", "2FA bypass", "session token", "auth token", "otp",
    "admin panel", "admin.php", "cpanel", "dashboard", "ftp", "webmail", "live support", "eval(",
    "fetch(", "xhr.open(", "window.location", "innerHTML", "onload", "cloudflare", "ngrok", "firebaseio",
    "herokuapp", "freehosting", "namecheap", "freenom", "godaddy", "hostinger", "wordpress.com",
    "blogspot.com", "base64_decode", "atob(", "btoa(", "unescape(", "obfuscate", "pack", "encrypt",
    "xor", "charCodeAt", "admin login", "panel access", "manage users", "credentials.txt", "logs",
    "session.log", "access.log", "transactions", "money", "bank transfer", "ifsc", "iban",
    "routing number", "swift code", "gateway", "broker ID", "account", "deposit address",
    "wallet recovery", "mnemonic phrase", "private key", "seed phrase", "api_key", "client_id",
    "secret_key", "token=", "api.secret", "jwt", "access_token", "env", ".env", "db_password",
    "db_user", "db_host", "config.php", "wp-config.php", ".env.production", ".env.local", "ftp_password",
    "smtp_password", "email_password", "smtp", "mailgun", "sendgrid", "smtp server", "webhook",
    "webhook.site", "endpoint", "callback", "callback_url", "payment processor", "payu", "stripe",
    "razorpay", "paypal", "skrill", "perfectmoney", "payeer", "payoneer", "btc", "eth", "xrp",
    "ltc", "usdc", "usdt", "erc20", "trc20", "bep20", "withdrawal fee", "deposit fee", "fake reviews",
    "testimonials", "as seen on", "aml", "fma warning", "iosco alert", "asx warning", "fca warning",
    "sec alert", "asic warning", "baFin warning", "amf warning", "ico", "whitelist", "kyc document",
    "passport", "national id", "proof of address", "proof of funds", "bank statement", "fraudulent",
    "fraud warning", "unlicensed", "unregulated", "scam alert", "cease and desist", "legal notice",
    "arbitration", "class action", "chargeback", "dispute", "complaint", "victim", "victim support",
    "dev@", "admin@", "webmaster@", "info@", "support@", "hostmaster@", "abuse@", "sales@", "noreply@",
    "no-reply@", "team@", "protonmail", "tutanota", "outlook", "viber", "wechat", "signal", "line.me",
    "snapchat", "kik", "email: ", "phone: ", "contact:", "telegram:", "discord:", "twitter:", "github",
    "bitbucket", "gitlab", "whois", "founder", "ceo", "developer", "engineer", "project lead",
    "contact us", "staff", "support team", "company registration", "incorporation", "business number",
    "abn", "vat", "gst", "country of incorporation", "uk companies house", "finra", "sec.gov",
    "open corporates", "company address", "office address", "address:", "eval(", "crypto-miner",
    "cryptojacker", "web skimmer", "magecart", "formgrabber", "keystroke", "window.open(",
    "document.cookie", "fetch(", "axios.post(", "axios.get(", "jquery.post(", "jquery.get(",
    "new XMLHttpRequest", "navigator.sendBeacon", "postMessage(", "open in new tab", "base64,",
    "xor_encrypt", "hex_encode", "percent_encode", "shell_exec(", "phpinfo(", "include(", "require(",
    "passthru(", "popen(", "proc_open(", "curl_exec(", "fsock", "password", "username", "login",
    "user:", "pass:", "cred=", "user_id", "login_id", "passwd", "pwd", "auth", "token", "session_id",
    "session_token", "bearer", "private_key", "public_key", "secret", "key=", "api_key", "api_secret",
    "ssh", "ssh-rsa", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN CERTIFICATE-----",
    "ssn", "dob", "date of birth", "credit card", "ccv", "cvv", "expiry", "pan", "cardholder",
    "billing address", "sort code", "routing number", "iban", "bic", "swift"
]

#Functions for analysis

def ensure_analysis_folder(base_folder):
    analysis_dir = Path(base_folder) / "Analysis"
    analysis_dir.mkdir(exist_ok=True)
    return analysis_dir

def update_file_type_stats(root_folder, analysis_dir):
    ext_counter = Counter()
    size_by_ext = Counter()
    for dirpath, dirnames, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            ext = Path(f).suffix.lower()
            ext_key = ext.lstrip('.').lower() if ext else 'no ext'
            full_path = os.path.join(dirpath, f)
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            ext_counter[ext_key.upper()] += 1
            size_by_ext[ext_key.upper()] += size
    today = datetime.now().strftime("%Y-%m-%d")
    types_sorted = sorted(ext_counter.keys())
    df_new = pd.DataFrame({
        "File Type": types_sorted,
        f"{today} (Count)": [ext_counter[t] for t in types_sorted],
        f"{today} (Size MB)": [f"{size_by_ext[t]/1024/1024:.2f}" for t in types_sorted]
    })
    outpath = analysis_dir / "file_type_stats.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        df_all = pd.merge(df_old, df_new, on="File Type", how="outer").sort_values("File Type").reset_index(drop=True)
        df_all.fillna("", inplace=True)
    else:
        df_all = df_new
    df_all.to_csv(outpath, index=False)
    print(f"File type stats updated: {outpath}")

def update_top10_largest_files(root_folder, analysis_dir):
    files_info = []
    for dirpath, _, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, root_folder)
            ext = Path(f).suffix.lower().lstrip('.').upper() if Path(f).suffix else 'NO EXT'
            try:
                size = os.path.getsize(full_path)
            except OSError:
                size = 0
            files_info.append({
                "File Name": f,
                "Relative Path": rel_path,
                "File Type": ext,
                "Size (MB)": size / 1024 / 1024
            })
    files_info = sorted(files_info, key=lambda x: x["Size (MB)"], reverse=True)[:10]
    today = datetime.now().strftime("%Y-%m-%d")
    df_new = pd.DataFrame(files_info)
    df_new.rename(columns={"Size (MB)": f"{today} Size (MB)"}, inplace=True)
    outpath = analysis_dir / "top10_largest_files.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        merge_cols = ["File Name", "Relative Path", "File Type"]
        df_all = pd.merge(df_old, df_new, on=merge_cols, how="outer")
        df_all = df_all.sort_values(by=merge_cols).reset_index(drop=True)
        df_all.fillna("", inplace=True)
    else:
        df_all = df_new
    df_all.to_csv(outpath, index=False)
    print(f"Top 10 largest files updated: {outpath}")

def update_suspicious_files_folders(root_folder, analysis_dir):
    matches = {term: [] for term in suspicious_terms}
    for dirpath, dirnames, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for d in dirnames:
            for term in suspicious_terms:
                if term.lower() in d.lower():
                    matches[term].append(os.path.relpath(os.path.join(dirpath, d), root_folder))
        for f in filenames:
            if should_ignore_file(f):
                continue
            for term in suspicious_terms:
                if term.lower() in f.lower():
                    matches[term].append(os.path.relpath(os.path.join(dirpath, f), root_folder))
    today = datetime.now().strftime("%Y-%m-%d")
    rows = []
    for term in sorted(suspicious_terms):
        paths = matches[term]
        rows.append({
            "Suspicious Term": term,
            f"{today} (Hits)": len(paths),
            f"{today} (Paths)": "; ".join(paths) if paths else ""
        })
    df_new = pd.DataFrame(rows)
    outpath = analysis_dir / "suspicious_files.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        df_all = pd.merge(df_old, df_new, on="Suspicious Term", how="outer").sort_values("Suspicious Term").reset_index(drop=True)
        df_all.fillna("", inplace=True)
    else:
        df_all = df_new
    df_all.to_csv(outpath, index=False)
    print(f"Suspicious files/folders updated: {outpath}")
    save_detailed_suspicious_paths(matches, analysis_dir, today)

def save_detailed_suspicious_paths(matches, analysis_dir, today):
    records = []
    for term, paths in matches.items():
        for path in paths:
            records.append({
                "Suspicious Term": term,
                "Date": today,
                "File Path": path
            })
    df = pd.DataFrame(records)
    outpath = analysis_dir / "suspicious_paths.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates()
    df.to_csv(outpath, index=False)
    print(f"Detailed suspicious paths saved: {outpath}")

def keyword_content_scan(root_folder, analysis_dir, suspicious_terms):
    records = []
    today = datetime.now().strftime("%Y-%m-%d")
    for dirpath, _, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, root_folder)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                    content = file.read().lower()
                    for term in suspicious_terms:
                        if term.lower() in content:
                            records.append({
                                "Suspicious Term": term,
                                "Date": today,
                                "File Path": rel_path
                            })
            except Exception:
                continue
    df = pd.DataFrame(records)
    outpath = analysis_dir / "keyword_scan.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates()
    df.to_csv(outpath, index=False)
    print(f"Keyword scan complete: {outpath}")

def js_analysis(root_folder, analysis_dir, suspicious_js_patterns=None):
    if suspicious_js_patterns is None:
        suspicious_js_patterns = ["eval(", "document.write", "setTimeout", "setInterval", "Function(", "window.open", "XMLHttpRequest", "fetch(", "atob(", "btoa("]
    today = datetime.now().strftime("%Y-%m-%d")
    js_files = []
    minified_count = 0
    largest_js = {"file": "", "size": 0}
    risky_js_count = 0
    for dirpath, _, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            if f.lower().endswith(".js"):
                full_path = os.path.join(dirpath, f)
                rel_path = os.path.relpath(full_path, root_folder)
                try:
                    size = os.path.getsize(full_path)
                    if size > largest_js["size"]:
                        largest_js = {"file": rel_path, "size": size}
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file:
                        content = file.read()
                        is_minified = ".min.js" in f.lower() or (len(content) > 0 and max(len(line) for line in content.splitlines() or [""]) > 500)
                        if is_minified:
                            minified_count += 1
                        risky = any(pattern in content for pattern in suspicious_js_patterns)
                        if risky:
                            risky_js_count += 1
                    js_files.append({
                        "JS File": rel_path,
                        "Size (KB)": f"{size/1024:.2f}",
                        "Minified": is_minified,
                        "Contains Risky Pattern": risky
                    })
                except Exception:
                    continue
    summary = {
        "Date": today,
        "Total JS Files": len(js_files),
        "Minified JS Files": minified_count,
        "Largest JS File": largest_js["file"],
        "Largest JS Size (KB)": f"{largest_js['size']/1024:.2f}",
        "JS Files with Risky Patterns": risky_js_count
    }
    per_file_outpath = analysis_dir / "js_per_file.csv"
    df_js_files = pd.DataFrame(js_files)
    df_js_files.to_csv(per_file_outpath, index=False)
    summary_outpath = analysis_dir / "js_analysis.csv"
    if summary_outpath.exists():
        df_old = pd.read_csv(summary_outpath)
        df_old = df_old[df_old["Date"] != today]
        df_all = pd.concat([df_old, pd.DataFrame([summary])], ignore_index=True)
    else:
        df_all = pd.DataFrame([summary])
    df_all.to_csv(summary_outpath, index=False)
    print(f"JS analysis complete: {summary_outpath}, per-file detail: {per_file_outpath}")

def hidden_files_folders_analysis_aggressive(root_folder, analysis_dir, suspicious_terms):
    today = datetime.now().strftime("%Y-%m-%d")
    sensitive_files = [
        ".git", ".env", ".htaccess", ".htpasswd", ".DS_Store", ".svn", ".bash_history", ".ssh",
        "config.php", "wp-config.php", "local.settings.json", "settings.py", "settings.json",
        "backup.sql", "db.sql", "credentials.txt", "secrets.json", "id_rsa", "id_rsa.pub",
        "docker-compose.yml", "dockerfile", ".bashrc", ".bash_profile"
    ]
    sensitive_files = [name.lower() for name in sensitive_files]
    suspicious_terms = [t.lower() for t in suspicious_terms]
    records = []
    for dirpath, dirnames, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for d in dirnames:
            d_lc = d.lower()
            if (
                d.startswith(".")
                or d_lc in sensitive_files
                or any(term in d_lc for term in suspicious_terms)
            ):
                records.append({
                    "Date": today,
                    "Name": d,
                    "Type": "Directory",
                    "Relative Path": os.path.relpath(os.path.join(dirpath, d), root_folder)
                })
        for f in filenames:
            if should_ignore_file(f):
                continue
            f_lc = f.lower()
            if (
                f.startswith(".")
                or f_lc in sensitive_files
                or any(term in f_lc for term in suspicious_terms)
            ):
                records.append({
                    "Date": today,
                    "Name": f,
                    "Type": "File",
                    "Relative Path": os.path.relpath(os.path.join(dirpath, f), root_folder)
                })
    df = pd.DataFrame(records)
    outpath = analysis_dir / "hidden_files.csv"
    if outpath.exists():
        df_old = pd.read_csv(outpath)
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates()
    df.to_csv(outpath, index=False)
    print(f"Aggressive hidden/sensitive files analysis complete: {outpath}")

def archive_executable_analysis(root_folder, analysis_dir):
    today = datetime.now().strftime("%Y-%m-%d")
    archive_exts = ["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "tar.gz", "tar.bz2", "iso"]
    exec_exts = ["exe", "dll", "bin", "bat", "msi", "sh", "pyc", "scr", "com", "vbs", "ps1", "apk", "app", "cmd", "jar", "wsf"]
    archive_exts = set(archive_exts)
    exec_exts = set(exec_exts)
    records = []
    for dirpath, _, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            full_path = os.path.join(dirpath, f)
            rel_path = os.path.relpath(full_path, root_folder)
            ext = Path(f).suffix.lower().lstrip('.')
            file_type = None
            if ext in archive_exts:
                file_type = "Archive"
            elif ext in exec_exts:
                file_type = "Executable"
            if file_type:
                size = os.path.getsize(full_path)
                records.append({
                    "Date": today,
                    "File Type": file_type,
                    "Name": f,
                    "Relative Path": rel_path,
                    "Size (KB)": f"{size/1024:.2f}"
                })
    df = pd.DataFrame(records)
    outpath = analysis_dir / "archive_executables.csv"
    if outpath.exists():
        try:
            df_old = pd.read_csv(outpath)
        except pd.errors.EmptyDataError:
            df_old = pd.DataFrame()
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates()
    df.to_csv(outpath, index=False)
    print(f"Archive/Executable files analysis complete: {outpath}")

def image_file_analysis(root_folder, analysis_dir, large_size_kb=1024):
    today = datetime.now().strftime("%Y-%m-%d")
    image_exts = [
        "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico", "webp", "tiff"
    ]
    image_exts = set(image_exts)
    per_file_records = []
    type_counts = {ext: 0 for ext in image_exts}
    large_images = []
    for dirpath, _, filenames in os.walk(root_folder):
        if should_ignore_folder(dirpath):
            continue
        for f in filenames:
            if should_ignore_file(f):
                continue
            ext = Path(f).suffix.lower().lstrip('.')
            if ext in image_exts:
                full_path = os.path.join(dirpath, f)
                rel_path = os.path.relpath(full_path, root_folder)
                size_kb = os.path.getsize(full_path) / 1024
                per_file_records.append({
                    "Date": today,
                    "Image Name": f,
                    "Type": ext,
                    "Relative Path": rel_path,
                    "Size (KB)": f"{size_kb:.2f}"
                })
                type_counts[ext] += 1
                if size_kb > large_size_kb:
                    large_images.append({
                        "Date": today,
                        "Image Name": f,
                        "Relative Path": rel_path,
                        "Size (KB)": f"{size_kb:.2f}"
                    })
    df_files = pd.DataFrame(per_file_records)
    outpath_files = analysis_dir / "image_files.csv"
    if outpath_files.exists():
        df_old = pd.read_csv(outpath_files)
        df_files = pd.concat([df_old, df_files], ignore_index=True).drop_duplicates()
    df_files.to_csv(outpath_files, index=False)
    type_counts_row = {"Date": today}
    type_counts_row.update({k.upper(): v for k, v in type_counts.items()})
    df_counts = pd.DataFrame([type_counts_row])
    outpath_counts = analysis_dir / "image_file_stats.csv"
    if outpath_counts.exists():
        df_old = pd.read_csv(outpath_counts)
        df_counts = pd.concat([df_old, df_counts], ignore_index=True).drop_duplicates()
    df_counts.to_csv(outpath_counts, index=False)
    df_large = pd.DataFrame(large_images)
    outpath_large = analysis_dir / "large_images.csv"
    if outpath_large.exists():
        df_old = pd.read_csv(outpath_large)
        df_large = pd.concat([df_old, df_large], ignore_index=True).drop_duplicates()
    df_large.to_csv(outpath_large, index=False)
    print(f"Image file analysis complete: {outpath_files}, {outpath_counts}, {outpath_large}")

def generate_html_dashboard(analysis_dir, output_html="analysis_dashboard.html"):
    dashboard_sections = []
    def render_table(csv_path, title):
        path = Path(analysis_dir) / csv_path
        if not path.exists() or os.stat(path).st_size == 0:
            return f"<h3>{title}</h3><p><em>No data found.</em></p>"
        try:
            df = pd.read_csv(path)
        except pd.errors.EmptyDataError:
            return f"<h3>{title}</h3><p><em>No data found.</em></p>"
        html = df.to_html(index=False, border=1, classes='data-table')
        return f"<h3>{title}</h3>{html}"

        
    dashboard_sections.append("""
    <html>
    <head>
    <title>Automated Forensic Analysis Dashboard</title>
    <style>
        body {{ font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f7f7fa; }}
        h2 {{ color: #38517c; }}
        h3 {{ margin-top: 36px; color: #4d4d4d; }}
        .data-table {{ border-collapse: collapse; margin-bottom: 24px; }}
        .data-table th, .data-table td {{ border: 1px solid #b8b8b8; padding: 6px 14px; }}
        .data-table th {{ background: #e0e4ed; }}
        .data-table tr:nth-child(even) {{ background: #f2f6ff; }}
        .section-link {{ margin-right: 18px; }}
        a {{ color: #2066a2; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
    </head>
    <body>
    <h2>Automated Forensic Analysis Dashboard</h2>
    <p>Last updated: <b>{}</b></p>
    <p>
      <a class="section-link" href="#filetypes">File Types</a>
      <a class="section-link" href="#top10">Top 10 Largest Files</a>
      <a class="section-link" href="#js">JavaScript Analysis</a>
      <a class="section-link" href="#archives">Archives & Executables</a>
      <a class="section-link" href="#images">Image Stats</a>
      <a class="section-link" href="#suspicious">Suspicious Files/Names</a>
      <a class="section-link" href="#hidden">Hidden Files/Folders</a>
    </p>
    """.format(pd.Timestamp.now().strftime("%d/%m/%Y %H:%M")))
    dashboard_sections.append('<a name="filetypes"></a>' + render_table("file_type_stats.csv", "File Type Stats"))
    dashboard_sections.append('<a name="top10"></a>' + render_table("top10_largest_files.csv", "Top 10 Largest Files"))
    dashboard_sections.append('<a name="js"></a>' + render_table("js_analysis.csv", "JavaScript Analysis Summary"))
    dashboard_sections.append('<a name="archives"></a>' + render_table("archive_executables.csv", "Archives & Executables"))
    dashboard_sections.append('<a name="images"></a>' + render_table("image_file_stats.csv", "Image File Stats"))
    dashboard_sections.append('<a name="suspicious"></a>' + render_table("suspicious_files.csv", "Suspicious Files/Names"))
    dashboard_sections.append('<a name="hidden"></a>' + render_table("hidden_files.csv", "Hidden/Sensitive Files & Folders"))
    dashboard_sections.append("""
    <br>
    <p style="font-size:14px;color:#888;">Download full datasets:
        <a href="file_type_stats.csv" download>file_type_stats.csv</a> |
        <a href="top10_largest_files.csv" download>top10_largest_files.csv</a> |
        <a href="js_analysis.csv" download>js_analysis.csv</a> |
        <a href="archive_executables.csv" download>archive_executables.csv</a> |
        <a href="image_file_stats.csv" download>image_file_stats.csv</a> |
        <a href="suspicious_files.csv" download>suspicious_files.csv</a> |
        <a href="hidden_files.csv" download>hidden_files.csv</a>
    </p>
    </body></html>
    """)
    dashboard = "\n".join(dashboard_sections)
    outpath = Path(analysis_dir) / output_html
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(dashboard)
    print(f"HTML dashboard generated: {outpath}")

def folder_analysis_httrack(root_folder, analysis_dir):
    from pathlib import Path
    # Accept either str or Path for root_folder and analyze the root directly
    root_folder = Path(root_folder)
    project_folder = root_folder
    if not os.path.isdir(project_folder):
        print(f"[ERROR] Project folder not found: {project_folder}")
        return
    total_folders = 0
    empty_folders = 0
    non_empty_folders = 0
    folder_sizes = []
    mirror_folders = [os.path.join(project_folder, d) for d in os.listdir(project_folder)
                      if os.path.isdir(os.path.join(project_folder, d))]
    for folder in mirror_folders:
        if should_ignore_folder(folder):
            continue
        total_folders += 1
        folder_size = 0
        is_empty = True
        for dirpath, dirnames, filenames in os.walk(folder):
            if should_ignore_folder(dirpath):
                continue
            if filenames or dirnames:
                is_empty = False
                for f in filenames:
                    if should_ignore_file(f):
                        continue
                    file_path = os.path.join(dirpath, f)
                    if os.path.isfile(file_path):
                        folder_size += os.path.getsize(file_path)
                break
        if is_empty:
            empty_folders += 1
        else:
            non_empty_folders += 1
        folder_sizes.append({
            "Date": datetime.now().strftime("%Y-%m-%d"),
            "Mirror Folder": os.path.relpath(folder, root_folder),
            "Size (MB)": f"{folder_size/1024/1024:.2f}",
            "Is Empty": is_empty
        })
    df = pd.DataFrame(folder_sizes)
    analysis_outpath = analysis_dir / "folder_analysis.csv"
    if analysis_outpath.exists():
        df_old = pd.read_csv(analysis_outpath)
        df = pd.concat([df_old, df], ignore_index=True).drop_duplicates()
    df.to_csv(analysis_outpath, index=False)
    success_percentage = (non_empty_folders / total_folders * 100) if total_folders > 0 else 0
    summary = {
        "Date": datetime.now().strftime("%Y-%m-%d"),
        "Total Mirrors": total_folders,
        "Empty Mirrors": empty_folders,
        "Non-Empty Mirrors": non_empty_folders,
        "Success Percentage": f"{success_percentage:.2f}%"
    }
    summary_outpath = analysis_dir / "folder_summary.csv"
    if summary_outpath.exists():
        df_old = pd.read_csv(summary_outpath)
        df_all = pd.concat([df_old, pd.DataFrame([summary])], ignore_index=True).drop_duplicates()
    else:
        df_all = pd.DataFrame([summary])
    df_all.to_csv(summary_outpath, index=False)
    print(f"\nMirror Success Percentage: {success_percentage:.2f}% ({non_empty_folders}/{total_folders} mirrors)")
    print(f"Per-folder details saved to: {analysis_outpath}")
    print(f"Summary saved to: {summary_outpath}")

#Functions for wayback

def fetch_and_mirror_wayback():
    base_folder = os.getcwd()
    liveness_folder = os.path.join(base_folder, "liveness_check")
    wayback_root = os.path.join(base_folder, "Wayback_mirrors")
    os.makedirs(wayback_root, exist_ok=True)
    today_str = datetime.now().strftime("%d_%m_%Y")
    wayback_folder = os.path.join(wayback_root, today_str)
    os.makedirs(wayback_folder, exist_ok=True)
    wayback_urls_file = os.path.join(wayback_folder, "wayback_urls.txt")

    if os.path.exists(wayback_urls_file):
        print(f"Found existing wayback_urls.txt ({wayback_urls_file}). Starting mirroring...")
        mirror_with_waybackpack(wayback_urls_file, wayback_folder)
        return

    print("wayback_urls.txt not found. Generating Wayback URLs from dead sites...")

    # Step 1: Find latest liveness check CSV
    csv_files = [f for f in os.listdir(liveness_folder) if f.endswith('.csv')]
    if not csv_files:
        raise Exception("No CSV files found in liveness_check folder.")

    latest_file = max(csv_files, key=lambda x: os.path.getmtime(os.path.join(liveness_folder, x)))
    ping_file = os.path.join(liveness_folder, latest_file)
    print(f"Using latest liveness check file: {ping_file}")

    # Step 2: Filter dead URLs
    df = pd.read_csv(ping_file)
    if "Status" not in df.columns:
        raise Exception("'Status' column not found in the CSV file.")

    dead_df = df[df["Status"].apply(lambda x: str(x).lower() != "alive" and str(x) != "200" and str(x) != "0")]
    snapshot_urls = []
    checked_count = 0

    # Step 3: Query Wayback for each dead URL
    for url in dead_df["URL"]:
        checked_count += 1
        print(f"({checked_count}/{len(dead_df)}) Checking Wayback for: {url}")
        api = "http://archive.org/wayback/available"
        params = {"url": url}
        try:
            response = requests.get(api, params=params, timeout=10)
            data = response.json()
            archived_snap = data.get("archived_snapshots", {})
            if "closest" in archived_snap:
                snapshot = archived_snap["closest"]["url"]
                print(f"Snapshot found: {snapshot}")
                snapshot_urls.append(snapshot)
            else:
                print(f"No snapshot found for: {url}")
        except Exception as e:
            print(f"Error checking Wayback for {url}: {e}")
        time.sleep(0.5)  # Gentle throttling


    # Step 4: Save and mirror
    if snapshot_urls:
        with open(wayback_urls_file, "w") as f:
            for url in snapshot_urls:
                f.write(url + "\n")
        print(f"{len(snapshot_urls)} Wayback URLs saved to {wayback_urls_file}")
        mirror_with_waybackpack(wayback_urls_file, wayback_folder)
    else:
        print("No Wayback URLs to mirror.")
def mirror_dead_with_wayback(dead_urls_file, wayback_folder):
    # Query Wayback API for each dead URL and save the closest snapshot URLs
    snapshot_urls = []
    with open(dead_urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]
    for url in urls:
        api = "http://archive.org/wayback/available"
        params = {"url": url}
        try:
            response = requests.get(api, params=params, timeout=10)
            data = response.json()
            archived_snap = data.get("archived_snapshots", {})
            if "closest" in archived_snap:
                snapshot = archived_snap["closest"]["url"]
                snapshot_urls.append(snapshot)
        except Exception as e:
            print(f"Wayback query failed for {url}: {e}")
        time.sleep(0.5)
    wayback_urls_txt = os.path.join(wayback_folder, "wayback_urls.txt")
    with open(wayback_urls_txt, "w") as f:
        for s in snapshot_urls:
            f.write(s + "\n")
    print(f"{len(snapshot_urls)} Wayback snapshot URLs written to {wayback_urls_txt}")
    if snapshot_urls:
        mirror_with_waybackpack(wayback_urls_txt, wayback_folder)
    else:
        print("No Wayback snapshots to mirror.")


def mirror_with_waybackpack(urls_file, output_folder):
    # Try to locate waybackpack.exe in PATH or common locations
    waybackpack_path = shutil.which("waybackpack.exe") or shutil.which("waybackpack")
    if waybackpack_path is None:
        # Try typical user locations
        possible_locations = [
            os.path.join(sys.prefix, "Scripts", "waybackpack.exe"),
            os.path.expanduser("~/AppData/Local/Programs/Python/Python313/Scripts/waybackpack.exe"),
            os.path.expanduser("~/AppData/Local/Packages/PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0/LocalCache/local-packages/Python313/Scripts/waybackpack.exe"),
        ]
        for loc in possible_locations:
            if os.path.exists(loc):
                waybackpack_path = loc
                break
    if waybackpack_path is None:
        print("waybackpack.exe not found! Please check your installation or add it to PATH.")
        return

    with open(urls_file, "r") as f:
        urls = [line.strip() for line in f if line.strip()]

    for snapshot_url in urls:
        try:
            # Parse: http(s)://web.archive.org/web/20240501043346/https://uicex2.com/
            parts = snapshot_url.split("/")
            if len(parts) < 6 or not parts[4].isdigit():
                print(f"Invalid archive URL: {snapshot_url}")
                continue
            ts = parts[4]  # e.g. 20240501043346
            orig_url = snapshot_url.split("/", 5)[-1]  # preserve protocol
            if not orig_url.startswith("http"):
                orig_url = "http://" + orig_url
            # Clean directory name
            domain = orig_url.replace("http://", "").replace("https://", "").replace("/", "_").replace(":", "_")
            site_folder = os.path.join(output_folder, f"{domain}_{ts}")
            os.makedirs(site_folder, exist_ok=True)

            print(f"Downloading snapshot {ts} for {orig_url} ...")
            # No --uniques-only or --collapse
            cmd = [
                waybackpack_path,
                orig_url,
                "--from-date", ts,
                "--to-date", ts,
                "-d", site_folder,
                "--quiet"
            ]
            # Timeout per site: 180 seconds
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                with open(os.path.join(site_folder, "waybackpack.log"), "w", encoding="utf-8") as logf:
                    logf.write(result.stdout + "\n" + result.stderr)
                if result.returncode == 0:
                    print(f"Downloaded {orig_url} [{ts}]")
                else:
                    print(f"Failed to download {orig_url} [{ts}]\n{result.stderr}")
            except subprocess.TimeoutExpired:
                print(f"Timeout expired for {orig_url} [{ts}] (skipped)")

        except Exception as e:
            print(f"Error processing {snapshot_url} - {e}")


#Functions for mirroring

def get_dns_tld(url):
    try:
        ext = tldextract.extract(url)
        return ext.suffix
    except:
        return 'Invalid'

def ensure_folder(path):
    os.makedirs(path, exist_ok=True)
    return path

def iosco_fetch(base_folder):
    print("Fetching IOSCO CSV...")
    csv_url = "https://www.iosco.org/i-scan/?export-to-csv&SUBSECTION=main&NCA_ID=64"
    today = datetime.now().strftime("%Y-%m-%d")

    # Create subfolders
    original_csv_folder = ensure_folder(os.path.join(base_folder, "original_csv"))
    urls_folder = ensure_folder(os.path.join(base_folder, "urls"))

    original_file = os.path.join(original_csv_folder, f"original_iosco_{today}.csv")
    clean_file = os.path.join(urls_folder, f"urls_{today}.csv")

    headers = {'User-Agent': 'Mozilla/5.0'}
    response = requests.get(csv_url, headers=headers)
    response.raise_for_status()

    with open(original_file, "w", encoding="utf-8") as f:
        f.write(response.text)

    df = pd.read_csv(StringIO(response.text))

    columns_to_extract = [col for col in ['url', 'other_urls'] if col in df.columns]
    if not columns_to_extract:
        raise Exception("Columns 'url' or 'other_urls' not found in the CSV.")

    raw_urls = pd.concat([df[col].dropna().astype(str).str.strip() for col in columns_to_extract])
    split_urls = raw_urls.str.split('|').explode().str.strip()
    urls = split_urls[split_urls.str.len() > 5].drop_duplicates().reset_index(drop=True)
    urls = urls.apply(lambda x: x if x.startswith('http') else f'https://{x}')

    url_df = pd.DataFrame(urls, columns=["URL"])
    url_df.to_csv(clean_file, index=False)

    print(f"IOSCO Fetch Complete: {len(url_df)} URLs saved to {clean_file}")
    return clean_file

def ping_urls(input_file, base_folder):
    print("Starting URL liveness check...")

    today = datetime.now().strftime("%Y-%m-%d")
    liveness_folder = ensure_folder(os.path.join(base_folder, "liveness_check"))
    output_file = os.path.join(liveness_folder, f"liveness_check_results_{today}.csv")

    df = pd.read_csv(input_file)
    urls = df["URL"].dropna().tolist()

    results = []

    for url in urls:
        try:
            response = requests.get(url, timeout=5)
            http_code = response.status_code
            status = "Alive" if http_code == 200 else f"Status {http_code}"
        except Exception:
            http_code = "Error"
            status = "Not Alive"

        ping_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        results.append({
            "Ping_Timestamp": ping_time,
            "URL": url,
            "Status": status,
            "HTTP_Code": http_code,
            "DNS_TLD": get_dns_tld(url)
        })

        time.sleep(0.5)

    ping_df = pd.DataFrame(results)
    ping_df.to_csv(output_file, index=False)

    print(f"Liveness check complete: Results saved to {output_file}")
    return output_file

def filter_alive_urls(ping_file, today_folder):
    df = pd.read_csv(ping_file)
    alive_df = df[df["Status"] == "Alive"]
    alive_urls_file = os.path.join(today_folder, "alive_urls.txt")
    alive_df["URL"].to_csv(alive_urls_file, index=False, header=False)
    print(f"{len(alive_df)} Alive URLs saved to {alive_urls_file}")
    return alive_urls_file

def filter_dead_urls(ping_file, today_folder):
    df = pd.read_csv(ping_file)
    dead_df = df[df["Status"].apply(lambda x: str(x).lower() != "alive")]
    dead_urls_file = os.path.join(today_folder, "dead_urls.txt")
    dead_df["URL"].to_csv(dead_urls_file, index=False, header=False)
    print(f"  {len(dead_df)} Dead URLs saved to {dead_urls_file}")
    return dead_urls_file


def create_today_folder(base_folder):
    today_str = datetime.now().strftime("%d_%m_%Y")
    folder_path = os.path.join(base_folder, today_str)
    os.makedirs(folder_path, exist_ok=True)
    print(f"Created folder: {folder_path}")
    return folder_path

def run_httrack(urls_file, project_folder):
    if not os.path.exists(urls_file):
        print("URLs file not found.")
        return

    httrack_exe = r'"C:\Program Files\WinHTTrack\httrack.exe"'

    # Read all URLs from the file
    with open(urls_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"Mirroring {len(urls)} sites individually for proper folder structure...")
    for idx, url in enumerate(urls, 1):
        # Extract a safe folder name from the domain
        domain = url.replace('http://', '').replace('https://', '').split('/')[0]
        out_folder = os.path.join(project_folder, domain)
        os.makedirs(out_folder, exist_ok=True)

        cmd = (
            f'{httrack_exe} "{url}" -O "{out_folder}" +* -r10 -n -s0 -c8 '
            '--disable-security-limits --keep-alive --user-agent "Mozilla/5.0" --robots=0 -q'
        )

        print(f"[{idx}/{len(urls)}] Mirroring: {url} -> {out_folder}")
        subprocess.run(cmd, shell=True)

    print("  All websites mirrored into individual folders.")


# --- Main Execution ---
def main():
    base_folder = os.getcwd()

    # 1. Fetch IOSCO URLs
    iosco_file = iosco_fetch(base_folder)

    # 2. Ping URLs for liveness
    ping_file = ping_urls(iosco_file, base_folder)

    # 3. Create today's folder for this run
    today_folder = create_today_folder(base_folder)

    # 4. Split alive/dead URLs
    alive_urls_file = filter_alive_urls(ping_file, today_folder)
    dead_urls_file = filter_dead_urls(ping_file, today_folder)

    # 5. Mirror with HTTrack (alive)
    run_httrack(alive_urls_file, today_folder)

    # # 6. Mirror with Wayback (dead)
    # # Make a custom wayback_folder for output
    # wayback_root = os.path.join(base_folder, "Wayback_mirrors")
    # today_str = os.path.basename(today_folder)
    # wayback_folder = os.path.join(wayback_root, today_str)
    # os.makedirs(wayback_folder, exist_ok=True)
    # # Make a dead_urls.txt for wayback
    # shutil.copy(dead_urls_file, os.path.join(wayback_folder, "wayback_urls.txt"))
    # mirror_with_waybackpack(os.path.join(wayback_folder, "wayback_urls.txt"), wayback_folder)
    wayback_root = os.path.join(base_folder, "Wayback_mirrors")
    today_str = os.path.basename(today_folder)
    wayback_folder = os.path.join(wayback_root, today_str)
    os.makedirs(wayback_folder, exist_ok=True)
    mirror_dead_with_wayback(dead_urls_file, wayback_folder)


    # 7. Run analysis on HTTrack output
    analysis_dir_alive = ensure_analysis_folder(today_folder)
    update_file_type_stats(today_folder, analysis_dir_alive)
    update_top10_largest_files(today_folder, analysis_dir_alive)
    update_suspicious_files_folders(today_folder, analysis_dir_alive)
    keyword_content_scan(today_folder, analysis_dir_alive, suspicious_terms)
    js_analysis(today_folder, analysis_dir_alive)
    hidden_files_folders_analysis_aggressive(today_folder, analysis_dir_alive, suspicious_terms)
    archive_executable_analysis(today_folder, analysis_dir_alive)
    image_file_analysis(today_folder, analysis_dir_alive, large_size_kb=1024)
    generate_html_dashboard(analysis_dir_alive)
    folder_analysis_httrack(today_folder, analysis_dir_alive)

    # 8. Run analysis on Wayback output (optional but recommended)
    analysis_dir_wayback = ensure_analysis_folder(wayback_folder)
    update_file_type_stats(wayback_folder, analysis_dir_wayback)
    update_top10_largest_files(wayback_folder, analysis_dir_wayback)
    update_suspicious_files_folders(wayback_folder, analysis_dir_wayback)
    keyword_content_scan(wayback_folder, analysis_dir_wayback, suspicious_terms)
    js_analysis(wayback_folder, analysis_dir_wayback)
    hidden_files_folders_analysis_aggressive(wayback_folder, analysis_dir_wayback, suspicious_terms)
    archive_executable_analysis(wayback_folder, analysis_dir_wayback)
    image_file_analysis(wayback_folder, analysis_dir_wayback, large_size_kb=1024)
    generate_html_dashboard(analysis_dir_wayback)
    folder_analysis_httrack(wayback_folder, analysis_dir_wayback)

    print("All done!")

if __name__ == "__main__":
    main()
