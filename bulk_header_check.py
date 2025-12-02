#!/usr/bin/env python3
import requests
import csv
import re
import json
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ===============================
# HEADER KEAMANAN WAJIB
# ===============================
SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps mitigate XSS, data injection",
    "Strict-Transport-Security": "Enforce HTTPS (HSTS)",
    "X-Frame-Options": "Prevent clickjacking",
    "X-Content-Type-Options": "Prevent MIME-sniffing",
    "Referrer-Policy": "Control referrer leaks / privacy",
    "Permissions-Policy": "Control browser features (camera, geolocation, etc.)"
}

# ===============================
# ANALISIS VERSI SERVER
# ===============================
def analyze_server_version(server_header):
    if not server_header:
        return "No server header detected. (Good for security, but no version info)"
    server = server_header.lower()
    patterns = {
        "apache": r"apache/?([\d\.]+)?",
        "nginx": r"nginx/?([\d\.]+)?",
        "cloudflare": r"cloudflare",
        "iis": r"microsoft-iis/?([\d\.]+)?"
    }
    for srv, pattern in patterns.items():
        match = re.search(pattern, server)
        if match:
            version = match.group(1)
            if version:
                try:
                    major = float(version.split('.')[0])
                except:
                    return f"{srv.capitalize()} detected (version hidden)"

                if srv == "apache":
                    try:
                        minor = float(version.split('.')[1])
                    except:
                        minor = 0
                    if major < 2:
                        return f"Apache {version} — HIGH RISK"
                    elif major == 2 and minor < 4:
                        return f"Apache {version} — MEDIUM"
                    else:
                        return f"Apache {version} — OK"

                elif srv == "nginx":
                    if major < 1:
                        return f"Nginx {version} — HIGH RISK"
                    else:
                        return f"Nginx {version} — OK"

                elif srv == "iis":
                    return f"IIS {version} — Check Microsoft lifecycle"

            return f"{srv.capitalize()} detected (version hidden)"
    return "Unknown server type"

# ===============================
# NORMALISASI URL
# ===============================
def normalize_url(u):
    if not u.startswith("http://") and not u.startswith("https://"):
        return "https://" + u
    return u

# ===============================
# CEK HEADER (diperbarui untuk HTTP 415)
# ===============================
def check_headers(url, timeout=10):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        hdr = resp.headers
        missing = [h for h in SECURITY_HEADERS if h not in hdr]
        server_header = hdr.get("Server", "")
        server_risk = analyze_server_version(server_header)

        # HTTP 415 bisa diabaikan
        if resp.status_code == 415:
            print(f"  [!] Warning: Server responded 415 (Unsupported Media Type). Header check may still be valid.")

        return {
            "status_code": resp.status_code,
            "headers": dict(hdr),
            "missing_headers": missing,
            "server_header": server_header,
            "server_risk": server_risk,
            "error": None
        }

    except Exception as e:
        return {
            "status_code": None,
            "headers": {},
            "server_header": "",
            "server_risk": "Cannot analyze",
            "missing_headers": list(SECURITY_HEADERS.keys()),
            "error": str(e)
        }

# ===============================
# GENERATE PDF REPORT
# ===============================
def generate_pdf(results, output_pdf="report.pdf"):
    c = canvas.Canvas(output_pdf, pagesize=A4)
    width, height = A4
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "Bulk Header Security Report")
    y -= 30
    c.setFont("Helvetica", 10)

    for r in results:
        if y < 100:
            c.showPage()
            y = height - 50

        c.drawString(50, y, f"URL: {r['url']}")
        y -= 15
        c.drawString(60, y, f"Status Code: {r['status_code']}")
        y -= 15
        c.drawString(60, y, f"Server: {r['server_header']}")
        y -= 15
        c.drawString(60, y, f"Server Risk: {r['server_risk']}")
        y -= 15
        c.drawString(60, y, f"Missing Headers: {', '.join(r['missing_headers']) if r['missing_headers'] else 'None'}")
        y -= 25

    c.save()
    return output_pdf

# ===============================
# SIMPAN KE JSON
# ===============================
def save_json(results, filename="report.json"):
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    return filename

# ===============================
# PROSES LIST DOMAIN
# ===============================
def process_list(domains):
    results = []

    print("\n==============================")
    print("  BULK HEADER SECURITY CHECK")
    print("==============================\n")

    for d in domains:
        url = normalize_url(d.strip())
        print(f"[i] Checking: {url}")

        res = check_headers(url)

        if res["error"]:
            print(f"  [-] ERROR: {res['error']}")
        else:
            print(f"  [+] Status Code : {res['status_code']}")
            print(f"  [+] Server      : {res['server_header']}")
            print(f"  [+] Risk        : {res['server_risk']}")
            print(f"  [+] Missing     : {', '.join(res['missing_headers']) if res['missing_headers'] else 'None'}")

        print("-" * 50)

        # Simpan record
        results.append({
            "url": url,
            "status_code": res["status_code"],
            "missing_headers": res["missing_headers"],
            "server_header": res["server_header"],
            "server_risk": res["server_risk"],
            "error": res["error"],
            "raw_headers": res["headers"]
        })

    # Output PDF
    generate_pdf(results)

    # Output JSON
    save_json(results)

    print("\n[✓] Scan selesai!")
    print("[✓] PDF disimpan sebagai: report.pdf")
    print("[✓] JSON disimpan sebagai: report.json\n")

    return results

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python bulk_header_check.py domains.txt")
        sys.exit(1)

    with open(sys.argv[1], "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    process_list(domains)
