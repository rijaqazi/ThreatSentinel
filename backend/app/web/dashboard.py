"""Authenticated Flask dashboard served with the migrated backend package."""

from flask import Flask, jsonify, redirect, render_template, request, send_file, send_from_directory, session, url_for
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import time
import os
import glob
import urllib.parse
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import certifi

from backend.app.core.paths import ensure_data_directories
from backend.app.core.settings import PROJECT_ROOT, settings


WEB_ROOT = PROJECT_ROOT / "frontend" / "web"
TEMPLATES_DIR = WEB_ROOT / "templates"
STATIC_DIR = WEB_ROOT / "static"

if not TEMPLATES_DIR.is_dir() or not STATIC_DIR.is_dir():
    raise RuntimeError("Dashboard templates and static files are missing from frontend/web.")

ensure_data_directories()
app = Flask(
    __name__,
    template_folder=str(TEMPLATES_DIR),
    static_folder=str(STATIC_DIR),
    static_url_path="/static",
)
@app.before_request
def block_methods():
    allowed = ['GET', 'POST', 'HEAD']
    if request.method not in allowed:
        return "Method Not Allowed", 405
@app.route("/api/health", methods=["GET", "HEAD"])
def health():
    return "OK", 200

# Initialize Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
    strategy="fixed-window"
)


dashboard_secret = os.getenv("SECRET_KEY")
if not dashboard_secret or dashboard_secret.startswith("change-me-"):
    raise RuntimeError("SECRET_KEY is not set. Add it to .env before starting the dashboard.")
dashboard_cookie_secure = os.getenv("DASHBOARD_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
app.config.update(
    SECRET_KEY=dashboard_secret,
    SESSION_COOKIE_SECURE=dashboard_cookie_secure,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)


@app.after_request
def add_security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.errorhandler(500)
def internal_error(e):
    return "Internal server error", 500

ATLAS_URI = settings.mongodb_uri
if not ATLAS_URI:
    raise RuntimeError("MONGODB_URI is not set. Add it to .env before starting the dashboard.")

try:
    client = MongoClient(
        ATLAS_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=10000,
        connectTimeoutMS=10000,
        socketTimeoutMS=30000,
        retryWrites=True
    )


    client.admin.command('ping')
    print("[+] Dashboard MongoDB connection established.")

except Exception:
    client = None
    print("[!] Dashboard could not connect to MongoDB. Database pages will be unavailable.")


if client:
    logins_db = client["Logins"]
    logins_collection = logins_db["users"]
    print(" Logins database connected")
else:
    logins_collection = None
    print(" Logins collection not available - DB connection failed")


def get_db_connections(username):
    if not client:
        raise Exception("Database connection not available. Please check MongoDB Atlas connection.")

    if username == 'internal':
        # Internal's database connections from Atlas
        ioc_db = client["ioc_database"]
        ioc_collection = ioc_db["Indicator_of_Compromise"]

        alerts_db = client["Alerts"]
        alerts_collection = alerts_db["Alerts"]

        cvss_db = client["CVSS"]
        cvss_collection = cvss_db["cvss"]
    else:  # username == 'infosecurity'
        # Infosecurity's database connections from Atlas
        infosec_db = client["organization1-infosec"]
        ioc_collection = infosec_db["iocs"]
        alerts_collection = infosec_db["alerts"]
        cvss_collection = infosec_db["cvss"]

    return ioc_collection, alerts_collection, cvss_collection


# The report worker creates PDFs beneath REPORTS_OUTPUT_DIR/REPORT and ZIPs
# beneath REPORTS_OUTPUT_DIR/zip.  The dashboard only exposes the PDF folder.
REPORTS_BASE_PATH = settings.reports_output_dir / "REPORT"
REPORTS_BASE_PATH.mkdir(parents=True, exist_ok=True)

#

@app.route('/')
@app.route('/index.html')
def home():
    return render_template("index.html")

@app.route('/Home.html')
def home_page():
    return render_template("Home.html")

@app.route('/features.html')
def features_page():
    return render_template("features.html")


def get_login_key():
    return f"login:{get_remote_address()}"


@app.route('/login.html', methods=['GET', 'POST'])
@limiter.limit("1 per minute", key_func=get_login_key, exempt_when=lambda: request.method == 'GET')
def login_page():
    if request.method == 'POST':
        work_email = request.form.get('work_email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        org_name = request.form.get('org_name')
        password = request.form.get('password')

        if not all([work_email, first_name, last_name, org_name, password]):
            return "All fields are required", 400

        username = first_name.lower()

        allowed_users = ["internal", "infosecurity"]   #two users can add more

        if username not in allowed_users:
            return "Access denied. You are not authorized to access this system.", 403


        if logins_collection is None:
            return "Database connection error. Please try again later or contact administrator.", 500

        existing_user = logins_collection.find_one({"username": username})

        if existing_user:
            if check_password_hash(existing_user['password'], password):
                session['username'] = username
                session['role'] = existing_user.get('role', 'user')

                if username == "internal":
                    return redirect(url_for("main_page"))
                elif session['role'] == "infosec":
                    return redirect(url_for("infosec_dashboard"))
            else:
                return "Invalid password.", 401
        else:
            hashed_password = generate_password_hash(password)
            user_role = "infosec" if username == "infosecurity" else "user"

            try:
                user_data = {
                    "username": username,
                    "work_email": work_email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "organization_name": org_name,
                    "password": hashed_password,
                    "role": user_role
                }
                logins_collection.insert_one(user_data)
                session['username'] = username
                session['role'] = user_role
            except Exception as e:
                return f"Error saving data: {e}", 500

            if username == "internal":
                return redirect(url_for("main_page"))
            elif user_role == "infosec":
                return redirect(url_for("infosec_dashboard"))

    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))

# ---------------- INTERNAL USER ROUTES ----------------
@app.route('/main.html')
def main_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_dashboard"))

    # Get database connections
    ioc_collection, alerts_collection, cvss_collection = get_db_connections(session['username'])

    all_data = list(cvss_collection.find(
        {}, {"_id": 0, "attack_type": 1, "cvss_score": 1, "priority": 1}
    ))

    unique = {}
    for item in all_data:
        attack = item.get("attack_type")
        if attack not in unique:
            unique[attack] = item
        if len(unique) == 6:
            break

    cvss_data = list(unique.values())
    total_alerts = alerts_collection.count_documents({})


    total_reports = 0
    try:
        if os.path.exists(REPORTS_BASE_PATH):
            # PDF files count karein, folders nahi
            pdf_files = [f for f in os.listdir(REPORTS_BASE_PATH)
                        if f.lower().endswith('.pdf') and os.path.isfile(os.path.join(REPORTS_BASE_PATH, f))]
            total_reports = len(pdf_files)
            print(f"=== DEBUG: Found {total_reports} PDF files in {REPORTS_BASE_PATH} ===")
    except Exception as e:
        print(f"Error counting reports: {e}")
        total_reports = 0

    pipeline = [
        {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    alerts_summary = list(alerts_collection.aggregate(pipeline))

    alerts_chart_data = {
        "types": [item["_id"] for item in alerts_summary],
        "counts": [item["count"] for item in alerts_summary]
    }

    ioc_pipeline = [
        {"$group": {"_id": "$pattern_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    ioc_summary = list(ioc_collection.aggregate(ioc_pipeline))

    ioc_chart_data = {
        "types": [item["_id"] for item in ioc_summary],
        "counts": [item["count"] for item in ioc_summary]
    }

    ioc_time_pipeline = [
        {
            "$group": {
                "_id": {"$substr": ["$created", 0, 10]},
                "count": {"$sum": 1}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    ioc_time_summary = list(ioc_collection.aggregate(ioc_time_pipeline))

    ioc_time_chart_data = {
        "dates": [item["_id"] for item in ioc_time_summary],
        "counts": [item["count"] for item in ioc_time_summary]
    }

    return render_template("main.html",
                           cvss_data=cvss_data,
                           total_alerts=total_alerts,
                           total_reports=total_reports,
                           alerts_chart_data=alerts_chart_data,
                           ioc_chart_data=ioc_chart_data,
                           ioc_time_chart_data=ioc_time_chart_data,
                           username=session.get('username'))

@app.route('/alerts.html')
def alerts_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_alerts_page"))

    # Get database connections
    _, alerts_collection, _ = get_db_connections(session['username'])

    # MongoDB Alerts collection data
    alerts_data = list(alerts_collection.find({}, {
        "_id": 1,
        "alert_type": 1,
        "src_ip": 1,
        "target_ip": 1,
        "src_mac": 1,
        "claimed_mac": 1,
        "previous_mac": 1,
        "ports": 1,
        "ports_scanned_count": 1,
        "start_time": 1,
        "duration_sec": 1
    }))

    # Convert ObjectId to string for JSON serialization
    for alert in alerts_data:
        alert['_id'] = str(alert['_id'])

    return render_template("alerts.html",
                           alerts_data=alerts_data,
                           username=session.get('username'),
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/ioc_list.html')
def ioc_list_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_ioc_list_page"))

    # Get database connections
    ioc_collection, _, _ = get_db_connections(session['username'])

    ioc_data = list(ioc_collection.find({}, {
        "_id": 0,
        "bundle_id": 1,
        "type": 1,
        "id": 1,
        "created": 1,
        "modified": 1,
        "name": 1,
        "ip_address": 1,
        "description": 1,
        "pattern": 1,
        "pattern_type": 1,
        "valid_from": 1,
        "labels": 1,
        "x_raw_logs": 1
    }))
    return render_template("ioc_list.html", ioc_data=ioc_data, username=session.get('username'))

@app.route('/report.html')
def report_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_report_page"))

    return render_template("report.html",
                           username=session.get('username'),
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/integration.html')
def integration_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_integration_page"))

    return render_template("integration.html", username=session.get('username'))

@app.route('/api/reports/folders')
def get_report_folders():
    try:
        print(f"=== DEBUG: Looking for reports in: {REPORTS_BASE_PATH}")

        if not os.path.exists(REPORTS_BASE_PATH):
            print("ERROR: Report folder does not exist")
            return jsonify([])

        # Get all PDF files directly in the reports path (NOT folders)
        pdf_files = glob.glob(os.path.join(REPORTS_BASE_PATH, '*.pdf'))

        # Extract just the file names without extension for display
        report_names = [os.path.splitext(os.path.basename(pdf))[0] for pdf in pdf_files]

        print(f"=== DEBUG: Found PDF files: {pdf_files}")
        print(f"=== DEBUG: Report names: {report_names}")
        print(f"=== DEBUG: Number of reports: {len(report_names)}")

        return jsonify(report_names)

    except Exception as e:
        print(f"ERROR in get_report_folders: {e}")
        return jsonify([])

@app.route('/api/reports/<path:report_name>/pdf')
def get_pdf_from_folder(report_name):
    try:
        report_name = urllib.parse.unquote(report_name)

        # Construct the full PDF file path
        pdf_file_path = os.path.join(REPORTS_BASE_PATH, f"{report_name}.pdf")

        print(f"Looking for PDF: {pdf_file_path}")

        if not os.path.exists(pdf_file_path):
            print("PDF file not found")
            return jsonify({'error': 'PDF file not found'}), 404

        # Create the web path for the PDF
        pdf_path = f"/static/Bootstrap/REPORT/{urllib.parse.quote(report_name)}.pdf"

        print(f"PDF path: {pdf_path}")
        return jsonify({'pdfPath': pdf_path})

    except Exception as e:
        print(f"Error in get_pdf_from_folder: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/download-report/<path:report_name>')
def download_report(report_name):
    try:
        report_name = urllib.parse.unquote(report_name)


        if ".." in report_name or "/" in report_name or "\\" in report_name:
            return "Invalid file name", 400


        pdf_file_path = os.path.join(REPORTS_BASE_PATH, f"{report_name}.pdf")

        if not os.path.exists(pdf_file_path):
            return "PDF file not found", 404


        if not pdf_file_path.lower().endswith(".pdf"):
            return "Invalid file type", 400

        return send_file(pdf_file_path, as_attachment=True, download_name=f"{report_name}.pdf")

    except Exception as e:
        return str(e), 500


@app.route('/static/Bootstrap/REPORT/<path:filename>')
def serve_pdf_files(filename):
    try:

        if ".." in filename or "/" in filename or "\\" in filename:
            return "Invalid file name", 400


        if not filename.lower().endswith(".pdf"):
            return "Invalid file type", 400

        return send_from_directory(REPORTS_BASE_PATH, filename)
    except Exception as e:
        return str(e), 404

@app.route('/settings.html')
def settings_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))

    if session.get('username') != 'internal':
        return "Access denied. This page is only for Internal Admin.", 403

    if session.get("role") != "user":
        return redirect(url_for("infosec_settings_page"))

    user_prefs = logins_collection.find_one(
        {"username": session['username']},
        {"settings": 1}
    )

    settings = user_prefs.get('settings', {}) if user_prefs else {}

    return render_template("settings.html",
                           username=session.get('username'),
                           settings=settings)


@app.route('/api/latest_alerts')
def get_latest_alerts():
    """Get latest alerts for real-time updates"""
    try:
        # Get database connections
        _, alerts_collection, _ = get_db_connections(session['username'])

        # Last 10 alerts from MongoDB
        latest_alerts = list(alerts_collection.find().sort([("_id", -1)]).limit(10))

        # Convert ObjectId to string
        for alert in latest_alerts:
            alert['_id'] = str(alert['_id'])

        return jsonify(latest_alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/check_new_alerts')
def check_new_alerts():
    """Check for new alerts in last 2 minutes - Only return unseen alerts"""
    try:
        # Get database connections
        _, alerts_collection, _ = get_db_connections(session['username'])

        two_minutes_ago = datetime.now() - timedelta(minutes=2)

        # Get recent alerts
        new_alerts = list(alerts_collection.find({
            'start_time': {'$gte': two_minutes_ago.isoformat()}
        }).sort([("_id", -1)]).limit(10))

        # Convert ObjectId to string
        for alert in new_alerts:
            alert['_id'] = str(alert['_id'])

        return jsonify({
            'new_alerts': len(new_alerts) > 0,
            'alerts': new_alerts,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts_data')
def get_alerts_data():
    """Get all alerts data for table refresh"""
    try:
        # Get database connections
        _, alerts_collection, _ = get_db_connections(session['username'])

        alerts_data = list(alerts_collection.find({}, {
            "_id": 1,
            "alert_type": 1,
            "src_ip": 1,
            "target_ip": 1,
            "src_mac": 1,
            "claimed_mac": 1,
            "previous_mac": 1,
            "ports": 1,
            "ports_scanned_count": 1,
            "start_time": 1,
            "duration_sec": 1
        }))

        # Convert ObjectId to string
        for alert in alerts_data:
            alert['_id'] = str(alert['_id'])

        return jsonify(alerts_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/recent_alerts')
def get_recent_alerts():
    try:
        _, alerts_collection, _ = get_db_connections(session['username'])


        recent_alerts = list(alerts_collection.find().sort([("_id", -1)]))  # Fetch all alerts

        # Format for popup display
        formatted_alerts = []
        for alert in recent_alerts:
            formatted_alerts.append({
                'id': str(alert['_id']),
                'src': alert.get('src_ip', 'Unknown'),
                'reason': alert.get('alert_type', 'Security Alert'),
                'time': time.time(),
                'type': 'info'
            })

        return jsonify(formatted_alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/update_settings', methods=['POST'])
def update_settings():
    if 'username' not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    try:
        data = request.get_json()
        setting_type = data.get('type')
        value = data.get('value')

        logins_collection.update_one(
            {"username": session['username']},
            {"$set": {f"settings.{setting_type}": value}}
        )

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'username' not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    try:
        data = request.get_json()
        current_password = data.get('currentPassword')
        new_password = data.get('newPassword')

        user = logins_collection.find_one({"username": session['username']})

        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404

        if not check_password_hash(user['password'], current_password):
            return jsonify({"success": False, "message": "Current password is incorrect"}), 400

        hashed_password = generate_password_hash(new_password)
        logins_collection.update_one(
            {"username": session['username']},
            {"$set": {"password": hashed_password}}
        )

        return jsonify({"success": True, "message": "Password updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/get_settings', methods=['GET'])
def get_settings():
    if 'username' not in session:
        return jsonify({"success": False, "message": "Not authenticated"}), 401

    try:
        user = logins_collection.find_one(
            {"username": session['username']},
            {"settings": 1}
        )
        settings = user.get('settings', {}) if user else {}
        return jsonify(settings)
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/blog.html')
def blog_page():
    return render_template("blog.html", username=session.get('username'))

@app.route('/about.html')
def about_page():
    return render_template("about.html", username=session.get('username'))

@app.route('/news.html')
def news_page():
    return render_template("news.html", username=session.get('username'))

@app.route('/demoform.html')
def demoform_page():
    return render_template("demoform.html", username=session.get('username'))

@app.route('/Events.html')
def events_page():
    return render_template("Events.html", username=session.get('username'))

@app.route('/blog-post2.html')
def blogpost2_page():
    return render_template("blog-post2.html", username=session.get('username'))

@app.route('/blog-post3.html')
def blogpost3_page():
    return render_template("blog-post3.html", username=session.get('username'))

@app.route('/blog-post4.html')
def blogpost4_page():
    return render_template("blog-post4.html", username=session.get('username'))

@app.route('/blog-post5.html')
def blogpost5_page():
    return render_template("blog-post5.html", username=session.get('username'))

@app.route('/blog-post6.html')
def blogpost6_page():
    return render_template("blog-post6.html", username=session.get('username'))

@app.route('/blog-post7.html')
def blogpost7_page():
    return render_template("blog-post7.html", username=session.get('username'))

@app.route('/blog-post8.html')
def blogpost8_page():
    return render_template("blog-post8.html", username=session.get('username'))

@app.route('/news-2.html')
def news2_page():
    return render_template("news-2.html", username=session.get('username'))

@app.route('/news-3.html')
def news3_page():
    return render_template("news-3.html", username=session.get('username'))

@app.route('/news-4.html')
def news4_page():
    return render_template("news-4.html", username=session.get('username'))

@app.route('/news-5.html')
def news5_page():
    return render_template("news-5.html", username=session.get('username'))

@app.route('/news-6.html')
def news6_page():
    return render_template("news-6.html", username=session.get('username'))

@app.route('/news-7.html')
def news7_page():
    return render_template("news-7.html", username=session.get('username'))

@app.route('/news-8.html')
def news8_page():
    return render_template("news-8.html", username=session.get('username'))

@app.route('/news-9.html')
def news9_page():
    return render_template("news-9.html", username=session.get('username'))

# ---------------- INFOSEC ENGINEER ROUTES ----------------
@app.route('/infosec_main.html')
def infosec_dashboard():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("main_page"))

    # Get database connections
    ioc_collection, alerts_collection, cvss_collection = get_db_connections(session['username'])

    all_data = list(cvss_collection.find(
        {}, {"_id": 0, "attack_type": 1, "cvss_score": 1, "priority": 1}
    ))

    unique = {}
    for item in all_data:
        attack = item.get("attack_type")
        if attack not in unique:
            unique[attack] = item
        if len(unique) == 6:
            break

    cvss_data = list(unique.values())
    total_alerts = alerts_collection.count_documents({})

    pipeline = [
        {"$group": {"_id": "$alert_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    alerts_summary = list(alerts_collection.aggregate(pipeline))

    alerts_chart_data = {
        "types": [item["_id"] for item in alerts_summary],
        "counts": [item["count"] for item in alerts_summary]
    }

    ioc_pipeline = [
        {"$group": {"_id": "$pattern_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    ioc_summary = list(ioc_collection.aggregate(ioc_pipeline))

    ioc_chart_data = {
        "types": [item["_id"] for item in ioc_summary],
        "counts": [item["count"] for item in ioc_summary]
    }

    ioc_time_pipeline = [
        {
            "$group": {
                "_id": {"$substr": ["$created", 0, 10]},
                "count": {"$sum": 1}
            }
        },
        {"$sort": {"_id": 1}}
    ]
    ioc_time_summary = list(ioc_collection.aggregate(ioc_time_pipeline))

    ioc_time_chart_data = {
        "dates": [item["_id"] for item in ioc_time_summary],
        "counts": [item["count"] for item in ioc_time_summary]
    }

    user_data = logins_collection.find_one({"username": session['username']})
    organization_name = user_data.get('organization_name', 'Security Team') if user_data else 'Security Team'

    return render_template("infosec_main.html",
                           cvss_data=cvss_data,
                           total_alerts=total_alerts,
                           alerts_chart_data=alerts_chart_data,
                           ioc_chart_data=ioc_chart_data,
                           ioc_time_chart_data=ioc_time_chart_data,
                           username=session.get('username'),
                           organization=organization_name,
                           dashboard_title="Security Team Dashboard")

@app.route('/infosec_ioc_list.html')
def infosec_ioc_list_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("ioc_list_page"))

    # Get database connections
    ioc_collection, _, _ = get_db_connections(session['username'])

    ioc_data = list(ioc_collection.find({}, {
        "_id": 0,
        "bundle_id": 1,
        "type": 1,
        "id": 1,
        "created": 1,
        "modified": 1,
        "name": 1,
        "ip_address": 1,
        "description": 1,
        "pattern": 1,
        "pattern_type": 1,
        "valid_from": 1,
        "labels": 1,
        "x_raw_logs": 1
    }))
    return render_template("infosec_ioc_list.html", ioc_data=ioc_data, username=session['username'])

@app.route('/infosec_alerts.html')
def infosec_alerts_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("alerts_page"))

    # Get database connections
    _, alerts_collection, _ = get_db_connections(session['username'])

    # MongoDB Alerts collection data
    alerts_data = list(alerts_collection.find({}, {
        "_id": 1,
        "alert_type": 1,
        "src_ip": 1,
        "target_ip": 1,
        "src_mac": 1,
        "claimed_mac": 1,
        "previous_mac": 1,
        "ports": 1,
        "ports_scanned_count": 1,
        "start_time": 1,
        "duration_sec": 1
    }))

    # Convert ObjectId to string for JSON serialization
    for alert in alerts_data:
        alert['_id'] = str(alert['_id'])

    return render_template("infosec_alerts.html",
                           alerts_data=alerts_data,
                           username=session['username'],
                           current_time=datetime.now().strftime("%Y-%m-d %H:%M:%S"))

@app.route('/infosec_report.html')
def infosec_report_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("report_page"))

    return render_template("infosec_report.html",
                           username=session['username'],
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/infosec_integration.html')
def infosec_integration_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("integration_page"))
    return render_template("infosec_integration.html", username=session['username'])

@app.route('/infosec_settings.html')
def infosec_settings_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("settings_page"))

    user_prefs = logins_collection.find_one(
        {"username": session['username']},
        {"settings": 1}
    )

    settings = user_prefs.get('settings', {}) if user_prefs else {}

    return render_template("infosec_settings.html",
                           username=session['username'],
                           settings=settings)

# INFOSEC NOTIFICATION PAGE ROUTE
@app.route('/infosec_notification.html')
def infosec_notification_page():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    if session.get("role") != "infosec":
        return redirect(url_for("main_page"))

    return render_template("infosec_notification.html", username=session['username'])

def main():
    """Run the dashboard locally without exposing Flask's development server."""
    if settings.dashboard_bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            "Do not expose the Flask development server. Use a production WSGI server behind TLS."
        )
    app.run(host=settings.dashboard_bind_host, port=settings.dashboard_port, debug=False)


if __name__ == "__main__":
    main()
