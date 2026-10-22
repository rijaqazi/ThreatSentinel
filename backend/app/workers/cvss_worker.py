"""Continuously score new alerts stored in MongoDB."""

import time

from pymongo import MongoClient

from ..core.settings import settings
from ..services.scoring.cvss_service import process_alert


def run_cvss_automation():
    if not settings.mongodb_uri:
        raise RuntimeError("MONGODB_URI must be set before running CVSS automation.")
    client = MongoClient(settings.mongodb_uri)
    alerts = client["Alerts"]["Alerts"]
    scores = client["CVSS"]["cvss"]
    print(f"[+] CVSS automation started; polling every {settings.cvss_poll_seconds} seconds.")

    while True:
        for alert in alerts.find():
            alert_id = str(alert["_id"])
            if scores.find_one({"alert_id": alert_id}):
                continue
            scores.insert_one(process_alert(alert))
            print(f"[+] CVSS score added for alert {alert_id}.")
        time.sleep(settings.cvss_poll_seconds)


def main():
    try:
        run_cvss_automation()
    except KeyboardInterrupt:
        print("[+] CVSS automation stopped.")


if __name__ == "__main__":
    main()
