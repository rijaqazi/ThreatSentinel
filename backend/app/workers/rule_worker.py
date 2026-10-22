"""Generate defensive rules from alerts and CVSS records."""

import argparse
import json
import time
import uuid
from pathlib import Path

from ..core.paths import RULES_DIR
from ..repositories.rule_repository import RuleRepository
from ..services.rules.rule_policy import ACTIONABLE_PRIORITIES, build_rule, decide_action


DEFAULT_RULES_DIR = RULES_DIR
DEFAULT_CHECK_INTERVAL = 30


class RuleGenerationWorker:
    """Coordinate alert retrieval, policy evaluation, and JSON rule persistence."""

    def __init__(self, repository, rules_dir=DEFAULT_RULES_DIR):
        self.repository = repository
        self.rules_dir = Path(rules_dir)
        self.processed_alerts = set()

    def load_processed_alerts(self):
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.processed_alerts.clear()
        for path in self.rules_dir.glob("*.json"):
            try:
                alert_id = json.loads(path.read_text(encoding="utf-8")).get("source_alert_id")
                if alert_id:
                    self.processed_alerts.add(str(alert_id))
            except (OSError, json.JSONDecodeError):
                continue
        return len(self.processed_alerts)

    @staticmethod
    def _monitoring_decision(alert_type, source_ip):
        return {
            "normalized_attack": alert_type,
            "action": "notify",
            "target": source_ip,
            "reason": f"{alert_type} detected (low priority - monitoring)",
            "confidence": "low",
            "expiry_seconds": 14400,
        }

    def _generate_rule(self, alert):
        source_ip = alert.get("src_ip")
        alert_type = alert.get("alert_type") or ""
        cvss_entry = self.repository.cvss_for_alert(source_ip, alert_type)
        if not cvss_entry:
            return None, "no_cvss"

        priority = (cvss_entry.get("priority", "") or "").lower()
        if priority in ACTIONABLE_PRIORITIES:
            decision = decide_action(alert, cvss_entry)
            outcome = "generated"
        else:
            decision = self._monitoring_decision(alert_type, source_ip)
            outcome = "low_priority"

        rule_id = f"rule-{uuid.uuid4().hex[:8]}"
        rule = build_rule(alert, cvss_entry, decision, rule_id)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        (self.rules_dir / f"{rule_id}.json").write_text(json.dumps(rule, indent=4), encoding="utf-8")
        return rule, outcome

    def process_new_alerts(self):
        """Generate rules only for alert IDs that have not been processed before."""
        summary = {
            "new_rules": 0,
            "skipped_processed": 0,
            "skipped_no_cvss": 0,
            "skipped_fp": 0,
            "skipped_low_priority": 0,
            "skipped_duration_na": 0,
            "total_alerts": 0,
        }
        alerts = self.repository.alerts()
        summary["total_alerts"] = len(alerts)
        for alert in alerts:
            alert_id = str(alert.get("_id"))
            if alert_id in self.processed_alerts:
                summary["skipped_processed"] += 1
                continue
            if alert.get("duration_sec") in (None, "N/A", "null", "NULL"):
                summary["skipped_duration_na"] += 1
                self.processed_alerts.add(alert_id)
                continue
            if not alert.get("src_ip"):
                summary["skipped_fp"] += 1
                self.processed_alerts.add(alert_id)
                continue

            rule, outcome = self._generate_rule(alert)
            if outcome == "no_cvss":
                summary["skipped_no_cvss"] += 1
                self.processed_alerts.add(alert_id)
                continue
            if outcome == "low_priority":
                summary["skipped_low_priority"] += 1
            self.processed_alerts.add(alert_id)
            summary["new_rules"] += 1
            print(f"[+] New rule generated: {rule['rule_id']} ({rule['alert_type']}, priority={rule['priority']})")
        return summary

    def process_all_alerts_once(self):
        """Generate rules for all currently eligible alerts."""
        summary = self.process_new_alerts()
        print("---- Summary ----")
        print(f"Total alerts processed: {summary['total_alerts']}")
        print(f"Rules generated: {summary['new_rules']}")
        print(f"Skipped - duration null/'N/A': {summary['skipped_duration_na']}")
        print(f"Skipped - false positives (no src_ip): {summary['skipped_fp']}")
        print(f"Skipped - no CVSS match: {summary['skipped_no_cvss']}")
        print(f"Skipped - low priority alerts: {summary['skipped_low_priority']}")
        return summary

    def monitor_alerts(self, interval=DEFAULT_CHECK_INTERVAL):
        print("Starting alert monitoring for rule generation...")
        print(f"Rules directory: {self.rules_dir}")
        print(f"Check interval: {interval} seconds")
        print(f"[!] Loaded {self.load_processed_alerts()} previously processed alerts")
        while True:
            try:
                summary = self.process_new_alerts()
                print(f"[+] New rules generated: {summary['new_rules']}") if summary["new_rules"] else print("[!] No new alerts to process")
            except Exception as exc:
                print(f"[x] Error in monitoring loop: {exc}")
            time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("monitor", nargs="?", choices=["monitor"], help="Continuously monitor for new alerts.")
    args = parser.parse_args()
    worker = RuleGenerationWorker(RuleRepository())
    if args.monitor:
        worker.monitor_alerts()
    else:
        print("Running one-time rule generation...")
        worker.process_all_alerts_once()
        print("\nTo monitor continuously, use: python3 -m backend.app.workers.rule_worker monitor")


if __name__ == "__main__":
    main()
