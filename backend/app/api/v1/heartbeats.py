"""Reusable heartbeat routes for the central and legacy Flask apps."""

from flask import Blueprint, Flask, current_app, jsonify, request

from ...core.settings import settings
from ...services.alerts.heartbeat_service import create_heartbeat_service


def _service():
    service = current_app.extensions.get("heartbeat_service")
    if service is None:
        service = create_heartbeat_service()
        current_app.extensions["heartbeat_service"] = service
    return service


def create_heartbeat_blueprint(name="heartbeats"):
    router = Blueprint(name, __name__)

    @router.route("/heartbeat", methods=["GET", "POST"])
    def heartbeat():
        if request.method == "GET":
            return jsonify({"status": "success", "message": "Use POST to send heartbeat data."})
        try:
            data = _service().process(request.get_json(silent=True))
        except ValueError as exc:
            return jsonify({"status": "error", "message": str(exc)}), 400
        except Exception:
            return jsonify({"status": "error", "message": "Database update failed"}), 500
        return jsonify({"status": "success", "message": f"Heartbeat received - IP {data['action']}", "data": data})

    @router.get("/status")
    def status():
        try:
            return jsonify(_service().status())
        except Exception:
            return jsonify({"status": "error", "message": "Heartbeat status is unavailable"}), 503

    @router.get("/heartbeats")
    def heartbeats():
        try:
            records = _service().recent_heartbeats()
            return jsonify({"count": len(records), "heartbeats": records})
        except Exception:
            return jsonify({"status": "error", "message": "Heartbeat history is unavailable"}), 503

    @router.get("/active_ips")
    def active_ips():
        try:
            records = _service().active_ips()
            return jsonify({"active_count": len(records), "active_ips": records})
        except Exception:
            return jsonify({"status": "error", "message": "Active IP data is unavailable"}), 503

    return router


def create_legacy_heartbeat_app():
    app = Flask(__name__)
    app.register_blueprint(create_heartbeat_blueprint("legacy_heartbeats"), url_prefix="/api")

    @app.get("/")
    def home():
        return jsonify({"service": "heartbeat", "api": "/api"})

    return app


def main():
    """Run the standalone heartbeat service used by the local launcher."""
    if settings.heartbeat_bind_host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(
            "Do not expose the Flask development server. Use a production WSGI server behind TLS."
        )
    create_legacy_heartbeat_app().run(host=settings.heartbeat_bind_host, port=5001, debug=False)


if __name__ == "__main__":
    main()
