
import json
import os
from datetime import UTC, datetime
from typing import Any, Optional

from jinja2 import Template

from src.core.config import get_config
from src.core.logging import get_logger

logger = get_logger(__name__)

HTML_REPORT_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Incident Report - {{ incident.title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a2e; background: #f8f9fa; padding: 40px; }
        .container { max-width: 900px; margin: 0 auto; background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); overflow: hidden; }
        .header { background: #1a1a2e; color: white; padding: 32px 40px; }
        .header h1 { font-size: 24px; margin-bottom: 8px; }
        .header .meta { font-size: 14px; opacity: 0.8; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; color: #1a1a2e; }
        .severity-low { background: #28a745; color: white; }
        .content { padding: 32px 40px; }
        .section { margin-bottom: 28px; }
        .section h2 { font-size: 18px; color: #1a1a2e; border-bottom: 2px solid #e9ecef; padding-bottom: 8px; margin-bottom: 16px; }
        .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
        .stat-card { background: #f8f9fa; padding: 16px; border-radius: 8px; }
        .stat-card .label { font-size: 12px; color: #6c757d; text-transform: uppercase; }
        .stat-card .value { font-size: 24px; font-weight: 700; color: #1a1a2e; }
        table { width: 100%; border-collapse: collapse; margin-top: 8px; }
        th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #e9ecef; font-size: 14px; }
        th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .action-list { list-style: none; }
        .action-list li { padding: 8px 0 8px 24px; position: relative; font-size: 14px; }
        .action-list li::before { content: "\\25B6"; position: absolute; left: 0; color: #1a1a2e; font-size: 10px; }
        .footer { background: #f8f9fa; padding: 16px 40px; font-size: 12px; color: #6c757d; text-align: center; border-top: 1px solid #e9ecef; }
        .timeline { position: relative; padding-left: 20px; }
        .timeline-item { padding: 8px 0 8px 16px; border-left: 2px solid #e9ecef; position: relative; }
        .timeline-item::before { content: ""; width: 10px; height: 10px; background: #1a1a2e; border-radius: 50%; position: absolute; left: -6px; top: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Incident Report</h1>
            <div class="meta">
                <span>{{ incident.title }}</span> &middot;
                <span class="severity-badge severity-{{ incident.severity }}">{{ incident.severity }}</span> &middot;
                <span>Risk Score: {{ "%.1f"|format(incident.risk_score|default(0)) }}/100</span>
            </div>
            <div style="margin-top: 8px; font-size: 12px; opacity: 0.7;">
                Report generated: {{ generated_at }} | Incident ID: {{ incident.id }}
            </div>
        </div>
        <div class="content">
            <div class="section">
                <h2>Executive Summary</h2>
                <p>{{ incident.ai_summary or 'No AI summary available.' }}</p>
                <p style="margin-top: 8px;"><strong>Root Cause:</strong> {{ incident.root_cause or 'Not determined' }}</p>
                <p><strong>AI Confidence:</strong> {{ "%.0f"|format((incident.ai_confidence or 0) * 100) }}%</p>
            </div>

            <div class="section">
                <h2>Incident Overview</h2>
                <div class="grid">
                    <div class="stat-card">
                        <div class="label">Total Alerts</div>
                        <div class="value">{{ incident.alert_count|default(0) }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Affected Hosts</div>
                        <div class="value">{{ (incident.affected_hosts or [])|length }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Source IPs</div>
                        <div class="value">{{ (incident.source_ips or [])|length }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="label">Status</div>
                        <div class="value" style="text-transform: capitalize;">{{ incident.status|default('open') }}</div>
                    </div>
                </div>
            </div>

            {% if incident.mitre_mapping %}
            <div class="section">
                <h2>MITRE ATT&CK Mapping</h2>
                <table>
                    <thead><tr><th>Technique ID</th><th>Technique</th><th>Tactic</th></tr></thead>
                    <tbody>
                    {% for m in incident.mitre_mapping %}
                        <tr><td>{{ m.technique_id }}</td><td>{{ m.technique }}</td><td>{{ m.tactic }}</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            {% if incident.recommended_actions %}
            <div class="section">
                <h2>Recommended Actions</h2>
                <ul class="action-list">
                {% for action in incident.recommended_actions %}
                    <li>{{ action }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}

            {% if incident.score_breakdown %}
            <div class="section">
                <h2>Risk Score Breakdown</h2>
                <table>
                    <thead><tr><th>Factor</th><th>Score</th><th>Max</th></tr></thead>
                    <tbody>
                    {% for factor, data in incident.score_breakdown.items() %}
                        <tr><td>{{ factor|replace('_', ' ')|title }}</td><td>{{ "%.1f"|format(data.score) }}</td><td>{{ data.max }}</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            <div class="section">
                <h2>Affected Assets</h2>
                <table>
                    <thead><tr><th>Hosts</th><th>Users</th><th>Source IPs</th></tr></thead>
                    <tbody>
                        <tr>
                            <td>{{ (incident.affected_hosts or [])|join(', ') or 'None' }}</td>
                            <td>{{ (incident.affected_users or [])|join(', ') or 'None' }}</td>
                            <td>{{ (incident.source_ips or [])|join(', ') or 'None' }}</td>
                        </tr>
                    </tbody>
                </table>
            </div>

            {% if incident.alerts %}
            <div class="section">
                <h2>Alert Timeline</h2>
                <div class="timeline">
                {% for alert in incident.alerts[:20] %}
                    <div class="timeline-item">
                        <strong>{{ alert.timestamp }}</strong> - {{ alert.event_type }}
                        on {{ alert.host }} (Rule: {{ alert.rule_id }})
                    </div>
                {% endfor %}
                {% if (incident.alerts or [])|length > 20 %}
                    <p style="margin-top: 8px; color: #6c757d;">... and {{ incident.alerts|length - 20 }} more alerts</p>
                {% endif %}
                </div>
            </div>
            {% endif %}
        </div>
        <div class="footer">
            Generated by Wazuh AI Correlation Engine &middot; {{ generated_at }}
        </div>
    </div>
</body>
</html>
""")


class ReportingEngine:
    def __init__(self) -> None:
        self.cfg = get_config()
        self.output_dir = self.cfg.alert_file_path.replace("alerts", "reports")
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_json(self, incident: dict[str, Any]) -> str:
        report = {
            "report_type": "incident",
            "generated_at": datetime.now(UTC).isoformat(),
            "incident": incident,
        }
        filepath = os.path.join(self.output_dir, f"incident_{incident.get('id', 'unknown')}.json")
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2, default=str)
        logger.info("json_report_generated", extra={"path": filepath})
        return filepath

    def generate_html(self, incident: dict[str, Any]) -> str:
        html = HTML_REPORT_TEMPLATE.render(
            incident=incident,
            generated_at=datetime.now(UTC).isoformat(),
        )
        filepath = os.path.join(self.output_dir, f"incident_{incident.get('id', 'unknown')}.html")
        with open(filepath, "w") as f:
            f.write(html)
        logger.info("html_report_generated", extra={"path": filepath})
        return filepath

    def generate_pdf(self, incident: dict[str, Any]) -> Optional[str]:
        try:
            html = self.generate_html(incident)
            from weasyprint import HTML
            pdf_path = html.replace(".html", ".pdf")
            HTML(filename=html).write_pdf(pdf_path)
            logger.info("pdf_report_generated", extra={"path": pdf_path})
            return pdf_path
        except ImportError:
            logger.warning("weasyprint_not_available_pdf_skipped")
            return None
        except Exception as e:
            logger.error("pdf_generation_failed", extra={"error": str(e)})
            return None

    def generate_report(self, incident: dict[str, Any], formats: list[str] | None = None) -> dict[str, str]:
        if formats is None:
            formats = ["json", "html"]

        results = {}
        if "json" in formats:
            results["json"] = self.generate_json(incident)
        if "html" in formats:
            results["html"] = self.generate_html(incident)
        if "pdf" in formats:
            pdf_path = self.generate_pdf(incident)
            if pdf_path:
                results["pdf"] = pdf_path

        return results
