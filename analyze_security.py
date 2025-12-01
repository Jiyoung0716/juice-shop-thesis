import os
import json
from collections import Counter
import csv
import matplotlib
matplotlib.use("Agg")  # GitHub Actions 같은 headless 환경
import matplotlib.pyplot as plt

# -------------------- 기본 경로 -------------------- #

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
OUTPUT_DIR = os.path.join(BASE_DIR, "metrics_output")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# -------------------- SonarCloud 로더 -------------------- #

def load_sonarcloud():
    path = os.path.join(REPORTS_DIR, "sonarcloud-report", "sonarcloud.json")
    if not os.path.exists(path):
        print(f"[SonarCloud] 파일 없음: {path}")
        return Counter(), []

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    details = []

    # key → 파일 경로 매핑
    comp_paths = {}
    for c in data.get("components", []):
        key = c.get("key")
        path_ = c.get("path") or c.get("name")
        if key:
            comp_paths[key] = path_

    for issue in data.get("issues", []):
        if issue.get("status") in ("RESOLVED", "CLOSED"):
            continue

        sev = issue.get("severity", "UNKNOWN")
        rule = issue.get("rule", "")
        msg = issue.get("message", "")

        comp_key = issue.get("component")
        path_ = comp_paths.get(comp_key, comp_key)
        line = issue.get("line")

        counts[sev] += 1

        target = f"{path_}:{line}" if line else path_

        details.append({
            "tool": "sonarcloud",
            "severity": sev,
            "rule_id": rule,
            "message": msg,
            "target": target,
            "location": str(line) if line else "",
        })

    print("[SonarCloud] severity counts:", dict(counts))
    return counts, details


# -------------------- ZAP 로더 -------------------- #

def _zap_determine_severity(alert, code_map):
    """ZAP alert severity 판단."""
    risk = alert.get("risk") or alert.get("riskdesc")
    riskcode = alert.get("riskcode")

    if isinstance(risk, str):
        r = risk.lower()
        if "high" in r: return "HIGH"
        if "medium" in r: return "MEDIUM"
        if "low" in r: return "LOW"
        if "inform" in r: return "INFO"

    if riskcode is not None:
        return code_map.get(str(riskcode), "UNKNOWN")

    return "UNKNOWN"


def _zap_get_alert_url(alert):
    """ZAP alert에서 대표 URL 추출."""
    url = alert.get("url", "")
    inst = alert.get("instances") or []
    if inst and isinstance(inst, list):
        return inst[0].get("uri", url)
    return url


def load_zap():
    path = os.path.join(REPORTS_DIR, "zap-report", "report_json.json")
    if not os.path.exists(path):
        print(f"[ZAP] 파일 없음: {path}")
        return Counter(), []

    with open(path, "r") as f:
        data = json.load(f)

    counts = Counter()
    details = []

    sites = data.get("site") or data.get("sites") or []

    code_map = {
        "0": "INFO",
        "1": "LOW",
        "2": "MEDIUM",
        "3": "HIGH",
    }

    for site in sites:
        for alert in site.get("alerts") or []:
            name = alert.get("name", "")
            plugin_id = alert.get("pluginId", "")

            sev = _zap_determine_severity(alert, code_map)
            url = _zap_get_alert_url(alert)

            counts[sev] += 1

            details.append({
                "tool": "zap",
                "severity": sev,
                "rule_id": plugin_id,
                "message": name,
                "target": url,
                "location": "",
            })

    print("[ZAP] severity counts:", dict(counts))
    return counts, details


# -------------------- CSV 생성 -------------------- #

def write_csv(all_tools_counts, csv_path):
    severities = set()
    for c in all_tools_counts.values():
        severities.update(c.keys())

    severities = sorted(severities)

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tool", "severity", "count"])

        for tool, counts in all_tools_counts.items():
            for sev in severities:
                writer.writerow([tool, sev, counts.get(sev, 0)])

    print(f"[CSV] 저장 완료: {csv_path}")


def write_detailed_csv(all_details, csv_path):
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["tool", "severity", "rule_id", "target", "location", "message"])

        for d in all_details:
            writer.writerow([
                d.get("tool", ""),
                d.get("severity", ""),
                d.get("rule_id", ""),
                d.get("target", ""),
                d.get("location", ""),
                d.get("message", "").replace("\n", " "),
            ])

    print(f"[CSV] 상세 저장 완료: {csv_path}")


# -------------------- 그래프 -------------------- #

SEVERITY_ORDER = ["BLOCKER", "CRITICAL", "MAJOR", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

COLOR_MAP = {
    "BLOCKER": "#7f0000",
    "CRITICAL": "#d7301f",
    "MAJOR": "#fc4e2a",
    "HIGH": "#fc8d59",
    "MEDIUM": "#fdae61",
    "LOW": "#fee090",
    "INFO": "#e0f3f8",
    "UNKNOWN": "#cccccc",
}

ZAP_COLOR_MAP = {
    "HIGH": "#2ca02c",
    "MEDIUM": "#74c476",
    "LOW": "#a1d99b",
    "INFO": "#c7e9c0",
    "UNKNOWN": "#d0d0d0",
}

plt.style.use("ggplot")


def ordered_items(counts: Counter):
    labels = []
    values = []
    for sev in SEVERITY_ORDER:
        if sev in counts:
            labels.append(sev)
            values.append(counts[sev])
    return labels, values


def plot_bar(tool_name, counts):
    labels, values = ordered_items(counts)
    if not labels:
        print(f"[{tool_name}] 데이터 없음")
        return

    palette = ZAP_COLOR_MAP if tool_name.lower() == "zap" else COLOR_MAP
    colors = [palette.get(sev, "#999999") for sev in labels]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, values, color=colors, width=0.5)

    plt.title(f"{tool_name} Severity", fontweight="bold")
    plt.xlabel("Severity")
    plt.ylabel("Count")

    for bar, val in zip(bars, values):
        plt.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.1,
            str(val),
            ha="center",
            va="bottom",
            fontsize=9,
        )

    out_path = os.path.join(OUTPUT_DIR, f"{tool_name}_severity.png")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    print(f"[PNG] 저장 완료: {out_path}")


def plot_combined_severity(all_tools_counts):
    combined = Counter()
    for c in all_tools_counts.values():
        combined.update(c)

    labels, values = ordered_items(combined)
    if not labels:
        print("[combined] 데이터 없음")
        return

    colors = [COLOR_MAP.get(sev, "#999999") for sev in labels]

    plt.figure(figsize=(6, 4))
    bars = plt.bar(labels, values, color=colors)

    for bar, val in zip(bars, values):
        plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1, str(val),
                 ha="center", va="bottom", fon
