"""Write dashboard.ndjson: the Chakravyuha Kibana dashboard (a data view, Lens panels, one
dashboard). After changing a panel, with Kibana running on 127.0.0.1:5601:

    uv run --project guard python guard/deploy/elk/kibana/make_dashboard.py

The objects are created through Kibana's API (so Kibana treats them as current) and then
exported with their version stamps; that export is the file the setup container imports on
`docker compose up` (see ../setup.sh). Importing unstamped Lens objects makes Kibana run every
old migration on them, which fails.
"""

import json
import sys
from pathlib import Path

import httpx

KIBANA = "http://127.0.0.1:5601"

DATA_VIEW = "chakravyuha-dv"
OUT = Path(__file__).with_name("dashboard.ndjson")


def count(label="Count", kql=None):
    column = {
        "label": label,
        "dataType": "number",
        "operationType": "count",
        "sourceField": "___records___",
        "isBucketed": False,
        "scale": "ratio",
        "customLabel": True,
    }
    if kql:
        column["filter"] = {"query": kql, "language": "kuery"}
    return column


def unique(field, label):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "unique_count",
        "sourceField": field,
        "isBucketed": False,
        "scale": "ratio",
        "customLabel": True,
    }


def average(field, label):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "average",
        "sourceField": field,
        "isBucketed": False,
        "scale": "ratio",
        "customLabel": True,
    }


def maximum(field, label):
    return {
        "label": label,
        "dataType": "number",
        "operationType": "max",
        "sourceField": field,
        "isBucketed": False,
        "scale": "ratio",
        "customLabel": True,
    }


def time_axis():
    return {
        "label": "@timestamp",
        "dataType": "date",
        "operationType": "date_histogram",
        "sourceField": "@timestamp",
        "isBucketed": True,
        "scale": "interval",
        "params": {"interval": "auto"},
    }


def terms(field, label, order_by, size=10, data_type="string"):
    return {
        "label": label,
        "dataType": data_type,
        "operationType": "terms",
        "sourceField": field,
        "isBucketed": True,
        "scale": "ordinal",
        "customLabel": True,
        "params": {
            "size": size,
            "orderBy": {"type": "column", "columnId": order_by},
            "orderDirection": "desc",
            "otherBucket": False,
            "missingBucket": False,
        },
    }


def lens(pid, title, vis_type, columns, visualization, kql=""):
    layer = {"columnOrder": list(columns), "columns": columns, "incompleteColumns": {}}
    return {
        "type": "lens",
        "id": f"chakravyuha-{pid}",
        "attributes": {
            "title": title,
            "description": "",
            "visualizationType": vis_type,
            "state": {
                "datasourceStates": {"formBased": {"layers": {"L1": layer}}},
                "visualization": visualization,
                "query": {"query": kql, "language": "kuery"},
                "filters": [],
                "internalReferences": [],
                "adHocDataViews": {},
            },
        },
        "references": [
            {"type": "index-pattern", "id": DATA_VIEW, "name": "indexpattern-datasource-layer-L1"}
        ],
    }


def xy(pid, title, columns, x, y, split=None, series="bar_stacked", kql=""):
    layer = {
        "layerId": "L1",
        "layerType": "data",
        "seriesType": series,
        "xAccessor": x,
        "accessors": y,
    }
    if split:
        layer["splitAccessor"] = split
    vis = {
        "legend": {"isVisible": True, "position": "right"},
        "preferredSeriesType": series,
        "valueLabels": "hide",
        "layers": [layer],
    }
    return lens(pid, title, "lnsXY", columns, vis, kql)


def metric(pid, title, column, kql=""):
    vis = {"layerId": "L1", "layerType": "data", "metricAccessor": "m"}
    return lens(pid, title, "lnsMetric", {"m": column}, vis, kql)


def pie(pid, title, group_field, group_label, kql=""):
    columns = {"g": terms(group_field, group_label, "c"), "c": count()}
    vis = {
        "shape": "donut",
        "layers": [
            {
                "layerId": "L1",
                "layerType": "data",
                "primaryGroups": ["g"],
                "metrics": ["c"],
                "numberDisplay": "value",
                "categoryDisplay": "default",
                "legendDisplay": "default",
            }
        ],
    }
    return lens(pid, title, "lnsPie", columns, vis, kql)


def table(pid, title, columns, kql=""):
    vis = {"layerId": "L1", "layerType": "data", "columns": [{"columnId": cid} for cid in columns]}
    return lens(pid, title, "lnsDatatable", columns, vis, kql)


PANELS = [
    # (saved object, x, y, w, h) on Kibana's 48-column grid
    (
        metric(
            "passwords",
            "Distinct passwords tried",
            unique("hedwig.password_fp", "Distinct passwords"),
        ),
        0,
        0,
        12,
        7,
    ),
    (
        metric(
            "trapped",
            "Requests answered by the maze",
            count("In the maze"),
            'event.action : "trapped"',
        ),
        12,
        0,
        12,
        7,
    ),
    (
        metric(
            "honeytokens", "Honeytoken alarms", count("Alarms"), 'event.category : "honeytoken"'
        ),
        24,
        0,
        12,
        7,
    ),
    (metric("ips", "Distinct source IPs", unique("source.ip", "Source IPs")), 36, 0, 12, 7),
    (
        xy(
            "attempts",
            "Attempts over time",
            {"t": time_axis(), "a": terms("event.action", "Action", "c"), "c": count()},
            "t",
            ["c"],
            split="a",
        ),
        0,
        7,
        32,
        13,
    ),
    (pie("outcome", "Allowed vs blocked vs trapped", "event.action", "Action"), 32, 7, 16, 13),
    (
        xy(
            "rings",
            "Stops per ring",
            {"r": terms("ring", "Ring", "c", size=8), "c": count()},
            "r",
            ["c"],
            series="bar",
            kql='not event.action : ("allowed" or "tarpitted" or '
            '"login_failed" or "challenge_solved")',
        ),
        0,
        20,
        16,
        12,
    ),
    (
        xy(
            "challenges",
            "Challenges issued vs solved",
            {
                "t": time_axis(),
                "i": count("Issued", 'event.action : "challenged"'),
                "s": count("Solved", 'event.action : "challenge_solved"'),
            },
            "t",
            ["i", "s"],
            series="line",
        ),
        16,
        20,
        16,
        12,
    ),
    (
        xy(
            "suspicion",
            "Suspicion over time",
            {
                "t": time_axis(),
                "avg": average("hedwig.suspicion", "Average"),
                "max": maximum("hedwig.suspicion", "Highest"),
            },
            "t",
            ["avg", "max"],
            series="line",
        ),
        32,
        20,
        16,
        12,
    ),
    (
        table(
            "top-ips",
            "Top source IPs",
            {
                "ip": terms("source.ip", "Source IP", "c", size=15, data_type="ip"),
                "c": count("Requests"),
                "s": maximum("hedwig.suspicion", "Highest suspicion"),
            },
        ),
        0,
        32,
        16,
        14,
    ),
    (
        xy(
            "bans-traps",
            "Bans and traps timeline",
            {"t": time_axis(), "a": terms("event.action", "Action", "c"), "c": count()},
            "t",
            ["c"],
            split="a",
            kql='event.action : ("banned" or "trapped" or "released")',
        ),
        16,
        32,
        16,
        14,
    ),
    (pie("categories", "Breakdown by category", "event.category", "Category"), 32, 32, 16, 14),
    (
        table(
            "campaigns",
            "Campaigns",
            {
                "camp": terms("campaign", "Campaign", "c", size=10),
                "c": count("Events"),
                "ips": unique("source.ip", "IPs"),
                "users": unique("user.name", "Usernames"),
            },
            "campaign : *",
        ),
        0,
        46,
        24,
        12,
    ),
    (
        table(
            "alarms",
            "Honeytoken alarms",
            {
                "ip": terms("source.ip", "Used from", "c", size=10, data_type="ip"),
                "kind": terms("hedwig.honeytoken.kind", "Token", "c", size=5),
                "c": count("Uses"),
            },
            'event.category : "honeytoken"',
        ),
        24,
        46,
        24,
        12,
    ),
]


def main() -> None:
    data_view = {
        "type": "index-pattern",
        "id": DATA_VIEW,
        "attributes": {
            "title": "chakravyuha-*",
            "name": "Chakravyuha events",
            "timeFieldName": "@timestamp",
        },
        "references": [],
    }
    panels, refs = [], []
    for i, (obj, x, y, w, h) in enumerate(PANELS, start=1):
        pid = f"p{i}"
        panels.append(
            {
                "type": "lens",
                "panelIndex": pid,
                "panelRefName": f"panel_{pid}",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                "embeddableConfig": {"enhancements": {}},
            }
        )
        refs.append({"name": f"panel_{pid}", "type": "lens", "id": obj["id"]})
    dashboard = {
        "type": "dashboard",
        "id": "chakravyuha-dashboard",
        "attributes": {
            "title": "Hedwig Chakravyuha",
            "description": "Every Guard decision: rings, traps, campaigns and honeytokens.",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps(
                {"useMargins": True, "syncColors": True, "hidePanelTitles": False}
            ),
            "timeRestore": True,
            "timeFrom": "now-1h",
            "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 5000},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(
                    {"query": {"query": "", "language": "kuery"}, "filter": []}
                )
            },
        },
        "references": refs,
    }
    objects = [data_view, *(obj for obj, *_ in PANELS), dashboard]
    with httpx.Client(base_url=KIBANA, headers={"kbn-xsrf": "true"}, timeout=30) as kibana:
        for obj in objects:
            response = kibana.post(
                f"/api/saved_objects/{obj['type']}/{obj['id']}",
                params={"overwrite": "true"},
                json={"attributes": obj["attributes"], "references": obj["references"]},
            )
            if response.status_code != 200:
                sys.exit(f"{obj['type']} {obj['id']}: {response.status_code} {response.text}")
        export = kibana.post(
            "/api/saved_objects/_export",
            json={
                "objects": [{"type": "dashboard", "id": dashboard["id"]}],
                "includeReferencesDeep": True,
                "excludeExportDetails": True,
            },
        )
        export.raise_for_status()
    lines = [line for line in export.text.splitlines() if line.strip()]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(lines)} objects, exported from {KIBANA})")


if __name__ == "__main__":
    main()
