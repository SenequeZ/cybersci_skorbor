from __future__ import annotations

import time
from dataclasses import asdict
from threading import Lock
from typing import Any

from defence_scraper.analysis import (
    DEFAULT_MIN_VULNS,
    VULN_CAP_MAX,
    VULN_CAP_MIN,
    head_to_head,
    project_all,
    service_summaries,
    standings_dataframe,
    ticks_dataframe,
)
from defence_scraper.config import get_competition_config
from defence_scraper.models import STAT_COLUMNS, CompetitionSnapshot, StatKind
from defence_scraper.scraper import scrape_all

_cache_lock = Lock()
_cache: dict[str, Any] = {"snapshot": None, "fetched_at": 0.0}
CACHE_TTL = 25


def get_snapshot(force: bool = False) -> CompetitionSnapshot:
    now = time.time()
    with _cache_lock:
        if (
            not force
            and _cache["snapshot"] is not None
            and now - _cache["fetched_at"] < CACHE_TTL
        ):
            return _cache["snapshot"]

    snapshot = scrape_all()
    _cache["snapshot"] = snapshot
    _cache["fetched_at"] = now
    return snapshot


def invalidate_cache() -> None:
    with _cache_lock:
        _cache["snapshot"] = None
        _cache["fetched_at"] = 0.0


def snapshot_meta(snapshot: CompetitionSnapshot) -> dict[str, Any]:
    config = get_competition_config()
    total_vulns = sum(s.vulns for s in config.services)
    return {
        "scraped_at": snapshot.scraped_at.isoformat(),
        "title": snapshot.scoreboard.title,
        "status": snapshot.scoreboard.status,
        "competition_start": (
            snapshot.scoreboard.competition_start.isoformat()
            if snapshot.scoreboard.competition_start
            else None
        ),
        "competition_end": (
            snapshot.scoreboard.competition_end.isoformat()
            if snapshot.scoreboard.competition_end
            else None
        ),
        "teams": [
            {"id": t.team_id, "name": t.name, "place": t.place, "score": t.score}
            for t in snapshot.scoreboard.teams
        ],
        "competition": {
            "services": [
                {"name": s.name, "address": s.address, "vulns": s.vulns}
                for s in config.services
            ],
            "total_vulns": total_vulns,
            "max_theoretical_score": total_vulns * VULN_CAP_MAX,
            "min_theoretical_score": total_vulns * VULN_CAP_MIN,
        },
    }


def competition_config_payload() -> dict[str, Any]:
    return get_competition_config().to_dict()


def standings_payload(snapshot: CompetitionSnapshot, min_vulns: int = DEFAULT_MIN_VULNS) -> list[dict[str, Any]]:
    df = standings_dataframe(snapshot, min_vulns)
    if df.empty:
        return []
    return df.to_dict(orient="records")


def projections_payload(
    snapshot: CompetitionSnapshot,
    total_ticks: int | None,
    min_vulns: int = DEFAULT_MIN_VULNS,
) -> list[dict[str, Any]]:
    return [asdict(p) for p in project_all(snapshot, total_ticks, min_vulns=min_vulns)]


def services_payload(snapshot: CompetitionSnapshot) -> list[dict[str, Any]]:
    return [asdict(s) for s in service_summaries(snapshot)]


def ticks_payload(snapshot: CompetitionSnapshot, team_id: int | None = None) -> list[dict[str, Any]]:
    df = ticks_dataframe(snapshot)
    if df.empty:
        return []
    if team_id is not None:
        df = df[df["team_id"] == team_id]
    return df.to_dict(orient="records")


def team_detail_payload(snapshot: CompetitionSnapshot, team_id: int) -> dict[str, Any]:
    team = snapshot.teams[team_id]
    return team.to_dict()


def compare_payload(snapshot: CompetitionSnapshot, team_a: int, team_b: int) -> dict[str, Any]:
    df = head_to_head(snapshot, team_a, team_b)
    return {
        "team_a": df.attrs.get("team_a", ""),
        "team_b": df.attrs.get("team_b", ""),
        "wins_a": df.attrs.get("wins_a", 0),
        "wins_b": df.attrs.get("wins_b", 0),
        "ties": df.attrs.get("ties", 0),
        "ticks": df.to_dict(orient="records") if not df.empty else [],
    }


def chart_payload(snapshot: CompetitionSnapshot) -> dict[str, Any]:
    team_names = {t.team_id: t.name for t in snapshot.scoreboard.teams}
    series: dict[str, list[dict[str, Any]]] = {}

    for point in snapshot.scoreboard.chart_scores:
        name = team_names.get(int(point.team), point.team) if point.team.isdigit() else point.team
        series.setdefault(name, []).append(
            {"time": point.timestamp.isoformat(), "score": point.score, "tick": point.timestamp.isoformat()}
        )

    for team_id, team in snapshot.teams.items():
        if team.ticks:
            name = team.team_name
            if name not in series or len(team.ticks) > len(series.get(name, [])):
                series[name] = [
                    {"time": tick.time, "score": tick.score, "tick": tick.tick}
                    for tick in team.ticks
                ]

    return {"series": series}


def _all_service_names(snapshot: CompetitionSnapshot) -> list[str]:
    for team in snapshot.teams.values():
        if team.services:
            return [s.name for s in team.services]
        if team.ticks:
            return [s.service for s in team.ticks[0].services]
    return []


def service_detail_payload(
    snapshot: CompetitionSnapshot,
    service: str | None = None,
    team_id: int | None = None,
) -> dict[str, Any]:
    config = get_competition_config()
    services = _all_service_names(snapshot)
    rows: list[dict[str, Any]] = []
    service_info: dict[str, Any] = {}
    cfg_svc = config.by_name().get(service) if service else None

    for tid, team in sorted(snapshot.teams.items()):
        if team_id is not None and tid != team_id:
            continue

        if service:
            for svc_meta in team.services:
                if svc_meta.name == service:
                    service_info = {
                        "name": svc_meta.name,
                        "address": svc_meta.address,
                        "description": svc_meta.description,
                    }
                    break

        cumulative_by_service: dict[str, float] = {}

        for tick in team.ticks:
            for svc in tick.services:
                if service and svc.service != service:
                    continue

                cumulative_by_service[svc.service] = (
                    cumulative_by_service.get(svc.service, 0.0) + svc.sigma
                )
                row: dict[str, Any] = {
                    "team_id": tid,
                    "team_name": team.team_name,
                    "tick": tick.tick,
                    "time": tick.time,
                    "service": svc.service,
                    "cumulative_sigma": cumulative_by_service[svc.service],
                }
                for kind in STAT_COLUMNS:
                    val = svc.stats[kind]
                    row[kind.value] = val.value
                    row[f"{kind.value}_raw"] = val.raw
                    row[f"{kind.value}_capped"] = val.capped
                    row[f"{kind.value}_no_comm"] = val.no_comm
                    row[f"{kind.value}_capped_discarded"] = val.capped_discarded
                rows.append(row)

    if cfg_svc:
        service_info = {
            **service_info,
            "name": cfg_svc.name,
            "address": cfg_svc.address or service_info.get("address"),
            "description": cfg_svc.description or service_info.get("description"),
            "vulns": cfg_svc.vulns,
            "requests_per_tick": cfg_svc.requests_per_tick,
            "schedule": [{"tick": s.tick, "set": s.set} for s in cfg_svc.schedule],
        }

    summaries: list[dict[str, Any]] = []
    for summary in service_summaries(snapshot):
        if service and summary.service != service:
            continue
        if team_id is not None and summary.team_id != team_id:
            continue
        summaries.append(asdict(summary))

    vulns = cfg_svc.vulns if cfg_svc else None
    return {
        "services": services,
        "service_info": service_info,
        "rows": rows,
        "summaries": summaries,
        "caps": {
            "per_vuln_max": VULN_CAP_MAX,
            "per_vuln_min": VULN_CAP_MIN,
            "configured_vulns": vulns,
            "service_max": vulns * VULN_CAP_MAX if vulns else None,
            "service_min": vulns * VULN_CAP_MIN if vulns else None,
            "note": "Caps use configured vuln counts (±100 per vuln). Scoreboard /discarded signals dampen pace.",
        },
    }
