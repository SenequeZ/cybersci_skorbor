from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

import math

import pandas as pd

from .models import CompetitionSnapshot, ServiceTickStats, StatKind, TeamScoreboard, TickRow


TICK_INTERVAL_MINUTES = 2
PROJECTION_WINDOW = 5
FLATLINE_LOOKBACK = 3
VULN_CAP_MAX = 100
VULN_CAP_MIN = -100
DEFAULT_MIN_VULNS = 1


@dataclass
class TeamProjection:
    team_id: int
    team_name: str
    current_score: float
    current_place: int
    ticks_completed: int
    ticks_remaining: int
    avg_score_per_tick: float
    projected_final_score: float
    projected_place: int
    score_delta_last_5_ticks: float | None
    projected_uncapped: float | None = None
    cap_limited: bool = False


@dataclass
class ServiceSummary:
    team_id: int
    team_name: str
    service: str
    ticks_seen: int
    total_sigma: float
    avg_sigma: float
    benign_ok_total: float
    benign_fail_total: float
    malicious_block_total: float
    malicious_leak_total: float
    down_ticks: int
    capped_ticks: int
    no_comm_ticks: int
    win_rate: float
    cap_headroom_up: float = 0.0
    cap_headroom_down: float = 0.0
    estimated_vulns: int = 1


def _estimate_total_ticks(snapshot: CompetitionSnapshot) -> int:
    start = snapshot.scoreboard.competition_start
    end = snapshot.scoreboard.competition_end
    if start and end:
        minutes = (end - start).total_seconds() / 60
        return max(int(minutes // TICK_INTERVAL_MINUTES), 1)
    return 120


def _estimate_vulns_for_service(
    team: TeamScoreboard,
    service_name: str,
    min_vulns: int = DEFAULT_MIN_VULNS,
) -> int:
    """Infer vulnerability count from stat totals (each vuln caps at ±100)."""
    peak = 0.0
    sigma_total = 0.0
    kind_totals: dict[StatKind, float] = {}

    for tick in team.ticks:
        svc = tick.service(service_name)
        if not svc:
            continue
        sigma_total += svc.sigma
        for kind in StatKind:
            if kind in (StatKind.SIGMA, StatKind.CAPPED):
                continue
            kind_totals[kind] = kind_totals.get(kind, 0.0) + svc.stats[kind].numeric

    candidates = [abs(sigma_total)] + [abs(v) for v in kind_totals.values()]
    peak = max(candidates) if candidates else 0.0
    if peak <= 0:
        return min_vulns
    return max(min_vulns, math.ceil(peak / VULN_CAP_MAX))


def _service_score_bounds(vuln_count: int) -> tuple[float, float]:
    return vuln_count * VULN_CAP_MIN, vuln_count * VULN_CAP_MAX


def _clamp_service_score(score: float, vuln_count: int) -> float:
    lo, hi = _service_score_bounds(vuln_count)
    return max(lo, min(hi, score))


def _service_names(team: TeamScoreboard) -> list[str]:
    if team.services:
        return [s.name for s in team.services]
    if team.ticks:
        return [s.service for s in team.ticks[0].services]
    return []


def _service_totals(team: TeamScoreboard) -> dict[str, float]:
    totals: dict[str, float] = {}
    for tick in team.ticks:
        for svc in tick.services:
            totals[svc.service] = totals.get(svc.service, 0.0) + svc.sigma
    return totals


def _service_sigma_series(team: TeamScoreboard, service_name: str) -> list[float]:
    return [
        (svc.sigma if (svc := tick.service(service_name)) else 0.0)
        for tick in team.ticks
    ]


def _service_recent_pace(team: TeamScoreboard, service_name: str, window: int = PROJECTION_WINDOW) -> float:
    sigmas = _service_sigma_series(team, service_name)
    if not sigmas:
        return 0.0
    trailing = sigmas[-FLATLINE_LOOKBACK:]
    if len(trailing) >= 2 and all(s == 0 for s in trailing):
        return 0.0
    recent = sigmas[-window:]
    return sum(recent) / len(recent)


def _project_service(
    current: float,
    pace: float,
    remaining: int,
    vuln_count: int,
) -> tuple[float, float]:
    uncapped = current + pace * remaining
    return _clamp_service_score(uncapped, vuln_count), uncapped


def _project_team_with_caps(
    team: TeamScoreboard,
    remaining: int,
    window: int = PROJECTION_WINDOW,
    min_vulns: int = DEFAULT_MIN_VULNS,
) -> tuple[float, float, float]:
    """Return (capped_projection, uncapped_projection, effective_pace)."""
    names = _service_names(team)
    totals = _service_totals(team)

    if not names:
        pace = _recent_pace(team, window)
        current = sum(totals.values())
        uncapped = current + pace * remaining
        return uncapped, uncapped, pace

    projected_sum = 0.0
    uncapped_sum = 0.0
    for name in names:
        current_svc = totals.get(name, 0.0)
        pace_svc = _service_recent_pace(team, name, window)
        vulns = _estimate_vulns_for_service(team, name, min_vulns)
        projected_svc, uncapped_svc = _project_service(current_svc, pace_svc, remaining, vulns)
        projected_sum += projected_svc
        uncapped_sum += uncapped_svc

    current_total = sum(totals.get(n, 0.0) for n in names)
    effective_pace = (projected_sum - current_total) / remaining if remaining > 0 else 0.0
    return projected_sum, uncapped_sum, effective_pace


def _tick_net_points(tick: TickRow) -> float:
    """Points earned/lost in a single tick (sum of service Σ columns)."""
    return sum(svc.sigma for svc in tick.services)


def _global_ticks_completed(snapshot: CompetitionSnapshot) -> int:
    max_tick = -1
    for team in snapshot.teams.values():
        for tick in team.ticks:
            max_tick = max(max_tick, tick.tick)
    return max_tick + 1 if max_tick >= 0 else 0


def _ticks_completed(team: TeamScoreboard) -> int:
    return len(team.ticks)


def _tick_net_series(team: TeamScoreboard) -> list[float]:
    return [_tick_net_points(t) for t in team.ticks]


def _recent_pace(team: TeamScoreboard, window: int = PROJECTION_WINDOW) -> float:
    """Average points per tick over the recent window, with flatline detection."""
    nets = _tick_net_series(team)
    if not nets:
        return 0.0

    trailing = nets[-FLATLINE_LOOKBACK:]
    if len(trailing) >= 2 and all(n == 0 for n in trailing):
        return 0.0

    recent = nets[-window:]
    return sum(recent) / len(recent)


def _score_per_tick_series(team: TeamScoreboard) -> pd.Series:
    if not team.ticks:
        return pd.Series(dtype=float)

    nets = _tick_net_series(team)
    return pd.Series(nets, index=[t.tick for t in team.ticks])


def project_team(
    snapshot: CompetitionSnapshot,
    team_id: int,
    total_ticks: int | None = None,
    window: int = PROJECTION_WINDOW,
    min_vulns: int = DEFAULT_MIN_VULNS,
) -> TeamProjection:
    board = snapshot.scoreboard
    team = snapshot.teams[team_id]
    total = total_ticks or _estimate_total_ticks(snapshot)
    global_completed = _global_ticks_completed(snapshot)
    remaining = max(total - global_completed, 0)

    board_entry = next((t for t in board.teams if t.team_id == team_id), None)
    current_score = float(board_entry.score if board_entry else team.latest_score)
    current_place = board_entry.place if board_entry else 0

    projected, uncapped, pace = _project_team_with_caps(team, remaining, window, min_vulns)
    cap_limited = abs(projected - uncapped) > 0.01

    nets = _tick_net_series(team)
    delta_last_5 = float(sum(nets[-PROJECTION_WINDOW:])) if nets else None

    return TeamProjection(
        team_id=team_id,
        team_name=team.team_name,
        current_score=current_score,
        current_place=current_place,
        ticks_completed=global_completed,
        ticks_remaining=remaining,
        avg_score_per_tick=pace,
        projected_final_score=projected,
        projected_place=0,
        score_delta_last_5_ticks=delta_last_5,
        projected_uncapped=uncapped if cap_limited else None,
        cap_limited=cap_limited,
    )


def project_all(
    snapshot: CompetitionSnapshot,
    total_ticks: int | None = None,
    window: int = PROJECTION_WINDOW,
    min_vulns: int = DEFAULT_MIN_VULNS,
) -> list[TeamProjection]:
    projections = [
        project_team(snapshot, team_id, total_ticks, window, min_vulns)
        for team_id in sorted(snapshot.teams)
    ]
    ranked = sorted(projections, key=lambda p: p.projected_final_score, reverse=True)
    place = 0
    last_score = None
    for idx, proj in enumerate(ranked, start=1):
        if last_score is None or proj.projected_final_score < last_score:
            place = idx
        proj.projected_place = place
        last_score = proj.projected_final_score
    return ranked


def service_summaries(snapshot: CompetitionSnapshot) -> list[ServiceSummary]:
    summaries: list[ServiceSummary] = []
    for team_id, team in sorted(snapshot.teams.items()):
        service_names = [s.name for s in team.services]
        if not service_names and team.ticks:
            service_names = [s.service for s in team.ticks[0].services]

        for service_name in service_names:
            total_sigma = 0.0
            benign_ok = benign_fail = malicious_block = malicious_leak = 0.0
            down_ticks = capped_ticks = no_comm_ticks = 0

            for tick in team.ticks:
                svc = tick.service(service_name)
                if not svc:
                    continue
                total_sigma += svc.sigma
                benign_ok += svc.stats[StatKind.BENIGN_OK].numeric
                benign_fail += svc.stats[StatKind.BENIGN_FAIL].numeric
                malicious_block += svc.stats[StatKind.MALICIOUS_FAIL].numeric
                malicious_leak += svc.stats[StatKind.MALICIOUS_OK].numeric
                if svc.stats[StatKind.DOWN].numeric > 0:
                    down_ticks += 1
                if svc.stats[StatKind.CAPPED].capped:
                    capped_ticks += 1
                if any(v.no_comm for v in svc.stats.values()):
                    no_comm_ticks += 1

            ticks_seen = len(team.ticks)
            win_rate = (
                sum(1 for t in team.ticks if (t.service(service_name) or ServiceTickStats(service_name)).sigma > 0)
                / ticks_seen
                if ticks_seen
                else 0.0
            )

            estimated_vulns = _estimate_vulns_for_service(team, service_name)
            svc_max, svc_min = _service_score_bounds(estimated_vulns)

            summaries.append(
                ServiceSummary(
                    team_id=team_id,
                    team_name=team.team_name,
                    service=service_name,
                    ticks_seen=ticks_seen,
                    total_sigma=total_sigma,
                    avg_sigma=total_sigma / ticks_seen if ticks_seen else 0.0,
                    benign_ok_total=benign_ok,
                    benign_fail_total=benign_fail,
                    malicious_block_total=malicious_block,
                    malicious_leak_total=malicious_leak,
                    down_ticks=down_ticks,
                    capped_ticks=capped_ticks,
                    no_comm_ticks=no_comm_ticks,
                    win_rate=win_rate,
                    cap_headroom_up=max(0.0, svc_max - total_sigma),
                    cap_headroom_down=max(0.0, total_sigma - svc_min),
                    estimated_vulns=estimated_vulns,
                )
            )
    return summaries


def ticks_dataframe(snapshot: CompetitionSnapshot) -> pd.DataFrame:
    rows = []
    for team_id, team in snapshot.teams.items():
        for tick in team.ticks:
            row = {
                "team_id": team_id,
                "team_name": team.team_name,
                "tick": tick.tick,
                "time": tick.time,
                "score": tick.score,
            }
            for svc in tick.services:
                prefix = svc.service.replace(" ", "_").lower()
                for kind, val in svc.stats.items():
                    row[f"{prefix}_{kind.value}"] = val.numeric
                    row[f"{prefix}_{kind.value}_raw"] = val.raw
            rows.append(row)
    return pd.DataFrame(rows)


def standings_dataframe(snapshot: CompetitionSnapshot, min_vulns: int = DEFAULT_MIN_VULNS) -> pd.DataFrame:
    projections = {p.team_id: p for p in project_all(snapshot, min_vulns=min_vulns)}
    rows = []
    for team in snapshot.scoreboard.teams:
        proj = projections[team.team_id]
        rows.append(
            {
                "place": team.place,
                "team_id": team.team_id,
                "team_name": team.name,
                "score": team.score,
                "ticks": proj.ticks_completed,
                "avg_per_tick": proj.avg_score_per_tick,
                "projected_score": proj.projected_final_score,
                "projected_place": proj.projected_place,
                "projected_uncapped": proj.projected_uncapped,
                "cap_limited": proj.cap_limited,
                "last_5_tick_delta": proj.score_delta_last_5_ticks,
            }
        )
    return pd.DataFrame(rows).sort_values("place")


def head_to_head(snapshot: CompetitionSnapshot, team_a: int, team_b: int) -> pd.DataFrame:
    a = snapshot.teams[team_a]
    b = snapshot.teams[team_b]
    by_tick_a = {t.tick: t for t in a.ticks}
    by_tick_b = {t.tick: t for t in b.ticks}
    shared_ticks = sorted(set(by_tick_a) & set(by_tick_b))

    rows = []
    wins_a = wins_b = ties = 0
    for tick_num in shared_ticks:
        delta_a = _score_per_tick_at(by_tick_a, tick_num)
        delta_b = _score_per_tick_at(by_tick_b, tick_num)
        if delta_a > delta_b:
            winner = a.team_name
            wins_a += 1
        elif delta_b > delta_a:
            winner = b.team_name
            wins_b += 1
        else:
            winner = "tie"
            ties += 1
        rows.append(
            {
                "tick": tick_num,
                "team_a_delta": delta_a,
                "team_b_delta": delta_b,
                "winner": winner,
            }
        )

    summary = pd.DataFrame(rows)
    summary.attrs["wins_a"] = wins_a
    summary.attrs["wins_b"] = wins_b
    summary.attrs["ties"] = ties
    summary.attrs["team_a"] = a.team_name
    summary.attrs["team_b"] = b.team_name
    return summary


def _score_per_tick_at(by_tick: dict[int, TickRow], tick_num: int) -> float:
    tick = by_tick[tick_num]
    return _tick_net_points(tick)
