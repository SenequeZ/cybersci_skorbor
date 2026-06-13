from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup, Tag

from .models import (
    STAT_COLUMNS,
    CompetitionSnapshot,
    Scoreboard,
    ScorePoint,
    ServiceInfo,
    ServiceTickStats,
    StatKind,
    StatValue,
    TeamEntry,
    TeamScoreboard,
    TickRow,
)

BASE_URL = "https://defence.thegreatreset.ca"
TEAM_IDS = range(9)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "DefenceScoreboardScraper/1.0"})


def fetch_html(path: str) -> str:
    url = path if path.startswith("http") else f"{BASE_URL}/{path.lstrip('/')}"
    response = SESSION.get(url, timeout=30)
    response.raise_for_status()
    return response.text


def _parse_status(soup: BeautifulSoup) -> str:
    h2 = soup.find("h2", class_="text-center")
    return h2.get_text(strip=True) if h2 else ""


def _parse_place(raw: str) -> tuple[int, str | None]:
    medal_match = re.match(r"([\U0001F947\U0001F948\U0001F949🥇🥈🥉]*)(\d+)", raw)
    if medal_match:
        return int(medal_match.group(2)), medal_match.group(1) or None
    digits = re.search(r"\d+", raw)
    return (int(digits.group()), None) if digits else (0, None)


def _parse_js_date_array(html: str, var_name: str) -> list[datetime] | None:
    match = re.search(rf"{var_name}\s*:\s*\[new Date\((\d+)\),\s*new Date\((\d+)\)\]", html)
    if not match:
        return None
    return [
        datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc),
        datetime.fromtimestamp(int(match.group(2)) / 1000, tz=timezone.utc),
    ]


def _parse_chart_scores(html: str) -> list[ScorePoint]:
    block_match = re.search(r"scores\s*=\s*(\[[\s\S]*?\]);", html)
    if not block_match:
        return []

    raw = block_match.group(1)
    raw = re.sub(r"new Date\((\d+)\)", r"\1", raw)
    raw = re.sub(r",\s*]", "]", raw)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    points: list[ScorePoint] = []
    for item in data:
        ts = item.get("date")
        if isinstance(ts, (int, float)):
            timestamp = datetime.fromtimestamp(ts / 1000, tz=timezone.utc)
        elif isinstance(ts, str):
            timestamp = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            continue
        team_key = item.get("team", "")
        points.append(
            ScorePoint(
                timestamp=timestamp,
                score=float(item.get("score", 0)),
                team=str(team_key),
            )
        )
    return points


def parse_scoreboard(html: str) -> Scoreboard:
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(strip=True) if soup.title else "CyberSci Nationals"
    status = _parse_status(soup)

    teams: list[TeamEntry] = []
    table = soup.find("table")
    if table:
        for row in table.find_all("tr")[1:]:
            cells = row.find_all("td")
            if len(cells) < 3:
                continue
            place, medal = _parse_place(cells[0].get_text(strip=True))
            link = cells[1].find("a")
            href = link.get("href", "") if link else ""
            team_id_match = re.search(r"team(\d+)\.html", href)
            team_id = int(team_id_match.group(1)) if team_id_match else -1
            name = link.get_text(strip=True) if link else cells[1].get_text(strip=True)
            score = float(cells[2].get_text(strip=True) or 0)
            teams.append(TeamEntry(place=place, name=name, team_id=team_id, score=score, medal=medal))

    domain = _parse_js_date_array(html, "xDomain")
    return Scoreboard(
        title=title,
        status=status,
        teams=teams,
        chart_scores=_parse_chart_scores(html),
        competition_start=domain[0] if domain else None,
        competition_end=domain[1] if domain else None,
    )


def _parse_service_header(th: Tag) -> ServiceInfo:
    link = th.find("a")
    name = link.get_text(strip=True) if link else th.get_text(strip=True)
    address = None
    description = None
    if link and link.has_attr("title"):
        title = link["title"]
        addr_match = re.search(r"Address:\s*(.+?)(?:\n|$)", title)
        desc_match = re.search(r"Description:\s*(.+?)(?:\n|$)", title, re.DOTALL)
        address = addr_match.group(1).strip() if addr_match else None
        description = desc_match.group(1).strip() if desc_match else None
    return ServiceInfo(name=name, address=address, description=description)


def _parse_stat_cell(td: Tag) -> StatValue:
    raw = td.get_text(strip=True)
    if raw in {"", "-"}:
        return StatValue(raw=raw or "-", value=None, no_comm=raw == "-")

    capped_span = td.find("span", class_="capped")
    if capped_span or raw.startswith("/"):
        number = re.sub(r"[^\d.-]", "", raw)
        return StatValue(
            raw=raw,
            value=float(number) if number else None,
            capped=True,
        )

    try:
        return StatValue(raw=raw, value=float(raw))
    except ValueError:
        return StatValue(raw=raw, value=None)


def parse_team_page(html: str, team_id: int) -> TeamScoreboard:
    soup = BeautifulSoup(html, "html.parser")
    h1 = soup.find("h1", class_="text-center")
    team_name = h1.get_text(strip=True).split(" - ", 1)[-1] if h1 else f"Team {team_id}"
    status = _parse_status(soup)

    table = soup.find("table")
    services: list[ServiceInfo] = []
    ticks: list[TickRow] = []

    if not table:
        return TeamScoreboard(team_id=team_id, team_name=team_name, status=status, services=[], ticks=[])

    header_rows = table.find_all("tr", recursive=False)
    if not header_rows:
        return TeamScoreboard(team_id=team_id, team_name=team_name, status=status, services=[], ticks=[])

    service_headers = header_rows[0].find_all("th")
    for th in service_headers:
        colspan = int(th.get("colspan", 1))
        if colspan == 7:
            services.append(_parse_service_header(th))

    data_rows = header_rows[2:]
    for row in data_rows:
        cells = row.find_all("td")
        expected = 2 + len(services) * 7 + 1
        if len(cells) < expected:
            continue

        time_val = cells[0].get_text(strip=True)
        tick_val = int(re.sub(r"\D", "", cells[1].get_text(strip=True)) or 0)

        service_stats: list[ServiceTickStats] = []
        offset = 2
        for service in services:
            stats: dict[StatKind, StatValue] = {}
            for idx, kind in enumerate(STAT_COLUMNS):
                stats[kind] = _parse_stat_cell(cells[offset + idx])
            service_stats.append(ServiceTickStats(service=service.name, stats=stats))
            offset += 7

        score = float(cells[offset].get_text(strip=True) or 0)
        ticks.append(
            TickRow(time=time_val, tick=tick_val, services=service_stats, score=score)
        )

    ticks.sort(key=lambda t: t.tick)

    return TeamScoreboard(
        team_id=team_id,
        team_name=team_name,
        status=status,
        services=services,
        ticks=ticks,
    )


def scrape_scoreboard() -> Scoreboard:
    return parse_scoreboard(fetch_html("scoreboard.html"))


def scrape_team(team_id: int) -> TeamScoreboard:
    return parse_team_page(fetch_html(f"team{team_id}.html"), team_id)


def scrape_all(team_ids: range | list[int] | None = None) -> CompetitionSnapshot:
    ids = list(team_ids if team_ids is not None else TEAM_IDS)
    scoreboard = scrape_scoreboard()
    teams = {team_id: scrape_team(team_id) for team_id in ids}
    return CompetitionSnapshot(scoreboard=scoreboard, teams=teams)
