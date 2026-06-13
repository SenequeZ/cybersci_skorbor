from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class StatKind(str, Enum):
    BENIGN_OK = "benign_ok"
    BENIGN_FAIL = "benign_fail"
    MALICIOUS_OK = "malicious_fail_for_team"
    MALICIOUS_FAIL = "malicious_block"
    DOWN = "down"
    CAPPED = "capped"
    SIGMA = "sigma"


STAT_COLUMNS: tuple[StatKind, ...] = (
    StatKind.BENIGN_OK,
    StatKind.BENIGN_FAIL,
    StatKind.MALICIOUS_OK,
    StatKind.MALICIOUS_FAIL,
    StatKind.DOWN,
    StatKind.CAPPED,
    StatKind.SIGMA,
)


@dataclass
class StatValue:
    raw: str
    value: float | None
    capped: bool = False
    no_comm: bool = False
    capped_discarded: float | None = None

    @property
    def numeric(self) -> float:
        return self.value if self.value is not None else 0.0


@dataclass
class ServiceInfo:
    name: str
    address: str | None = None
    description: str | None = None


@dataclass
class ServiceTickStats:
    service: str
    stats: dict[StatKind, StatValue] = field(default_factory=dict)

    @property
    def sigma(self) -> float:
        sigma = self.stats.get(StatKind.SIGMA)
        return sigma.numeric if sigma else 0.0


@dataclass
class TickRow:
    time: str
    tick: int
    services: list[ServiceTickStats]
    score: float

    def service(self, name: str) -> ServiceTickStats | None:
        for svc in self.services:
            if svc.service == name:
                return svc
        return None


@dataclass
class ScorePoint:
    timestamp: datetime
    score: float
    team: str


@dataclass
class TeamEntry:
    place: int
    name: str
    team_id: int
    score: float
    medal: str | None = None


@dataclass
class Scoreboard:
    title: str
    status: str
    teams: list[TeamEntry]
    chart_scores: list[ScorePoint]
    competition_start: datetime | None = None
    competition_end: datetime | None = None
    scraped_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "status": self.status,
            "scraped_at": self.scraped_at.isoformat(),
            "competition_start": self.competition_start.isoformat() if self.competition_start else None,
            "competition_end": self.competition_end.isoformat() if self.competition_end else None,
            "teams": [asdict(t) for t in self.teams],
            "chart_scores": [
                {"timestamp": p.timestamp.isoformat(), "score": p.score, "team": p.team}
                for p in self.chart_scores
            ],
        }


@dataclass
class TeamScoreboard:
    team_id: int
    team_name: str
    status: str
    services: list[ServiceInfo]
    ticks: list[TickRow]
    scraped_at: datetime = field(default_factory=datetime.now)

    @property
    def latest_score(self) -> float:
        if not self.ticks:
            return 0.0
        return self.ticks[-1].score

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team_id,
            "team_name": self.team_name,
            "status": self.status,
            "scraped_at": self.scraped_at.isoformat(),
            "latest_score": self.latest_score,
            "services": [asdict(s) for s in self.services],
            "ticks": [
                {
                    "time": t.time,
                    "tick": t.tick,
                    "score": t.score,
                    "services": {
                        s.service: {
                            kind.value: {
                                "raw": val.raw,
                                "value": val.value,
                                "capped": val.capped,
                                "no_comm": val.no_comm,
                                "capped_discarded": val.capped_discarded,
                            }
                            for kind, val in s.stats.items()
                        }
                        for s in t.services
                    },
                }
                for t in self.ticks
            ],
        }


@dataclass
class CompetitionSnapshot:
    scoreboard: Scoreboard
    teams: dict[int, TeamScoreboard]
    scraped_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scraped_at": self.scraped_at.isoformat(),
            "scoreboard": self.scoreboard.to_dict(),
            "teams": {str(k): v.to_dict() for k, v in self.teams.items()},
        }
