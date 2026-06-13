from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

CONFIG_PATH = Path(__file__).with_name("competition_config.yaml")


@dataclass
class RequestSchedule:
    tick: int
    set: list[int]


@dataclass
class ServiceConfig:
    name: str
    folder: str
    file: str
    class_name: str
    address: str
    description: str
    vulns: int
    requests_per_tick: int = 10
    schedule: list[RequestSchedule] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "folder": self.folder,
            "file": self.file,
            "class": self.class_name,
            "address": self.address,
            "description": self.description,
            "vulns": self.vulns,
            "requests": {
                "per_tick": self.requests_per_tick,
                "schedule": [{"tick": s.tick, "set": s.set} for s in self.schedule],
            },
        }


@dataclass
class CompetitionConfig:
    services: list[ServiceConfig]

    def by_name(self) -> dict[str, ServiceConfig]:
        return {s.name: s for s in self.services}

    def vulns_for(self, service_name: str, fallback: int = 1) -> int:
        svc = self.by_name().get(service_name)
        return svc.vulns if svc else fallback

    def to_dict(self) -> dict[str, Any]:
        return {"services": [s.to_dict() for s in self.services]}


def _parse_service(raw: dict[str, Any]) -> ServiceConfig:
    requests = raw.get("requests") or {}
    schedule = [
        RequestSchedule(tick=int(entry["tick"]), set=[int(x) for x in entry["set"]])
        for entry in requests.get("schedule") or []
    ]
    description = raw.get("description") or ""
    if isinstance(description, str):
        description = " ".join(description.split())
    return ServiceConfig(
        name=str(raw["name"]),
        folder=str(raw.get("folder") or ""),
        file=str(raw.get("file") or ""),
        class_name=str(raw.get("class") or ""),
        address=str(raw.get("address") or ""),
        description=description,
        vulns=int(raw.get("vulns") or 1),
        requests_per_tick=int(requests.get("per_tick") or 10),
        schedule=schedule,
    )


def load_competition_config(path: Path | None = None) -> CompetitionConfig:
    config_path = path or CONFIG_PATH
    with config_path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    services = [_parse_service(entry) for entry in data.get("services") or []]
    return CompetitionConfig(services=services)


@lru_cache(maxsize=1)
def get_competition_config() -> CompetitionConfig:
    return load_competition_config()


def reload_competition_config(path: Path | None = None) -> CompetitionConfig:
    get_competition_config.cache_clear()
    if path:
        return load_competition_config(path)
    return get_competition_config()
