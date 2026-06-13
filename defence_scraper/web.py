from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from defence_scraper.api_data import (
    chart_payload,
    compare_payload,
    get_snapshot,
    invalidate_cache,
    projections_payload,
    service_detail_payload,
    services_payload,
    snapshot_meta,
    standings_payload,
    team_detail_payload,
    ticks_payload,
)

APP_DIR = Path(__file__).parent
STATIC_DIR = APP_DIR / "static"

app = FastAPI(title="CyberSci Defence Dashboard", version="1.0.0")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/meta")
async def api_meta(refresh: bool = Query(False)) -> dict[str, Any]:
    snapshot = get_snapshot(force=refresh)
    return snapshot_meta(snapshot)


@app.get("/api/standings")
async def api_standings(refresh: bool = Query(False)) -> list[dict[str, Any]]:
    snapshot = get_snapshot(force=refresh)
    return standings_payload(snapshot)


@app.get("/api/projections")
async def api_projections(
    total_ticks: int | None = Query(None, ge=1, le=500),
    refresh: bool = Query(False),
) -> list[dict[str, Any]]:
    snapshot = get_snapshot(force=refresh)
    return projections_payload(snapshot, total_ticks)


@app.get("/api/services")
async def api_services(refresh: bool = Query(False)) -> list[dict[str, Any]]:
    snapshot = get_snapshot(force=refresh)
    return services_payload(snapshot)


@app.get("/api/ticks")
async def api_ticks(
    team_id: int | None = Query(None, ge=0, le=8),
    refresh: bool = Query(False),
) -> list[dict[str, Any]]:
    snapshot = get_snapshot(force=refresh)
    return ticks_payload(snapshot, team_id)


@app.get("/api/service-detail")
async def api_service_detail(
    service: str | None = Query(None),
    team_id: int | None = Query(None, ge=0, le=8),
    refresh: bool = Query(False),
) -> dict[str, Any]:
    snapshot = get_snapshot(force=refresh)
    return service_detail_payload(snapshot, service, team_id)


@app.get("/api/teams/{team_id}")
async def api_team(team_id: int, refresh: bool = Query(False)) -> dict[str, Any]:
    if team_id < 0 or team_id > 8:
        raise HTTPException(status_code=400, detail="team_id must be 0-8")
    snapshot = get_snapshot(force=refresh)
    if team_id not in snapshot.teams:
        raise HTTPException(status_code=404, detail="Team not found")
    return team_detail_payload(snapshot, team_id)


@app.get("/api/compare")
async def api_compare(
    a: int = Query(..., ge=0, le=8),
    b: int = Query(..., ge=0, le=8),
    refresh: bool = Query(False),
) -> dict[str, Any]:
    if a == b:
        raise HTTPException(status_code=400, detail="Choose two different teams")
    snapshot = get_snapshot(force=refresh)
    return compare_payload(snapshot, a, b)


@app.get("/api/chart")
async def api_chart(refresh: bool = Query(False)) -> dict[str, Any]:
    snapshot = get_snapshot(force=refresh)
    return chart_payload(snapshot)


@app.post("/api/refresh")
async def api_refresh() -> dict[str, str]:
    invalidate_cache()
    get_snapshot(force=True)
    return {"status": "ok"}


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    import uvicorn

    uvicorn.run("defence_scraper.web:app", host=host, port=port, reload=False)
