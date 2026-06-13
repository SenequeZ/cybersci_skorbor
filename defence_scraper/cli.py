from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .analysis import (
    head_to_head,
    project_all,
    service_summaries,
    standings_dataframe,
    ticks_dataframe,
)
from .scraper import scrape_all, scrape_scoreboard, scrape_team

app = typer.Typer(help="Scrape and analyze CyberSci Nationals defence scoreboards.")
console = Console()


@app.command()
def standings(
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write raw snapshot JSON"),
):
    """Show current standings from the main scoreboard."""
    snapshot = scrape_all()
    if json_out:
        json_out.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Saved snapshot to {json_out}[/green]")

    table = Table(title=snapshot.scoreboard.title)
    table.add_column("Place", justify="right")
    table.add_column("Team")
    table.add_column("Score", justify="right")
    table.add_column("Ticks", justify="right")
    table.add_column("Avg/Tick", justify="right")
    table.add_column("Projected", justify="right")

    df = standings_dataframe(snapshot)
    for _, row in df.iterrows():
        table.add_row(
            str(int(row["place"])),
            row["team_name"],
            f"{row['score']:.0f}",
            str(int(row["ticks"])),
            f"{row['avg_per_tick']:.2f}",
            f"{row['projected_score']:.0f}",
        )

    console.print(table)
    console.print(f"\n[dim]{snapshot.scoreboard.status}[/dim]")


@app.command()
def team(
    team_id: int = typer.Argument(..., min=0, max=8, help="Team ID (0-8)"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write team JSON"),
):
    """Show detailed tick stats for one team."""
    board = scrape_scoreboard()
    detail = scrape_team(team_id)
    if json_out:
        json_out.write_text(json.dumps(detail.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Saved team data to {json_out}[/green]")

    console.print(f"[bold]{detail.team_name}[/bold] (team {team_id})")
    console.print(f"[dim]{detail.status}[/dim]\n")

    if detail.services:
        svc_table = Table(title="Services")
        svc_table.add_column("Service")
        svc_table.add_column("Address")
        for svc in detail.services:
            svc_table.add_row(svc.name, svc.address or "-")
        console.print(svc_table)
        console.print()

    if not detail.ticks:
        console.print("[yellow]No tick data yet — competition may not have started.[/yellow]")
        score = next((t.score for t in board.teams if t.team_id == team_id), 0)
        console.print(f"Current scoreboard score: {score:.0f}")
        return

    tick_table = Table(title=f"Last {min(10, len(detail.ticks))} ticks")
    tick_table.add_column("Tick", justify="right")
    tick_table.add_column("Time")
    tick_table.add_column("Score", justify="right")
    for service in detail.services:
        tick_table.add_column(f"{service.name} Σ", justify="right")

    for tick in detail.ticks[-10:]:
        row = [str(tick.tick), tick.time, f"{tick.score:.0f}"]
        for service in detail.services:
            svc = tick.service(service.name)
            row.append(f"{svc.sigma:.0f}" if svc else "-")
        tick_table.add_row(*row)

    console.print(tick_table)


@app.command()
def project(
    total_ticks: Optional[int] = typer.Option(None, help="Override estimated total ticks"),
):
    """Project final scores and ranks from current pace."""
    snapshot = scrape_all()
    projections = project_all(snapshot, total_ticks)

    table = Table(title="Projected Final Standings")
    table.add_column("Proj", justify="right")
    table.add_column("Team")
    table.add_column("Now", justify="right")
    table.add_column("Avg/Tick", justify="right")
    table.add_column("Projected", justify="right")
    table.add_column("Uncapped", justify="right")
    table.add_column("Ticks Left", justify="right")

    for p in projections:
        uncapped = f"{p.projected_uncapped:.0f}" if p.cap_limited else "-"
        table.add_row(
            str(p.projected_place),
            p.team_name,
            f"{p.current_score:.0f}",
            f"{p.avg_score_per_tick:.2f}",
            f"{p.projected_final_score:.0f}",
            uncapped,
            str(p.ticks_remaining),
        )

    console.print(table)


@app.command()
def services():
    """Show per-service stats for all teams."""
    snapshot = scrape_all()
    summaries = service_summaries(snapshot)

    if not summaries or all(s.ticks_seen == 0 for s in summaries):
        console.print("[yellow]No tick data yet.[/yellow]")
        for team in snapshot.scoreboard.teams:
            detail = snapshot.teams[team.team_id]
            if detail.services:
                console.print(f"\n[bold]{team.name}[/bold] services:")
                for svc in detail.services:
                    console.print(f"  • {svc.name} ({svc.address or 'no address'})")
        return

    table = Table(title="Service Stats")
    table.add_column("Team")
    table.add_column("Service")
    table.add_column("Σ Total", justify="right")
    table.add_column("Avg Σ", justify="right")
    table.add_column("Blocks", justify="right")
    table.add_column("Leaks", justify="right")
    table.add_column("Down", justify="right")
    table.add_column("Win%", justify="right")

    for s in sorted(summaries, key=lambda x: (-x.total_sigma, x.team_name)):
        table.add_row(
            s.team_name,
            s.service,
            f"{s.total_sigma:.0f}",
            f"{s.avg_sigma:.2f}",
            f"{s.malicious_block_total:.0f}",
            f"{s.malicious_leak_total:.0f}",
            str(s.down_ticks),
            f"{100 * s.win_rate:.0f}%",
        )

    console.print(table)


@app.command()
def export(
    output: Path = typer.Argument(..., help="Output file (.json, .csv, or directory for both)"),
    format: str = typer.Option("all", "--format", "-f", help="json, csv, ticks, standings, or all"),
):
    """Export scraped data for manipulation in pandas/Excel."""
    snapshot = scrape_all()

    if output.suffix == ".json" or (format == "json" and output.suffix != ".csv"):
        path = output if output.suffix == ".json" else output / "snapshot.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
        console.print(f"[green]Wrote {path}[/green]")

    if output.suffix == ".csv" or format in {"csv", "ticks", "standings", "all"}:
        base = output if output.is_dir() else output.parent
        base.mkdir(parents=True, exist_ok=True)

        if format in {"csv", "standings", "all"}:
            standings_path = base / "standings.csv"
            standings_dataframe(snapshot).to_csv(standings_path, index=False)
            console.print(f"[green]Wrote {standings_path}[/green]")

        if format in {"csv", "ticks", "all"}:
            ticks_path = base / "ticks.csv"
            ticks_dataframe(snapshot).to_csv(ticks_path, index=False)
            console.print(f"[green]Wrote {ticks_path}[/green]")


@app.command()
def compare(
    team_a: int = typer.Argument(..., min=0, max=8),
    team_b: int = typer.Argument(..., min=0, max=8),
):
    """Head-to-head tick win comparison between two teams."""
    snapshot = scrape_all()
    df = head_to_head(snapshot, team_a, team_b)

    if df.empty:
        console.print("[yellow]No overlapping tick data yet.[/yellow]")
        return

    console.print(
        f"[bold]{df.attrs['team_a']}[/bold] vs [bold]{df.attrs['team_b']}[/bold]: "
        f"{df.attrs['wins_a']} - {df.attrs['wins_b']} (ties: {df.attrs['ties']})"
    )

    table = Table()
    table.add_column("Tick", justify="right")
    table.add_column(f"{df.attrs['team_a']} Δ", justify="right")
    table.add_column(f"{df.attrs['team_b']} Δ", justify="right")
    table.add_column("Winner")

    for _, row in df.iterrows():
        table.add_row(
            str(int(row["tick"])),
            f"{row['team_a_delta']:.0f}",
            f"{row['team_b_delta']:.0f}",
            row["winner"],
        )

    console.print(table)


@app.command()
def watch(
    interval: int = typer.Option(30, min=5, help="Poll interval in seconds"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Append snapshots to JSON lines file"),
):
    """Continuously poll the scoreboard (matches the site's 30s refresh)."""
    console.print(f"Watching scoreboard every {interval}s — Ctrl+C to stop")
    try:
        while True:
            snapshot = scrape_all()
            top = snapshot.scoreboard.teams[0] if snapshot.scoreboard.teams else None
            ts = snapshot.scraped_at.strftime("%H:%M:%S")
            if top:
                console.print(f"[{ts}] #{top.place} {top.name}: {top.score:.0f} — {snapshot.scoreboard.status}")
            if output:
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(snapshot.to_dict()) + "\n")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Host to bind"),
    port: int = typer.Option(8080, help="Port to bind"),
):
    """Launch the interactive web dashboard."""
    import uvicorn

    console.print(f"[green]Dashboard running at http://{host}:{port}[/green]")
    uvicorn.run("defence_scraper.web:app", host=host, port=port, reload=False)


def main():
    app()


if __name__ == "__main__":
    main()
