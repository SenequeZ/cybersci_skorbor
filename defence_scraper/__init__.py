"""CyberSci Nationals defence scoreboard scraper and analysis toolkit."""

from .analysis import (
    head_to_head,
    project_all,
    project_team,
    service_summaries,
    standings_dataframe,
    ticks_dataframe,
)
from .models import CompetitionSnapshot, Scoreboard, TeamScoreboard
from .scraper import scrape_all, scrape_scoreboard, scrape_team

__all__ = [
    "CompetitionSnapshot",
    "Scoreboard",
    "TeamScoreboard",
    "scrape_all",
    "scrape_scoreboard",
    "scrape_team",
    "project_team",
    "project_all",
    "service_summaries",
    "standings_dataframe",
    "ticks_dataframe",
    "head_to_head",
]
