"""Target-list expansion for the attack runner.

Two modes, picked by what's in config.yaml:

  flat IPs   `teams: [10.60.1.2, ...]` — a plain address list (the original
             RJ-contingency shape, no attack-defense scoring engine confirmed
             to use flag IDs, so team numbers/IDs don't apply here).

  templated  `team_numbers: [3, 4, 5]` + `target_template: "fd66:666:{team}::2"`
             — for ctf-gameserver-based events (FAUST CTF and similar) that
             assign every team a fixed, team-number-derived address, usually
             IPv6. Each target keeps its team number so flag IDs can be
             looked up per (service, team) via flagids.FlagIdCache.

Deliberately does NOT eval() an arbitrary Python expression from config —
config.yaml is local and gitignored, but there's no reason to make "target
list" a code-execution sink when a format string does the job just as well.
"""
from __future__ import annotations

from typing import TypedDict


class Target(TypedDict):
    host: str
    team: str | None  # None when running in flat-IP mode (no flag-ID lookup possible)


def expand_targets(cfg: dict) -> list[Target]:
    own_ips = {str(x) for x in cfg.get("own_ips", [])}
    own_team = str(cfg["own_team_number"]) if cfg.get("own_team_number") is not None else None

    if "team_numbers" in cfg:
        template = cfg["target_template"]
        out: list[Target] = []
        for t in cfg["team_numbers"]:
            team = str(t)
            if team == own_team:
                continue
            host = template.format(team=team)
            if host in own_ips:
                continue
            out.append({"host": host, "team": team})
        return out

    return [{"host": h, "team": None} for h in cfg.get("teams", []) if str(h) not in own_ips]
