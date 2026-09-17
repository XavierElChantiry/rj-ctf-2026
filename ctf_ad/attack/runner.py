"""Attack-side round runner for an attack/defend CTF.

Each round: run every discovered exploit against every enemy team, collect
candidate output, validate against the flag regex, dedupe against flags
already captured, and submit new ones through the configured backend.

Usage:
    python -m ctf_ad.attack.runner --config ctf_ad/config.yaml           # loop forever
    python -m ctf_ad.attack.runner --config ctf_ad/config.yaml --once    # single round
    python -m ctf_ad.attack.runner --config ctf_ad/config.yaml --dry-run # force NullSubmitter
"""
from __future__ import annotations

import argparse
import importlib
import logging
import pkgutil
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from types import ModuleType

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_ad.attack import exploits as exploits_pkg
from ctf_ad.attack.flagids import FlagIdCache
from ctf_ad.attack.submitters import Submitter, build_submitter
from ctf_ad.common.flags import FlagStore, compile_flag_regex, extract_flags
from ctf_ad.common.targets import Target, expand_targets

log = logging.getLogger("ctf_ad.attack")

# The exact placeholder IPs shipped in config.example.yaml — if `teams` still
# matches this, the operator copied the template without filling in real
# enemy hosts, so refuse to fire exploits at it.
EXAMPLE_TEAMS = {"10.60.1.2", "10.60.2.2", "10.60.3.2"}


def load_exploits() -> list[ModuleType]:
    mods = []
    for info in pkgutil.iter_modules(exploits_pkg.__path__):
        if info.name.startswith("_"):
            continue
        mod = importlib.import_module(f"ctf_ad.attack.exploits.{info.name}")
        if not hasattr(mod, "SERVICE_NAME") or not hasattr(mod, "run"):
            log.warning("skipping %s: missing SERVICE_NAME/run", info.name)
            continue
        mods.append(mod)
    return mods


def run_round(
    targets: list[Target],
    exploit_mods: list[ModuleType],
    timeout: float,
    concurrency: int,
    flag_regex,
    flag_store: FlagStore,
    submitter: Submitter,
    flagid_cache: FlagIdCache | None,
) -> dict[str, int]:
    stats = {"attempts": 0, "raw_hits": 0, "new_flags": 0, "submitted": 0, "errors": 0}

    def attempt(mod: ModuleType, tgt: Target) -> list[str]:
        ids = flagid_cache.get(mod.SERVICE_NAME, tgt["team"]) if flagid_cache and tgt["team"] else []
        try:
            return mod.run(tgt["host"], timeout, flag_ids=ids) or []
        except TypeError:
            # exploit module hasn't been updated to accept flag_ids yet
            return mod.run(tgt["host"], timeout) or []
        except Exception:
            log.exception("exploit %s crashed against %s", mod.SERVICE_NAME, tgt["host"])
            return []

    jobs = [(mod, tgt) for mod in exploit_mods for tgt in targets]
    stats["attempts"] = len(jobs)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(attempt, mod, tgt): (mod, tgt) for mod, tgt in jobs}
        for fut in as_completed(futures):
            mod, tgt = futures[fut]
            try:
                outputs = fut.result()
            except Exception:
                stats["errors"] += 1
                continue

            for raw in outputs:
                for flag in extract_flags(raw, flag_regex):
                    stats["raw_hits"] += 1
                    if not flag_store.is_new(flag):
                        continue
                    stats["new_flags"] += 1
                    log.info("NEW FLAG via %s @ %s: %s", mod.SERVICE_NAME, tgt["host"], flag)
                    flag_store.mark_seen(flag)
                    if submitter.submit(flag):
                        stats["submitted"] += 1

    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="ctf_ad/config.yaml")
    ap.add_argument("--once", action="store_true", help="run a single round and exit")
    ap.add_argument(
        "--dry-run", action="store_true", help="force NullSubmitter regardless of config"
    )
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    acfg = cfg["attack"]

    logging.basicConfig(
        level=getattr(logging, acfg["logging"].get("level", "INFO")),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(acfg["logging"]["path"]),
            logging.StreamHandler(),
        ],
    )

    if not acfg.get("acknowledged_rules"):
        log.error(
            "attack.acknowledged_rules is false in config.yaml — read the "
            "event's rules on allowed targets, then set it true. Refusing to start."
        )
        return

    if "teams" in cfg and set(cfg["teams"]) == EXAMPLE_TEAMS:
        log.error(
            "`teams` in config.yaml still matches the placeholder example IPs "
            "— fill in real enemy hosts before running. Refusing to start."
        )
        return

    targets = expand_targets(cfg)
    if not targets:
        log.error("no targets configured (check config.yaml `teams` / `team_numbers`)")
        return

    exploit_mods = load_exploits()
    if not exploit_mods:
        log.warning("no exploits found in ctf_ad/attack/exploits — drop modules in there")

    flag_regex = compile_flag_regex(cfg["flag_regex"])
    flag_store = FlagStore(acfg["state"]["seen_flags_path"])
    sub_cfg = dict(acfg["submission"])
    if args.dry_run:
        sub_cfg["backend"] = "null"
    submitter = build_submitter(sub_cfg)

    flagid_cfg = acfg.get("flag_ids")
    flagid_cache = (
        FlagIdCache(flagid_cfg["url"], flagid_cfg.get("refresh_seconds", 60))
        if flagid_cfg and flagid_cfg.get("url")
        else None
    )

    interval = acfg.get("round_interval_seconds", 90)
    round_num = 0
    while True:
        round_num += 1
        if flagid_cache:
            flagid_cache.refresh()
        log.info(
            "=== round %d: %d exploit(s) x %d target(s) ===",
            round_num,
            len(exploit_mods),
            len(targets),
        )
        stats = run_round(
            targets,
            exploit_mods,
            acfg.get("timeout_seconds", 5),
            acfg.get("concurrency", 20),
            flag_regex,
            flag_store,
            submitter,
            flagid_cache,
        )
        log.info("round %d done: %s", round_num, stats)

        if args.once:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
