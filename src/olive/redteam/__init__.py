"""Olive's autonomous red-team engine (ADR-0015).

Authorized adversarial testing of Olive's OWN gateway, offline and deterministic.
It applies attack strategies (payload mutators) to seed malicious intents, runs
every variant through the REAL inspector pipeline, and reports which ones bypass.
Its only outputs are a campaign report and `known-miss` candidate cases - it has
no write path to any enforcement artifact (the anti-cheat guarantee, ADR-0015).
"""

from olive.redteam.engine import CampaignReport, run_campaign
from olive.redteam.strategies import SEEDS, STRATEGIES, AttackStrategy, SeedIntent

__all__ = [
    "SEEDS",
    "STRATEGIES",
    "AttackStrategy",
    "CampaignReport",
    "SeedIntent",
    "run_campaign",
]
