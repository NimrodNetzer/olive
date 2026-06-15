"""The Agentic Command Center - a Textual TUI over `UIBroker` (ADR-0017).

Read-only by construction (see `broker.py`): every panel renders `UIEvent`s
streamed from `UIBroker`. The one write path is the attack-theater "Launch"
button, which publishes an announce-only `operator-request` object (SS5) - it
never itself runs a campaign or changes gateway state.
"""

from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import Button, Footer, Header, Label, ListItem, ListView, RichLog, Static

from olive.intelligence.bus import IncidentBus
from olive.ui.broker import UIBroker, UIEvent, make_operator_request

# Runtime departments that actually publish onto the incident bus (ADR-0014/0016).
DEPARTMENTS = ("defense", "remediation", "redteam")


class DepartmentPanel(Static):
    """A single department's last-seen activity. `activity` reflects the most
    recent `UIEvent.kind` seen with this `source_dept`."""

    activity: reactive[str] = reactive("idle")

    def __init__(self, dept: str) -> None:
        super().__init__()
        self.dept = dept

    def render(self) -> str:
        return f"[b]{self.dept.upper()}[/b]\nactivity: {self.activity}"


class GatewayNode(Static):
    """The central Olive gateway. `last_decision` reflects the most recent
    inline pipeline verdict (`UIEvent.kind == 'decision'`)."""

    last_decision: reactive[str] = reactive("-")

    def render(self) -> str:
        return f"[b]OLIVE[/b]\nAI Firewall Gateway\nlast decision: {self.last_decision}"


class CommandCenterApp(App):
    """The Agentic Command Center. Construct with a `UIBroker` (always) and
    optionally an open `IncidentBus` (to enable the attack-theater "Launch"
    button) and a corpus directory (default `evals/corpus`)."""

    CSS = """
    Screen { background: #0a0e14; }
    #top-row { height: 18; }
    DepartmentPanel { border: round #30363d; padding: 1; height: 5; }
    GatewayNode { border: round #30363d; padding: 1; height: 100%; width: 1fr; }
    #attack-theater { border: round #d29922; padding: 1; height: 100%; width: 40; }
    #corpus-list { height: 1fr; }
    #feed-container { height: 1fr; }
    #mitigation-feed { border: round #30363d; height: 100%; }
    """

    def __init__(
        self,
        broker: UIBroker,
        bus: IncidentBus | None = None,
        corpus_dir: str | Path | None = None,
    ) -> None:
        super().__init__()
        self._broker = broker
        self._bus = bus
        self._corpus_dir = Path(corpus_dir) if corpus_dir else None
        self._corpus_cases: list[str] = (
            sorted(p.stem for p in self._corpus_dir.glob("*.yaml"))
            if self._corpus_dir and self._corpus_dir.is_dir()
            else []
        )
        self._panels = {dept: DepartmentPanel(dept) for dept in DEPARTMENTS}
        self._gateway = GatewayNode()

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top-row"):
            with Vertical():
                yield from self._panels.values()
            yield self._gateway
            with Vertical(id="attack-theater"):
                yield Label("[b]ATTACK THEATER[/b] [yellow](SANDBOX - never live traffic)[/yellow]")
                yield ListView(*self._corpus_items(), id="corpus-list")
                yield Button("Launch (request)", id="launch", variant="warning")
        with VerticalScroll(id="feed-container"):
            yield RichLog(id="mitigation-feed", wrap=True, markup=True)
        yield Footer()

    def _corpus_items(self) -> list[ListItem]:
        if not self._corpus_cases:
            return [ListItem(Label("(no corpus dir configured)"))]
        return [ListItem(Label(case)) for case in self._corpus_cases]

    async def on_mount(self) -> None:
        self.run_worker(self._drain_broker(), exclusive=True)

    async def _drain_broker(self) -> None:
        log = self.query_one("#mitigation-feed", RichLog)
        async for event in self._broker.stream():
            self._apply(event, log)

    def _apply(self, event: UIEvent, log: RichLog) -> None:
        if event.kind == "decision":
            self._gateway.last_decision = f"{event.decision} ({event.rule})"
            log.write(f"[decision] {event.decision} rule={event.rule} {event.evidence or ''}")
            return
        if event.source_dept in self._panels:
            self._panels[event.source_dept].activity = event.kind
        log.write(
            f"[{event.kind}] dept={event.source_dept or '-'} {event.object_id or ''} "
            f"{event.evidence or ''}"
        )

    async def on_button_pressed(self, message: Button.Pressed) -> None:
        if message.button.id != "launch" or self._bus is None:
            return
        list_view = self.query_one("#corpus-list", ListView)
        index = list_view.index
        case = self._corpus_cases[index] if index is not None and self._corpus_cases else ""
        obj = make_operator_request(
            self._bus, action="run-campaign-request", evidence=f"corpus case: {case}"
        )
        await self._bus.publish(obj)
        log = self.query_one("#mitigation-feed", RichLog)
        log.write(f"[operator-request] run-campaign-request ({case}) published")
