"""Rule registry and runner."""

import logging

from app.rules.base import Rule, RuleContext
from app.rules.live_rules import LiveDnsRule, LiveHttpRule, LiveTcpRule
from app.rules.pcap_rules import (
    CaptureNoMatchRule,
    DnsErrorRule,
    DnsUnansweredRule,
    EvidenceGapRule,
    TcpResetRule,
    TcpRetransmissionRule,
    TcpSynNoReplyRule,
)
from app.schemas.models import Finding, RuleInfo

log = logging.getLogger("linkguard.rules")

RULES: list[Rule] = [
    LiveDnsRule(),
    LiveTcpRule(),
    LiveHttpRule(),
    DnsUnansweredRule(),
    DnsErrorRule(),
    TcpResetRule(),
    TcpRetransmissionRule(),
    TcpSynNoReplyRule(),
    EvidenceGapRule(),
    CaptureNoMatchRule(),
]

_STATUS_ORDER = {"issue": 0, "inconclusive": 1, "ok": 2}
_SEVERITY_ORDER = {"medium": 0, "low": 1, "info": 2}


def run_rules(ctx: RuleContext, rules: list[Rule] | None = None) -> list[Finding]:
    """Evaluate every rule. A rule that raises becomes an inconclusive finding, not a crash."""
    findings: list[Finding] = []
    for rule in rules if rules is not None else RULES:
        try:
            findings.extend(rule.evaluate(ctx))
        except Exception as exc:  # noqa: BLE001
            log.exception("rule %s failed", rule.rule_id)
            findings.append(
                Finding(
                    rule_id=rule.rule_id, title=f"{rule.title} (rule could not be evaluated)", severity="low",
                    status="inconclusive", source=rule.source,  # type: ignore[arg-type]
                    observed=f"The rule raised {type(exc).__name__} while examining the evidence.",
                    interpretation="No conclusion can be drawn from this rule for this investigation.",
                    limitations=["This is a defect in the tool, not a finding about the network."],
                    next_test="Report the problem to the project team with the evidence that triggered it.",
                )
            )
    order = {r.rule_id: i for i, r in enumerate(rules if rules is not None else RULES)}
    findings.sort(key=lambda f: (_STATUS_ORDER[f.status], _SEVERITY_ORDER[f.severity], order.get(f.rule_id, 99)))
    return findings


def catalogue() -> list[RuleInfo]:
    return [r.info() for r in RULES]
