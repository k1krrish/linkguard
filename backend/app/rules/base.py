"""Rule engine building blocks.

A rule is a small class that:
  * declares its stable ``rule_id``, title and plain-language documentation,
  * reads normalized ``Evidence`` from a ``RuleContext``,
  * returns zero or more ``Finding`` objects.

Returning ``[]`` means "this rule does not apply to the evidence I was given".
"""

from dataclasses import dataclass
from typing import Optional

from app.schemas.models import CaptureSummary, Evidence, Finding, RuleInfo


@dataclass
class RuleContext:
    evidence: list[Evidence]
    capture: Optional[CaptureSummary] = None

    def of_kind(self, *kinds: str) -> list[Evidence]:
        return [e for e in self.evidence if e.kind in kinds]


class Rule:
    rule_id: str = ""
    title: str = ""
    source: str = "pcap"  # "pcap" or "live_check"
    description: str = ""
    triggers: str = ""
    does_not_prove: str = ""

    def evaluate(self, ctx: RuleContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    def info(self) -> RuleInfo:
        return RuleInfo(
            rule_id=self.rule_id,
            title=self.title,
            source=self.source,  # type: ignore[arg-type]
            description=self.description,
            triggers=self.triggers,
            does_not_prove=self.does_not_prove,
        )

    def finding(self, evidence: list[Evidence], **fields) -> Finding:
        """Build a Finding that carries the rule's identity and its evidence references."""
        refs = [e.id for e in evidence]
        packets: list[int] = []
        for e in evidence:
            packets.extend(p for p in e.packet_refs if p not in packets)
        return Finding(
            rule_id=self.rule_id,
            source=self.source,  # type: ignore[arg-type]
            evidence_refs=refs,
            packet_refs=packets[:50],
            simulated=any(e.simulated for e in evidence),
            **fields,
        )
