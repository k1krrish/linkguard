"""Write the synthetic demo captures to tests/fixtures/ (run from backend/: python scripts/generate_fixtures.py).

All captures are SYNTHETIC (built with Scapy, documentation address ranges, .test names).
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.services import fixtures  # noqa: E402

out = pathlib.Path(__file__).resolve().parents[1] / "tests" / "fixtures"
out.mkdir(parents=True, exist_ok=True)
for name in fixtures.FIXTURES:
    (out / f"{name}.pcap").write_bytes(fixtures.build_pcap(name))
(out / "tcp_refused.pcapng").write_bytes(fixtures.to_pcapng_bytes(fixtures.tcp_refused()))
(out / "empty.pcap").write_bytes(fixtures.empty_pcap())
(out / "truncated.pcap").write_bytes(fixtures.truncated_pcap())
(out / "malformed.pcap").write_bytes(fixtures.malformed_bytes())
print("wrote", len(list(out.glob("*"))), "files to", out)
