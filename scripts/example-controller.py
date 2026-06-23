#!/usr/bin/env python3
"""Example EXTERNAL intervention controller for a3s-observer.

This is the "外部去实现" (externally-implemented) path from docs/enforcement.md, made
concrete: the policy lives *here*, in userspace, in any language. It reads the observer's
NDJSON event stream and writes the enforcer's deny-list file; the kernel (a3s-observer-enforce
+ the cgroup/connect4 guard) enforces whatever this writes. Observe -> decide externally ->
enforce, fully decoupled.

    A3S_OBSERVER_JSON=1 a3s-observer-collector \
        | scripts/example-controller.py /etc/a3s/egress-deny.txt
    a3s-observer-enforce /sys/fs/cgroup/<agent> /etc/a3s/egress-deny.txt   # applies it

Policy in this example: an agent may only reach an allow-listed set of LLM providers; any
TLS connection (has SNI) to a non-approved provider has its peer IP added to the deny-list.
Adapt the policy to taste — that's the point of an external controller.
"""
import json
import sys

ALLOWED_PROVIDERS = {"Anthropic", "OpenAi", "Gemini"}


def main() -> int:
    deny_path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/a3s-egress-deny.txt"
    denied: set[str] = set()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        event = ev.get("event", {})
        call = event.get("LlmCall") or event.get("Egress")
        # Only gate TLS connections (those carry an SNI) to non-approved providers.
        if not call or not call.get("sni"):
            continue
        # provider is a string for known providers, a dict {"Other": "..."} otherwise, or null.
        prov = ev.get("provider")
        if isinstance(prov, str) and prov in ALLOWED_PROVIDERS:
            continue
        peer = call.get("peer")
        if not peer or peer == "0.0.0.0" or peer in denied:
            continue
        denied.add(peer)
        with open(deny_path, "w") as f:
            f.write("\n".join(sorted(denied)) + "\n")
        print(
            f"[controller] deny {peer} "
            f"(sni={call.get('sni')} provider={ev.get('provider')}) -> {deny_path}",
            file=sys.stderr,
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
