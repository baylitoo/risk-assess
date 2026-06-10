"""Minimal policy-as-code (v0).

Doctrine rule 2: the authorization *model* ships in Phase 1 even though the
full OPA/Cedar engine ships in Phase 3. Per-agent YAML declares what an
agent may read, write, and is forbidden to do; the harness asks this engine
before every tool call. Every decision carries the matched rule so the
audit answer to "show me the rule that allowed this" is a file + a line,
not archaeology.

Policy file shape (one per agent, ``policies/<agent>.yaml``)::

    agent: vuln_operator
    can_read:
      - artifact.asset_inventory
      - mirror.nvd
      - mirror.kev
      - mirror.epss
    can_write:
      - artifact.vulnerability_findings
    cannot:                       # takes precedence over everything
      - read:document.raw.*
      - execute:ticket.create
      - execute:report.publish

Semantics:
- ``cannot`` entries are ``<action>:<resource-glob>`` (or a bare action) and
  always win.
- ``read``/``write`` are allowed only if the resource matches a glob in the
  corresponding allow list.
- Any other action (``execute``…) is **deny by default** unless explicitly
  granted via ``can_execute``.
- Unknown agent ⇒ deny everything.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

import yaml

_ALLOW_LIST_FOR_ACTION = {
    "read": "can_read",
    "write": "can_write",
    "execute": "can_execute",
}


class PolicyError(Exception):
    pass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    agent: str
    action: str
    resource: str
    rule: str          # the matched rule, or the reason for denial
    source_file: str   # which policy file decided this

    def __bool__(self) -> bool:  # allows `if engine.check(...):`
        return self.allowed


@dataclass(frozen=True)
class AgentPolicy:
    agent: str
    can_read: tuple[str, ...]
    can_write: tuple[str, ...]
    can_execute: tuple[str, ...]
    cannot: tuple[str, ...]
    source_file: str


def _load_policy_file(path: Path) -> AgentPolicy:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "agent" not in data:
        raise PolicyError(f"{path}: policy file must be a mapping with an 'agent' key")
    known = {"agent", "can_read", "can_write", "can_execute", "cannot"}
    unknown = set(data) - known
    if unknown:
        raise PolicyError(f"{path}: unknown policy keys {sorted(unknown)}")

    def _aslist(key: str) -> tuple[str, ...]:
        value = data.get(key) or []
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise PolicyError(f"{path}: '{key}' must be a list of strings")
        return tuple(value)

    return AgentPolicy(
        agent=str(data["agent"]),
        can_read=_aslist("can_read"),
        can_write=_aslist("can_write"),
        can_execute=_aslist("can_execute"),
        cannot=_aslist("cannot"),
        source_file=str(path),
    )


class PolicyEngine:
    def __init__(self, policies: dict[str, AgentPolicy]):
        self._policies = policies

    @classmethod
    def load_dir(cls, directory: str | Path) -> "PolicyEngine":
        directory = Path(directory)
        policies: dict[str, AgentPolicy] = {}
        for path in sorted(directory.glob("*.yaml")):
            policy = _load_policy_file(path)
            if policy.agent in policies:
                raise PolicyError(f"duplicate policy for agent {policy.agent!r}")
            policies[policy.agent] = policy
        if not policies:
            raise PolicyError(f"no policy files found in {directory}")
        return cls(policies)

    def check(self, agent: str, action: str, resource: str) -> Decision:
        policy = self._policies.get(agent)
        if policy is None:
            return Decision(False, agent, action, resource,
                            rule=f"no policy defined for agent {agent!r}",
                            source_file="")

        # 1. Explicit prohibitions always win.
        for entry in policy.cannot:
            entry_action, _, entry_resource = entry.partition(":")
            if entry_action != action:
                continue
            if entry_resource == "" or fnmatch(resource, entry_resource):
                return Decision(False, agent, action, resource,
                                rule=f"cannot: {entry}",
                                source_file=policy.source_file)

        # 2. Allow-list match for the action.
        allow_key = _ALLOW_LIST_FOR_ACTION.get(action)
        if allow_key is None:
            return Decision(False, agent, action, resource,
                            rule=f"unknown action {action!r} (deny by default)",
                            source_file=policy.source_file)
        for pattern in getattr(policy, allow_key):
            if fnmatch(resource, pattern):
                return Decision(True, agent, action, resource,
                                rule=f"{allow_key}: {pattern}",
                                source_file=policy.source_file)

        # 3. Default deny.
        return Decision(False, agent, action, resource,
                        rule=f"no matching {allow_key} entry (deny by default)",
                        source_file=policy.source_file)

    def enforce(self, agent: str, action: str, resource: str) -> Decision:
        """check() that raises — for harness call sites that must not proceed."""
        decision = self.check(agent, action, resource)
        if not decision.allowed:
            raise PolicyError(
                f"denied: {agent} {action} {resource} — {decision.rule}"
            )
        return decision
