"""Simulation executor and deliberately unavailable real executor interfaces."""


class SimulationOnlyError(RuntimeError):
    pass


class RealExecutionNotImplemented(SimulationOnlyError):
    """Phase 9 has no real execution path by design."""


class FirewallExecutor:
    def execute(self, *_args, **_kwargs):
        raise RealExecutionNotImplemented("real firewall execution is not implemented in Phase 9")


class IdentityExecutor:
    def execute(self, *_args, **_kwargs):
        raise RealExecutionNotImplemented("real identity execution is not implemented in Phase 9")


class EndpointExecutor:
    def execute(self, *_args, **_kwargs):
        raise RealExecutionNotImplemented("real endpoint execution is not implemented in Phase 9")


class SimulationExecutor:
    """Return descriptions/results only; it never opens sockets or writes files."""
    def execute(self, action_type, target, parameters, evidence):
        if action_type == "collect_evidence":
            import hashlib
            import json
            event_ids = sorted(value for kind, value in evidence if kind == "EVENT")
            return {"mode": "simulation", "snapshot": {"event_ids": event_ids,
                    "canonical_hash": hashlib.sha256(json.dumps(event_ids, separators=(",", ":")).encode()).hexdigest()},
                    "files_written": False}
        return {"mode": "simulation", "action_type": action_type, "target": target,
                "parameters": parameters, "external_effect": False}
