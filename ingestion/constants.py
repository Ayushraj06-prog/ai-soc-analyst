"""Controlled normalized security event vocabulary and Windows mappings."""
EVENT_TYPES = frozenset({
    "auth_failure", "auth_success", "logoff", "account_created", "account_enabled",
    "account_disabled", "account_deleted", "account_lockout", "password_change",
    "privilege_assigned", "group_membership_change", "audit_log_cleared",
    "service_created", "network_connection", "unknown",
})

WINDOWS_EVENT_TYPES = {
    4624: "auth_success", 4625: "auth_failure", 4634: "logoff", 4647: "logoff",
    4648: "auth_success", 4672: "privilege_assigned", 4720: "account_created",
    4722: "account_enabled", 4724: "password_change", 4725: "account_disabled",
    4726: "account_deleted", 4732: "group_membership_change", 4740: "account_lockout",
    4768: "auth_success", 4769: "auth_success", 4771: "auth_failure",
    4776: "auth_success", 1102: "audit_log_cleared", 7045: "service_created",
}


def map_event_type(value: object) -> str:
    text = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "failed_login": "auth_failure", "login_failure": "auth_failure", "authentication_failure": "auth_failure",
        "successful_login": "auth_success", "login_success": "auth_success", "authentication_success": "auth_success",
        "network_connection_established": "network_connection", "privilege_escalation": "privilege_assigned",
        "password_changed": "password_change", "password_reset": "password_change",
        "account_locked": "account_lockout", "account_lockout_detected": "account_lockout",
        "user_created": "account_created", "user_enabled": "account_enabled",
        "user_disabled": "account_disabled", "user_deleted": "account_deleted",
        "group_membership_changed": "group_membership_change", "audit_cleared": "audit_log_cleared",
        "windows_service_created": "service_created",
    }
    candidate = aliases.get(text, text)
    if candidate == text:
        if any(term in text for term in ("failed login", "failed password", "authentication failure", "auth failed")):
            candidate = "auth_failure"
        elif any(term in text for term in ("successful login", "accepted password", "auth success", "logged in")):
            candidate = "auth_success"
        elif "logoff" in text or "logged out" in text:
            candidate = "logoff"
        elif "network" in text and "connection" in text:
            candidate = "network_connection"
    return candidate if candidate in EVENT_TYPES else "unknown"
