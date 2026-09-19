import time


_sessions: dict[str, dict] = {}


def manage_session(
    client_id: str,
    token: str,
    expires_at: int,
    action: str = "create",
) -> dict | None:
    """Create, retrieve, or remove a client session."""

    if action == "create":
        _sessions[client_id] = {
            "token": token,
            "expires_at": expires_at,
        }
        return _sessions[client_id].copy()

    if action == "get":
        session = _sessions.get(client_id)

        if not session:
            return None

        if session["expires_at"] <= int(time.time()):
            _sessions.pop(client_id, None)
            return None

        return session.copy()

    if action == "remove":
        return _sessions.pop(client_id, None)

    raise ValueError(f"Unknown session action: {action}")