"""OS keyring integration with env-var and file fallbacks.

Priority for reading a secret:
  1. Environment variable (CVES_API_KEY, CVES_TOKEN_<name>)
  2. OS keyring (keyring.get_password)
  3. Credentials file (~/.config/cves/credentials) — chmod 600
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

_CRED_FILE = Path(os.environ.get("CVES_CONFIG_DIR", Path.home() / ".config" / "cves")) / "credentials"
_SERVICE = "cves-cli"


def _read_cred_file() -> dict[str, str]:
    if not _CRED_FILE.exists():
        return {}
    mode = _CRED_FILE.stat().st_mode
    # Warn if world-readable on POSIX
    if os.name == "posix" and mode & (stat.S_IRGRP | stat.S_IROTH):
        import warnings

        warnings.warn(
            f"{_CRED_FILE} is group/world-readable. Run: chmod 600 {_CRED_FILE}",
            stacklevel=3,
        )
    lines: dict[str, str] = {}
    for line in _CRED_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            lines[k.strip()] = v.strip()
    return lines


def _write_cred_file(key: str, value: str) -> None:
    _CRED_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_cred_file()
    existing[key] = value
    content = "\n".join(f"{k}={v}" for k, v in existing.items()) + "\n"
    _CRED_FILE.write_text(content, encoding="utf-8")
    if os.name == "posix":
        os.chmod(_CRED_FILE, 0o600)


def get_secret(name: str, env_var: str | None = None) -> str | None:
    """Retrieve a stored secret."""
    # 1. Env var override
    if env_var:
        val = os.environ.get(env_var)
        if val:
            return val

    # 2. OS keyring
    try:
        import keyring

        val = keyring.get_password(_SERVICE, name)
        if val:
            return val
    except Exception:
        pass

    # 3. Credential file fallback
    return _read_cred_file().get(name)


def set_secret(name: str, value: str) -> None:
    """Store a secret — keyring first, file as fallback."""
    try:
        import keyring

        keyring.set_password(_SERVICE, name, value)
        return
    except Exception:
        pass
    _write_cred_file(name, value)


def delete_secret(name: str) -> None:
    """Delete a stored secret from all backends."""
    try:
        import keyring

        keyring.delete_password(_SERVICE, name)
    except Exception:
        pass
    # Also remove from file
    existing = _read_cred_file()
    if name in existing:
        del existing[name]
        content = "\n".join(f"{k}={v}" for k, v in existing.items()) + "\n"
        _CRED_FILE.write_text(content, encoding="utf-8")
