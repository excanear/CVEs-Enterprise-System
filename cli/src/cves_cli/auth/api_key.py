"""API key authentication — store/retrieve cves_* format keys."""
from __future__ import annotations

import re

from cves_cli.auth.keyring import delete_secret, get_secret, set_secret

_KEY_PATTERN = re.compile(r"^cves_[A-Za-z0-9]{20,}$")


def is_valid_api_key(key: str) -> bool:
    return bool(_KEY_PATTERN.match(key))


def store_api_key(auth_name: str, key: str) -> None:
    if not is_valid_api_key(key):
        raise ValueError(f"Invalid API key format. Expected: cves_<base62>. Got: {key[:12]}...")
    set_secret(f"apikey:{auth_name}", key)


def get_api_key(auth_name: str) -> str | None:
    return get_secret(f"apikey:{auth_name}", env_var="CVES_API_KEY")


def delete_api_key(auth_name: str) -> None:
    delete_secret(f"apikey:{auth_name}")
