"""
Generate time-limited read SAS URLs for Azure Blob Storage (private containers).
Uses AZURE_STORAGE_ACCOUNT_NAME + AZURE_STORAGE_ACCOUNT_KEY from environment.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import quote, urlparse, unquote

from app.config import _get  # reuse internal getter; same module pattern as config


def _expiry_minutes() -> int:
    try:
        return max(5, min(24 * 60, int(_get("AZURE_SAS_EXPIRY_MINUTES", "60") or "60")))
    except ValueError:
        return 60


def azure_credentials_configured() -> bool:
    return bool(_get("AZURE_STORAGE_ACCOUNT_NAME", "").strip() and _get("AZURE_STORAGE_ACCOUNT_KEY", "").strip())


def parse_https_blob_url(url: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse https://{account}.blob.core.windows.net/{container}/{blob...}
    Returns (account_name, container_name, blob_name) or None.
    """
    u = (url or "").strip()
    if not u.startswith("https://"):
        return None
    parsed = urlparse(u)
    host = (parsed.netloc or "").lower()
    if ".blob.core.windows.net" not in host:
        return None
    account_name = host.split(".")[0]
    path = unquote((parsed.path or "").lstrip("/"))
    if "/" not in path:
        return None
    container_name, blob_name = path.split("/", 1)
    if not container_name or not blob_name:
        return None
    return account_name, container_name, blob_name


def resolve_blob_location(doc: Dict[str, Any]) -> Optional[Tuple[str, str, str]]:
    """
    From a screenshot document, return (account_name, container_name, blob_name) for SAS signing.
    Account name must match AZURE_STORAGE_ACCOUNT_NAME (same key in env).
    """
    env_account = (_get("AZURE_STORAGE_ACCOUNT_NAME", "") or "").strip()
    if not env_account:
        return None

    url = (doc.get("screenshot_url") or "").strip()
    if url.startswith("https://") and ".blob.core.windows.net" in url:
        parsed = parse_https_blob_url(url)
        if not parsed:
            return None
        acc, container, blob = parsed
        if acc.lower() != env_account.lower():
            # Wrong account for configured key
            return None
        return env_account, container, blob

    # Fallback: file_path under default container
    fp = (doc.get("file_path") or "").strip().lstrip("/")
    if not fp:
        return None
    container = (_get("AZURE_SCREENSHOT_CONTAINER", "screenshots") or "screenshots").strip()
    # If path starts with container name, strip it (e.g. screenshots/2024/a.png)
    if fp.lower().startswith(container.lower() + "/"):
        fp = fp[len(container) + 1 :]
    return env_account, container, fp


def build_read_sas_url(*, account_name: str, container_name: str, blob_name: str) -> Tuple[str, int]:
    """
    Returns (full_https_url_with_sas, expiry_minutes).
    """
    try:
        from azure.storage.blob import BlobSasPermissions, generate_blob_sas
    except ImportError as e:
        raise RuntimeError("azure-storage-blob is not installed") from e

    account_key = (_get("AZURE_STORAGE_ACCOUNT_KEY", "") or "").strip()
    if not account_key:
        raise RuntimeError("AZURE_STORAGE_ACCOUNT_KEY is not set")

    expiry_minutes = _expiry_minutes()
    expiry = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

    sas_token = generate_blob_sas(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name,
        account_key=account_key,
        permission=BlobSasPermissions(read=True),
        expiry=expiry,
    )

    # Encode path for HTTP; SAS is generated with the raw blob name the SDK expects
    path_in_url = quote(blob_name, safe="/")
    base = f"https://{account_name}.blob.core.windows.net/{container_name}/{path_in_url}"
    url = f"{base}?{sas_token}"
    return url, expiry_minutes
