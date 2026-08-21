"""
Secret storage helpers for ssh-mcp.

Backends (par priorité) :
1. Windows Credential Manager (win32cred) — natif Windows
2. keyring lib — cross-platform (Linux Secret Service, macOS Keychain)
3. Aucun — raise à l'usage ; servers.json reste utilisable avec clés SSH sans passphrase
"""

from __future__ import annotations

from typing import Any


def _detect_backend() -> tuple[Any | None, str]:
    try:
        import win32cred  # type: ignore[import]
        return win32cred, "win32cred"
    except ImportError:
        pass
    try:
        import keyring  # type: ignore[import]
        # Vérifie qu'un backend réel existe (pas le fail backend)
        if keyring.get_keyring().priority > 0:
            return keyring, "keyring"
    except Exception:
        pass
    return None, "none"


class SecretStore:
    def __init__(self, backend: Any | None = None, prefix: str = "ssh-mcp"):
        if backend is not None:
            self._backend = backend
            self._kind = "win32cred" if hasattr(backend, "CredWrite") else "keyring"
        else:
            self._backend, self._kind = _detect_backend()
        self._prefix = prefix

    def is_available(self) -> bool:
        return self._backend is not None

    @property
    def backend_name(self) -> str:
        return self._kind

    def _target(self, alias: str, field: str) -> str:
        return f"{self._prefix}:{alias}:{field}"

    def set_secret(self, alias: str, field: str, value: str) -> None:
        if not value:
            return
        if not self.is_available():
            raise RuntimeError(
                "Aucun store de secrets disponible "
                "(installe pywin32 sur Windows ou keyring sur Linux/macOS)."
            )
        if self._kind == "win32cred":
            self._backend.CredWrite(
                {
                    "Type": self._backend.CRED_TYPE_GENERIC,
                    "TargetName": self._target(alias, field),
                    "UserName": alias,
                    "CredentialBlob": value,
                    "Persist": self._backend.CRED_PERSIST_LOCAL_MACHINE,
                    "Comment": f"ssh-mcp secret for {alias}:{field}",
                },
                0,
            )
        else:  # keyring
            self._backend.set_password(self._prefix, f"{alias}:{field}", value)

    def get_secret(self, alias: str, field: str) -> str | None:
        if not self.is_available():
            return None
        try:
            if self._kind == "win32cred":
                cred = self._backend.CredRead(
                    Type=self._backend.CRED_TYPE_GENERIC,
                    TargetName=self._target(alias, field),
                )
                blob = cred.get("CredentialBlob")
                if blob is None:
                    return None
                if isinstance(blob, bytes):
                    return blob.decode("utf-16-le")
                return str(blob)
            else:  # keyring
                return self._backend.get_password(self._prefix, f"{alias}:{field}")
        except Exception:
            return None

    def delete_secret(self, alias: str, field: str) -> None:
        if not self.is_available():
            return
        try:
            if self._kind == "win32cred":
                self._backend.CredDelete(
                    TargetName=self._target(alias, field),
                    Type=self._backend.CRED_TYPE_GENERIC,
                    Flags=0,
                )
            else:  # keyring
                self._backend.delete_password(self._prefix, f"{alias}:{field}")
        except Exception:
            pass

    def has_secret(self, alias: str, field: str) -> bool:
        return self.get_secret(alias, field) is not None