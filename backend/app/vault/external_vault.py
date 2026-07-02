from .local_encrypted import LocalEncryptedBackend


class ExternalVaultBackend(LocalEncryptedBackend):
    """Mock external vault backend.

    It stores ciphertext locally for demo/testing, while preserving the same
    interface expected from a future HashiCorp Vault or KMS integration.
    """

    def create_secret(self, name: str, secret_type: str, value: str | None, metadata: dict):
        secret = super().create_secret(name, secret_type, value, metadata)
        secret.backend_type = "external_vault"
        secret.external_ref = metadata.get("external_ref") or f"mock://vault/{secret.id}"
        return secret
