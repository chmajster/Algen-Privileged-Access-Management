from abc import ABC, abstractmethod


class VaultBackend(ABC):
    @abstractmethod
    def create_secret(self, name: str, secret_type: str, value: str | None, metadata: dict):
        raise NotImplementedError

    @abstractmethod
    def get_secret_value(self, secret_id: int, context: dict):
        raise NotImplementedError

    @abstractmethod
    def get_secret_metadata(self, secret_id: int):
        raise NotImplementedError

    @abstractmethod
    def update_secret(self, secret_id: int, value: str | None, metadata: dict):
        raise NotImplementedError

    @abstractmethod
    def rotate_secret(self, secret_id: int, rotation_context: dict):
        raise NotImplementedError

    @abstractmethod
    def disable_secret(self, secret_id: int):
        raise NotImplementedError

    @abstractmethod
    def list_versions(self, secret_id: int):
        raise NotImplementedError

    @abstractmethod
    def activate_version(self, secret_id: int, version_id: int):
        raise NotImplementedError

    @abstractmethod
    def revoke_version(self, secret_id: int, version_id: int):
        raise NotImplementedError
