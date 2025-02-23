from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Optional

T = TypeVar("T")  # Generic Type for domain models


class StoragePersistencePort(ABC, Generic[T]):
    """Generic storage interface for saving and retrieving domain models."""

    @abstractmethod
    def save(self, entity: T, entity_id: str) -> bool:
        """
            Persist an entity in storage with a given ID.

            Args:
                entity: The entity to save.
                entity_id: The ID of the entity.

            Returns:
                True if the entity was saved successfully, False otherwise.
        """

        raise NotImplementedError

    @abstractmethod
    def load(self, entity: T, entity_id: str) -> Optional[T]:
        """
            Retrieve an entity by its ID.

            Args:
                entity: The type of the entity to load.
                entity_id: The ID of the entity.

            Returns:
                The entity if found, otherwise None.
        """
        raise NotImplementedError
