from abc import abstractmethod
from collections import defaultdict


class BaseAdapter:
    def __init__(self, *args, **kwargs):
        self._ids = defaultdict(set)

    @abstractmethod
    def __call__(self, *args, **kwargs):
        raise NotImplementedError

    def get_ids(self) -> dict:
        return self._ids
