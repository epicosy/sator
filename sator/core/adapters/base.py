from abc import abstractmethod
from collections import defaultdict
from typing import Dict, Union, Iterator

from arepo.mixins import EntityLoaderMixin


class BaseAdapter:
    def __init__(self, *args, **kwargs):
        self._ids = defaultdict(set)

    @abstractmethod
    def __call__(self, *args, **kwargs):
        raise NotImplementedError

    def get_ids(self) -> dict:
        return self._ids

    def yield_if_new(self, model_instance, table_name: str) -> Iterator[Dict[str, Union[None, object]]]:
        if isinstance(model_instance, EntityLoaderMixin):
            model_id = model_instance.id
        else:
            model_id = model_instance.composite_id

        if model_id not in self._ids[table_name]:
            self._ids[table_name].add(model_id)
            yield {model_id: model_instance}
