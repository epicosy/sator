from tqdm import tqdm
from pathlib import Path
from arepo.base import Base
from typing import List, Dict

from sator.utils.misc import split_dict
from sator.handlers.source import SourceHandler
from sator.core.adapters.nvd.adapter import CVEToDBAdapter

from nvdutils.models.cve import CVE
from nvdutils.loaders.json.yearly import JSONYearlyLoader
from nvdutils.data.profiles.zero_click import ZeroClickProfile


class NVDHandler(SourceHandler):
    class Meta:
        label = 'nvd'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._database_handler = None

    @property
    def database_handler(self):
        if self._database_handler is None:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)

        return self._database_handler

    def run(self, start: int = 1988, end: int = 2025):
        loader = JSONYearlyLoader(start=start, end=end, profile=ZeroClickProfile)
        # self.database_handler.init_global_context()

        # process files in batch by year
        cve_dict = loader.load(Path("~/.nvdutils/nvd-json-data-feeds"), include_subdirectories=True)
        print(len(cve_dict))

        processed_batches = [self.process(cve_dict.entries) for year, cve_dict in cve_dict.entries.items()]

        print(processed_batches[:10])

        # self.database_handler.bulk_insert_in_order(processed_batches)

    def process(self, cve_data: Dict[str, CVE]) -> List[Dict[str, Base]]:
        res = []

        for cve_id, cve in cve_data.items():
            cve_adapter = CVEToDBAdapter(cve, self.database_handler.tag_ids, self.database_handler.cwe_ids)
            res.extend(cve_adapter())

        return res


def load(app):
    app.handler.register(NVDHandler)
