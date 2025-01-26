from cement import Handler

from tqdm import tqdm
from pathlib import Path
from arepo.base import Base
from typing import List, Dict

from sator.core.adapters.nvd.adapter import CVEToDBAdapter
from sator.core.interfaces import HandlersInterface


from nvdutils.models.cve import CVE
from nvdutils.loaders.json.yearly import JSONYearlyLoader
from nvdutils.data.profiles.zero_click import ZeroClickProfile


class NVDHandler(HandlersInterface, Handler):
    class Meta:
        label = 'nvd'

    def __init__(self, **kw):
        super().__init__(**kw)
        self._database_handler = None
        self.id = "nvd_id"
        self.name = "NVD"
        self.email = "nvd@nist.gov"

    @property
    def database_handler(self):
        if self._database_handler is None:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)

        return self._database_handler

    # TODO: this should be done somewhere else, maybe during population of the database
    def check_source_id(self):
        if self.id not in self.database_handler.source_ids:
            self.database_handler.add_source_id(self.id, self.name, self.email)

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
            cve_adapter = CVEToDBAdapter(cve, tag_ids=self.database_handler.tag_ids,
                                         cwe_ids=self.database_handler.cwe_ids,
                                         source_ids=self.database_handler.source_ids
                                         )
            res.extend(cve_adapter())

        return res


def load(app):
    app.handler.register(NVDHandler)
