from cement import Handler

from tqdm import tqdm
from arepo.base import Base
from typing import List, Dict

from sator.utils.misc import split_dict
from sator.core.adapters.nvd.adapter import CVEToDBAdapter
from sator.core.interfaces import HandlersInterface


from nvdutils.types.cve import CVE
from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.options import CVEOptions, ConfigurationOptions


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
        cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True),
                                 start=start, end=end)
        loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)

        self.database_handler.init_global_context()
        self.check_source_id()

        # process files in batch by year
        for year, cve_data in tqdm(loader.load(by_year=True, eager=False)):
            self.app.log.info(f"Loaded {len(cve_data)} records.")
            # split the cve_data in batches of 1000
            batches = split_dict(cve_data, 500)
            self.app.log.info(f"Processing {len(cve_data)} records for year {year}. Batches {len(batches)}.")
            multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)

            for batch in batches:
                multi_task_handler.add(cve_data=batch)

            multi_task_handler(func=self.process)

            # TODO: bottleneck here when running for man years, fix it
            processed_batches = multi_task_handler.results()

            # insert in order
            self.database_handler.bulk_insert_in_order(processed_batches)

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
