from cement import Handler
from typing import Dict, List

from arepo.base import Base
from arepo.models.common.vulnerability import VulnerabilityModel

from sator.core.adapters.osv.adapter import OSVToDBAdapter
from sator.utils.misc import split_dict
from sator.core.interfaces import HandlersInterface

from osvutils.types.osv import OSV
from osvutils.core.loader import OSVDataLoader
from osvutils.core.filters.loader import LoaderFilters
from osvutils.core.filters.database import DatabaseFilter
from osvutils.core.filters.affected_packages import AffectedPackagesFilter


class OSVHandler(HandlersInterface, Handler):
    class Meta:
        label = 'osv'

    def __init__(self, **kw):
        super().__init__(**kw)

        self._database_handler = None

    @property
    def database_handler(self):
        if self._database_handler is None:
            self._database_handler = self.app.handler.get('handlers', 'database', setup=True)

        return self._database_handler

    def run(self, **kwargs):
        self.database_handler.init_global_context()

        loader = OSVDataLoader(
            ecosystems=['GIT'],
            filters=LoaderFilters(
                database_filter=DatabaseFilter(
                    prefix_is_cve=True
                ),
                affected_packages_filter=AffectedPackagesFilter(
                    has_git_ranges=True
                )
            )
        )

        loader()

        for ecosystem, osv_data in loader:
            self.app.log.info(f"Loaded {len(osv_data)} OSV records for ecosystem {ecosystem}.")
            batches = split_dict(osv_data, 500)
            self.app.log.info(f"Batches {len(batches)}.")

            multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)

            for batch in batches:
                multi_task_handler.add(osv_data=batch)

            multi_task_handler(func=self.process)

            processed_batches = multi_task_handler.results()

            # insert in order
            self.database_handler.bulk_insert_in_order(processed_batches)

    def process(self, osv_data: Dict[str, OSV]) -> List[Dict[str, Base]]:
        res = []

        for cve_id, osv in osv_data.items():
            # TODO: find a better way to check if the record exists
            # We only want to insert new records for the CVEs that we have in the database
            if not self.database_handler.has_id(cve_id, VulnerabilityModel.__tablename__):
                continue

            osv_adapter = OSVToDBAdapter(osv, self.database_handler.tag_ids)
            res.extend(osv_adapter())

        return res
