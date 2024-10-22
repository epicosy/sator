import threading

from cement import Handler
from typing import List, Dict
from sqlalchemy.exc import IntegrityError

from arepo.base import Base
from sator.core.interfaces import HandlersInterface

from arepo.models.common.weakness import CWEModel
from arepo.models.common.scoring import CVSS2Model, CVSS3Model, CVSS2AssociationModel, CVSS3AssociationModel
from arepo.models.common.tag import TagModel, TagAssociationModel
from arepo.models.common.reference import ReferenceModel, ReferenceAssociationModel
from arepo.models.common.vulnerability import VulnerabilityModel, VulnerabilityCWEModel

from arepo.models.common.platform.configuration import ConfigurationModel, NodeModel
from arepo.models.common.platform.cpe import CPEModel, CPEMatchModel
from arepo.models.common.platform.product import ProductModel
from arepo.models.common.platform.vendor import VendorModel

from arepo.models.source import SourceModel
from arepo.models.vcs.symbol import TopicModel
from arepo.models.vcs.core.repository import RepositoryModel, RepositoryAssociationModel
from arepo.models.vcs.core.commit import CommitModel, CommitFileModel, CommitAssociationModel


class DatabaseHandler(HandlersInterface, Handler):
    class Meta:
        label = 'database'

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db_ids = {}
        self._tag_ids = {}
        self._cwe_ids = []
        self._source_ids = {}
        self.lock = threading.Lock()
        # TODO: update this
        self.dependency_tables = [
            [VulnerabilityModel.__tablename__, ReferenceModel.__tablename__, CVSS2Model.__tablename__,
             CVSS3Model.__tablename__, RepositoryModel.__tablename__, VendorModel.__tablename__],
            [CommitModel.__tablename__, ConfigurationModel.__tablename__, ProductModel.__tablename__,
             VulnerabilityCWEModel.__tablename__, ReferenceAssociationModel.__tablename__,
             TagAssociationModel.__tablename__, RepositoryAssociationModel.__tablename__,
             CVSS2AssociationModel.__tablename__, CVSS3AssociationModel.__tablename__],
            [CommitAssociationModel.__tablename__, CPEModel.__tablename__, NodeModel.__tablename__],
            [CPEMatchModel.__tablename__]
        ]

    @property
    def tag_ids(self):
        if not self._tag_ids:
            session = self.app.db_con.get_session()

            for tag in session.query(TagModel).all():
                self._tag_ids[tag.name] = tag.id

        return self._tag_ids

    @property
    def cwe_ids(self):
        if not self._cwe_ids:
            session = self.app.db_con.get_session()

            for cwe in session.query(CWEModel).all():
                self._cwe_ids.append(cwe.id)

        return self._cwe_ids

    @property
    def source_ids(self):
        if not self._source_ids:
            session = self.app.db_con.get_session()

            for source in session.query(SourceModel).all():
                self._source_ids[source.id] = source.email

        return self._source_ids

    def add_source_id(self, source_id: str, source_name: str, email: str):
        # TODO: temporary solution, should be handled by the ORM
        session = self.app.db_con.get_session()
        session.add(SourceModel(id=source_id, name=source_name, email=email))
        session.commit()

        self.source_ids[source_name] = source_id

    def get_cve_ids(self):
        if VulnerabilityModel.__tablename__ not in self.db_ids:
            session = self.app.db_con.get_session()

            self.db_ids[VulnerabilityModel.__tablename__] = set(
                [cve.id for cve in session.query(VulnerabilityModel).all()])

        return self.db_ids[VulnerabilityModel.__tablename__]

    def get_tag_ids(self):
        if not self.tag_ids:
            session = self.app.db_con.get_session()

            for tag in session.query(TagModel).all():
                self.tag_ids[tag.name] = tag.id

        return self.tag_ids

    def init_global_context(self):
        # TODO: Caching and Initialization should be done at the ORM-Level
        # TODO: Look into Identity Map Pattern for Efficient ID Handling
        self.app.log.info("Initializing global context...")
        session = self.app.db_con.get_session()

        for model in [TagModel, CWEModel, VulnerabilityModel, VulnerabilityCWEModel, ReferenceModel, RepositoryModel,
                      ReferenceAssociationModel, CommitModel, RepositoryAssociationModel, CommitAssociationModel,
                      TagAssociationModel, CVSS2Model, CVSS3Model, ProductModel, VendorModel, ConfigurationModel,
                      NodeModel, CPEModel, CPEMatchModel, TopicModel, CommitFileModel, CVSS2AssociationModel,
                      CVSS3AssociationModel]:
            self.app.log.info(f"Loading {model.__tablename__} primary IDs.")
            self.db_ids[model.__tablename__] = model.get_all_ids(session)

    def has_id(self, _id: str, _type: str) -> bool:
        return _id in self.db_ids[_type]

    def add_id(self, _id: str, _type: str):
        with self.lock:
            self.db_ids[_type].add(_id)

    def get_session(self):
        return self.app.db_con.get_session()

    def bulk_insert(self, models: List[Dict[str, Base]], tables: List[str]):
        """
            Insert models into the database. If the model is in the keys list (table names), it will be inserted.

            Args:
                models (List[Dict[str, Base]]): List of ORM models to be inserted
                tables (List[str]): List of tables to insert models into

            Returns:
                List of models that were not inserted
        """
        self.app.log.info(f"Inserting {len(models)} items.")
        session = self.app.db_con.get_session(scoped=True)
        # separate models that are to be inserted
        models_in_keys = []
        models_not_in_keys = []

        for model in models:
            for k, v in model.items():
                if v.__tablename__ in tables:
                    if not self.has_id(k, v.__tablename__):
                        self.add_id(k, v.__tablename__)
                        models_in_keys.append(v)
                else:
                    models_not_in_keys.append(model)

        try:
            session.bulk_save_objects(models_in_keys)
            session.flush()  # Detect errors here before committing
            session.commit()
            self.app.log.info(f"Inserted {len(models_in_keys)} items.")
            # return models that were not inserted
            return models_not_in_keys
        except IntegrityError as ie:
            self.app.log.warning(f"IntegrityError: {ie}")
            session.rollback()
        finally:
            session.close()

        # return empty list to avoid executing subsequent tasks, otherwise it will result in more integrity errors
        return []

    def bulk_insert_in_order(self, models_batches: List[List[Base]]):
        for tables in self.dependency_tables:
            self.app.log.info(f"Inserting {tables}.")
            multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)

            for models_batch in models_batches:
                multi_task_handler.add(models=models_batch, tables=tables)

            multi_task_handler(func=self.bulk_insert)
            models_batches = multi_task_handler.results()
