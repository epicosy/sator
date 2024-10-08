import threading

from cement import Handler
from typing import List, Dict
from sqlalchemy.exc import IntegrityError

from arepo.base import Base
from sator.core.interfaces import HandlersInterface
from arepo.models.common.scoring import CVSS2Model, CVSS3Model
from arepo.models.common.vulnerability import (VulnerabilityModel, VulnerabilityCWEModel, TagModel, ReferenceModel,
                                               ReferenceTagModel)
from arepo.models.common.weakness import CWEModel
from arepo.models.common.platform import ProductModel, VendorModel, ConfigurationModel, ConfigurationVulnerabilityModel
from arepo.models.vcs.core import RepositoryModel, CommitModel, CommitFileModel
from arepo.models.vcs.symbol import TopicModel


class DatabaseHandler(HandlersInterface, Handler):
    class Meta:
        label = 'database'

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db_ids = {}
        self.tag_ids = {}
        self.cwe_ids = []
        self.lock = threading.Lock()

    def init_global_context(self):
        # TODO: too complex, simplify
        self.app.log.info("Initializing global context...")
        session = self.app.db_con.get_session()
        # Setup available tags and CWE-IDs

        for tag in session.query(TagModel).all():
            self.tag_ids[tag.name] = tag.id

        for cwe in session.query(CWEModel).all():
            self.cwe_ids.append(cwe.id)

        # Setup IDs in database
        self.app.log.info("Loading vuln IDs...")
        self.db_ids[VulnerabilityModel.__tablename__] = set([cve.id for cve in session.query(VulnerabilityModel).all()])
        self.app.log.info("Loading vuln_cwe IDs...")
        self.db_ids[VulnerabilityCWEModel.__tablename__] = set([f"{vc.vulnerability_id}_{vc.cwe_id}" for vc in session.query(VulnerabilityCWEModel).all()])
        self.app.log.info("Loading ref IDs...")
        self.db_ids[ReferenceModel.__tablename__] = set([ref.id for ref in session.query(ReferenceModel).all()])
        self.app.log.info("Loading ref_tag IDs...")
        self.db_ids[ReferenceTagModel.__tablename__] = set([f"{rf.reference_id}_{rf.tag_id}" for rf in session.query(ReferenceTagModel).all()])
        self.app.log.info("Loading repo IDs...")
        self.db_ids[RepositoryModel.__tablename__] = set([repo.id for repo in session.query(RepositoryModel).all()])
        self.app.log.info("Loading commits IDs...")
        self.db_ids[CommitModel.__tablename__] = set([commit.id for commit in session.query(CommitModel).all()])
        self.app.log.info("Loading configs IDs...")
        self.db_ids[ConfigurationModel.__tablename__] = set([config.id for config in session.query(ConfigurationModel).all()])
        self.app.log.info("Loading config_vuln IDs...")
        self.db_ids[ConfigurationVulnerabilityModel.__tablename__] = set([f"{cv.configuration_id}_{cv.vulnerability_id}" for cv in
                                                                          session.query(ConfigurationVulnerabilityModel).all()])
        self.app.log.info("Loading products IDs...")
        self.db_ids[ProductModel.__tablename__] = set([product.id for product in session.query(ProductModel).all()])
        self.app.log.info("Loading vendors IDs...")
        self.db_ids[VendorModel.__tablename__] = set([vendor.id for vendor in session.query(VendorModel).all()])
        self.app.log.info("Loading commits files IDs...")
        self.db_ids[CommitFileModel.__tablename__] = set([commit_file.id for commit_file in session.query(CommitFileModel).all()])
        self.app.log.info("Loading CVSS2 IDs...")
        self.db_ids[CVSS2Model.__tablename__] = set([cvss.id for cvss in session.query(CVSS2Model).all()])
        self.app.log.info("Loading CVSS3 IDs...")
        self.db_ids[CVSS3Model.__tablename__] = set([cvss.id for cvss in session.query(CVSS3Model).all()])
        self.app.log.info("Loading topics IDs...")
        self.db_ids[TopicModel.__tablename__] = set([topic.id for topic in session.query(TopicModel).all()])

    def has_id(self, _id: str, _type: str) -> bool:
        return _id in self.db_ids[_type]

    def add_id(self, _id: str, _type: str):
        with self.lock:
            self.db_ids[_type].add(_id)

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
