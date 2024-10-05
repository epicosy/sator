import json
from typing import List

from sqlalchemy.exc import IntegrityError
from tqdm import tqdm

from sator.core.exc import SatorError
from sator.handlers.source import SourceHandler

from nvdutils.core.loaders.json_loader import JSONFeedsLoader
from nvdutils.types.configuration import Configuration
from nvdutils.types.reference import Reference, CommitReference
from nvdutils.types.weakness import Weakness, WeaknessType
from nvdutils.types.cve import CVE
from nvdutils.types.cvss import CVSSType, CVSSv3, CVSSv2
from nvdutils.types.options import CVEOptions, ConfigurationOptions


from arepo.models.vcs.core import RepositoryModel, CommitModel
from arepo.models.common.scoring import CVSS3Model, CVSS2Model
from arepo.models.common.vulnerability import (VulnerabilityModel, ReferenceModel, VulnerabilityCWEModel,
                                               ReferenceTagModel)
from arepo.models.common.platform import ConfigurationModel, ConfigurationVulnerabilityModel, VendorModel, ProductModel


class NVDHandler(SourceHandler):
    class Meta:
        label = 'nvd'

    def __init__(self, **kw):
        super().__init__(**kw)

    def run(self, start: int = 1988, end: int = 2025):
        cve_options = CVEOptions(config_options=ConfigurationOptions(has_config=True, has_vulnerable_products=True),
                                 start=start, end=end)
        loader = JSONFeedsLoader(data_path='~/.nvdutils/nvd-json-data-feeds', options=cve_options, verbose=True)
        # TODO. load only files by year
        loader.load()
        self.app.log.info(f"Loaded {len(loader.records)} records.")

        # TODO: Need to initialize the database connection somewhere
        # self.app.db_con.init(self.app.db_con.uri)
        self.init_global_context()

        # process files in batch by year
        for cve_id, cve in tqdm(loader.records.items()):
            self.multi_task_handler.add(cve_id=cve_id, cve=cve)

        self.multi_task_handler(func=self.insert)
        self.multi_task_handler.results()

    def insert(self, cve_id: str, cve: CVE):
        session = self.app.db_con.get_session(scoped=True)

        try:
            self.insert_vulnerability(cve_id, cve, session)

            weaknesses = cve.get_weaknesses(weakness_type=WeaknessType.Primary, source="nvd@nist.gov")
            self.insert_cwe(cve_id, weaknesses, session)

            commits, references = cve.get_separated_references(vcs='github')
            ids_to_insert = self.insert_references(cve_id, references, session)
            session.flush()

            for ref_id, tag_ids in ids_to_insert.items():
                for tag_id in tag_ids:
                    session.add(ReferenceTagModel(reference_id=ref_id, tag_id=tag_id))

            self.insert_commits(cve_id, commits, session)

            ids_to_insert = self.insert_configurations(cve_id, cve.configurations, session)
            session.flush()

            for config_vuln, cpe_id in ids_to_insert.items():
                if not self.has_id(config_vuln, 'config_vuln'):
                    session.add(ConfigurationVulnerabilityModel(configuration_id=cpe_id,
                                                                vulnerability_id=cve_id))
                    self.add_id(config_vuln, 'config_vuln')

            cvss2_metrics = cve.get_metrics('cvssMetricV2', CVSSType.Primary)
            self.insert_v2_metrics(cve_id, cvss2_metrics, session)

            cvss31_metrics = cve.get_metrics('cvssMetricV31', CVSSType.Primary)
            self.insert_v3_metrics(cve_id, cvss31_metrics, session)

            cvss30_metrics = cve.get_metrics('cvssMetricV30', CVSSType.Primary)
            self.insert_v3_metrics(cve_id, cvss30_metrics, session)

            session.commit()  # Commit after processing each CVE
        except IntegrityError as ie:
            self.app.log.warning(f"Integrity error for {cve_id}: {ie}")
            session.rollback()  # Rollback in case of an error
        finally:
            session.close()  # Ensure session is closed after processing

    def insert_vulnerability(self, cve_id: str, cve: CVE, session):
        if not self.has_id(cve_id, 'vulns'):
            # TODO: remove severity, impact, exploitability
            session.add(VulnerabilityModel(id=cve_id, description=cve.get_eng_description().value,
                                           assigner=cve.source, severity=None, impact=None, exploitability=None,
                                           published_date=cve.published_date, last_modified_date=cve.last_modified_date))

            self.add_id(cve_id, 'vulns')

    # TODO: database needs to be updated to accommodate both types of weaknesses
    def insert_cwe(self, cve_id: str, weaknesses: List[Weakness], session):
        if not self.has_id(cve_id, 'vulns'):
            for weakness in weaknesses:
                for cwe_id in weakness.get_numeric_values():
                    if cwe_id in self.cwe_ids:
                        session.add(VulnerabilityCWEModel(vulnerability_id=cve_id, cwe_id=cwe_id))

    def insert_references(self, cve_id: str, references: List[Reference], session):
        ids_to_insert = {}

        for ref in references:
            ref_digest = self.get_digest(ref.url)
            ids_to_insert[ref_digest] = []

            if not self.has_id(ref_digest, 'refs'):
                self.add_id(ref_digest, 'refs')
                session.add(ReferenceModel(id=ref_digest, url=ref.url, vulnerability_id=cve_id))

                for tag in ref.tags:
                    ids_to_insert[ref_digest].append(self.tag_ids[tag])

        return ids_to_insert

    def insert_commits(self, cve_id: str, commits: List[CommitReference], session):
        for commit in commits:
            commit_digest = self.get_digest(commit.processed_url)
            repo_digest = self.get_digest(f"{commit.owner}/{commit.repo}")

            if not self.has_id(repo_digest, 'repos'):
                self.add_id(repo_digest, 'repos')
                session.add(RepositoryModel(id=repo_digest, name=commit.repo, owner=commit.owner))

            if not self.has_id(commit_digest, 'commits'):
                self.add_id(commit_digest, 'commits')
                session.add(CommitModel(id=commit_digest, url=commit.processed_url, sha=commit.sha,
                                        kind='|'.join(commit.tags), vulnerability_id=cve_id,
                                        repository_id=repo_digest))

    def insert_configurations(self, cve_id: str, configurations: List[Configuration], session):
        ids_to_insert = {}

        for config in configurations:
            # TODO: this needs a Node table
            for node in config.nodes:
                # TODO: this needs a CPE table
                for cpe_match in node.cpe_match:
                    config_vuln = f"{cpe_match.criteria_id}_{cve_id}"

                    if not self.has_id(cpe_match.criteria_id, 'configs'):
                        self.add_id(cpe_match.criteria_id, 'configs')

                        # TODO: should be inserted in separate
                        vendor_digest = self.get_digest(cpe_match.cpe.vendor)

                        if not self.has_id(vendor_digest, 'vendors'):
                            self.add_id(vendor_digest, 'vendors')
                            session.add(VendorModel(id=vendor_digest, name=cpe_match.cpe.vendor))

                        # TODO: should be inserted in separate
                        product_digest = self.get_digest(f"{cpe_match.cpe.vendor}:{cpe_match.cpe.product}")

                        if not self.has_id(product_digest, 'products'):
                            self.add_id(product_digest, 'products')
                            session.add(ProductModel(id=product_digest, name=cpe_match.cpe.product,
                                                     vendor_id=vendor_digest, product_type_id=8))

                        # TODO: update to CPEModel
                        session.add(ConfigurationModel(id=cpe_match.criteria_id, vulnerable=cpe_match.vulnerable,
                                                       part=cpe_match.cpe.part, version=cpe_match.cpe.version,
                                                       update=cpe_match.cpe.update, edition=cpe_match.cpe.edition,
                                                       language=cpe_match.cpe.language,
                                                       sw_edition=cpe_match.cpe.sw_edition,
                                                       target_sw=cpe_match.cpe.target_sw,
                                                       target_hw=cpe_match.cpe.target_hw,
                                                       other=cpe_match.cpe.other,
                                                       vendor_id=vendor_digest, product_id=product_digest))

                        # Flush to ensure ConfigurationModel is written before continuing
                        session.flush()

                        ids_to_insert[config_vuln] = cpe_match.criteria_id

        return ids_to_insert

    def insert_v2_metrics(self, cve_id: str, cvss_v2: List[CVSSv2], session):
        for cvss in cvss_v2:
            cvss_dict = cvss.to_dict()
            # TODO: cve_id should not be part of the id
            cvss_dict.update({"cve_id": cve_id})
            cvss_v2_id = self.get_digest(json.dumps(cvss_dict))

            if not self.has_id(cvss_v2_id, 'cvss2'):
                self.add_id(cvss_v2_id, 'cvss2')
                cvss2_instance = CVSS2Model(
                    id=cvss_v2_id,
                    vulnerability_id=cve_id,
                    cvssData_version=cvss.version,
                    cvssData_vectorString=cvss.vector,
                    cvssData_accessVector=cvss.access_vector,
                    cvssData_accessComplexity=cvss.access_complexity,
                    cvssData_authentication=cvss.authentication,
                    cvssData_confidentialityImpact=cvss.impact.confidentiality,
                    cvssData_integrityImpact=cvss.impact.integrity,
                    cvssData_availabilityImpact=cvss.impact.availability,
                    cvssData_baseScore=cvss.scores.base,
                    baseSeverity=cvss.base_severity,
                    exploitabilityScore=cvss.scores.exploitability,
                    impactScore=cvss.scores.impact,
                    acInsufInfo=cvss.ac_insuf_info,
                    obtainAllPrivilege=cvss.obtain_all_privilege,
                    obtainUserPrivilege=cvss.obtain_user_privilege,
                    obtainOtherPrivilege=cvss.obtain_other_privilege,
                    userInteractionRequired=cvss.user_interaction_required
                )
                session.add(cvss2_instance)

                # TODO: add instance with cvss_v2_id and vulnerability_id to CVSS2Vulnerability table

    def insert_v3_metrics(self, cve_id: str, cvss_v3: List[CVSSv3], session):
        for cvss in cvss_v3:
            cvss_dict = cvss.to_dict()
            # TODO: cve_id should not be part of the id
            cvss_dict.update({"cve_id": cve_id})
            cvss_v3_id = self.get_digest(json.dumps(cvss_dict))

            # Create a CVSS3 instance with the extracted data
            if not self.has_id(cvss_v3_id, 'cvss3'):
                self.add_id(cvss_v3_id, 'cvss3')
                # TODO: vulnerability_id should not be part of the CVSS3 table
                cvss3_instance = CVSS3Model(
                    id=cvss_v3_id,
                    vulnerability_id=cve_id,
                    exploitabilityScore=cvss.scores.exploitability,
                    impactScore=cvss.scores.impact,
                    cvssData_version=cvss.version,
                    cvssData_vectorString=cvss.vector,
                    cvssData_attackVector=cvss.attack_vector,
                    cvssData_attackComplexity=cvss.attack_complexity,
                    cvssData_privilegesRequired=cvss.privileges_required,
                    cvssData_userInteraction=cvss.user_interaction,
                    cvssData_scope=cvss.scope,
                    cvssData_confidentialityImpact=cvss.impact.confidentiality,
                    cvssData_integrityImpact=cvss.impact.integrity,
                    cvssData_availabilityImpact=cvss.impact.availability,
                    cvssData_baseScore=cvss.scores.base,
                    cvssData_baseSeverity=cvss.base_severity
                )
                session.add(cvss3_instance)

                # TODO: add instance with cvss_v3_id and vulnerability_id to CVSS3Vulnerability table


def load(app):
    app.handler.register(NVDHandler)
