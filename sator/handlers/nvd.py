import json
from collections import defaultdict
from typing import List, Dict

from sqlalchemy.exc import IntegrityError
from tqdm import tqdm

from sator.handlers.source import SourceHandler

from nvdutils.types.cve import CVE
from nvdutils.types.configuration import Configuration
from nvdutils.types.cvss import CVSSType, CVSSv3, CVSSv2
from nvdutils.types.weakness import Weakness, WeaknessType
from nvdutils.types.reference import Reference, CommitReference
from nvdutils.types.options import CVEOptions, ConfigurationOptions

from nvdutils.core.loaders.json_loader import JSONFeedsLoader

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

        self.init_global_context()

        # process files in batch by year
        for year, cve_data in tqdm(loader.load(by_year=True, eager=False)):
            self.app.log.info(f"Loaded {len(cve_data)} records.")

            # split the cve_data in batches of 100
            batches = self.split_dict(cve_data, 500)
            self.app.log.info(f"Processing {len(cve_data)} records for {year}. Batches {len(batches)}.")

            for batch in batches:
                self.multi_task_handler.add(cve_data=batch)

                self.multi_task_handler(func=self.process)
                self.app.log.info(f"Inserted {len(batch)} records for year {year}.")

                for res in self.multi_task_handler.results():
                    session = self.app.db_con.get_session(scoped=True)

                    try:
                        for key, values in res.items():
                            session.bulk_save_objects(values)

                            if key in ['refs', 'repos', 'vendors', 'products', 'configs']:
                                session.flush()

                        session.commit()  # Commit after processing CVEs
                    except IntegrityError as ie:
                        session.rollback()  # Rollback in case of an error
                    finally:
                        session.close()  # Ensure session is closed after processing

                del self.multi_task_handler

    @staticmethod
    def split_dict(cve_data: Dict[str, CVE], batch_size: int) -> List[Dict[str, CVE]]:
        batches = []
        batch = {}
        count = 0

        for cve_id, cve in cve_data.items():
            if count == batch_size:
                batches.append(batch)
                batch = {}
                count = 0

            batch[cve_id] = cve
            count += 1

        if count > 0:
            batches.append(batch)

        return batches

    def process(self, cve_data: Dict[str, CVE]):
        results = defaultdict(list)

        for cve_id, cve in cve_data.items():
            results['vulns'].append(self.get_vulnerability(cve_id, cve))

            weaknesses = cve.get_weaknesses(
                weakness_type=WeaknessType.Primary,
                source="nvd@nist.gov"
            )

            results['cwes'].extend(self.get_cwe(cve_id, weaknesses))
            commits, references = cve.get_separated_references(vcs='github')
            tags, refs = self.get_references(cve_id, references)
            results['refs'].extend(refs)
            results['tags'].extend(tags)

            repo_models, commit_models = self.get_commits(cve_id, commits)

            results['repos'].extend(repo_models)
            results['commits'].extend(commit_models)

            # TODO: there must be a better way to handle this
            configs, vendors, products, rels = self.get_configurations(cve_id, cve.configurations)

            results['vendors'].extend(vendors)
            results['products'].extend(products)
            results['configs'].extend(configs)
            results['rels'].extend(rels)

            results['metrics'].extend(
                self.get_v2_metrics(
                    cve_id,
                    cve.get_metrics('cvssMetricV2', CVSSType.Primary)
                )
            )

            results['metrics'].extend(
                self.get_v3_metrics(
                    cve_id,
                    cve.get_metrics('cvssMetricV31', CVSSType.Primary)
                )
            )

            results['metrics'].extend(
                self.get_v3_metrics(
                    cve_id,
                    cve.get_metrics('cvssMetricV30', CVSSType.Primary)
                )
            )

        return results

    def get_vulnerability(self, cve_id: str, cve: CVE):
        if not self.has_id(cve_id, 'vulns'):
            self.add_id(cve_id, 'vulns')

            return VulnerabilityModel(
                id=cve_id,
                description=cve.get_eng_description().value,
                assigner=cve.source,
                severity=None, impact=None, exploitability=None,  # TODO: remove severity, impact, exploitability
                published_date=cve.published_date,
                last_modified_date=cve.last_modified_date
            )

    # TODO: database needs to accommodate both types of weaknesses
    def get_cwe(self, cve_id: str, weaknesses: List[Weakness]):
        vuln_cwe = []

        if not self.has_id(cve_id, 'vulns'):
            for weakness in weaknesses:
                for cwe_id in weakness.get_numeric_values():
                    if cwe_id in self.cwe_ids:
                        vuln_cwe.append(
                            VulnerabilityCWEModel(
                                vulnerability_id=cve_id,
                                cwe_id=cwe_id
                            )
                        )

        return vuln_cwe

    def get_references(self, cve_id: str, references: List[Reference]):
        refs = []
        tags = []

        for ref in references:
            ref_digest = self.get_digest(ref.url)

            if not self.has_id(ref_digest, 'refs'):
                self.add_id(ref_digest, 'refs')
                refs.append(
                    ReferenceModel(
                        id=ref_digest,
                        url=ref.url,
                        vulnerability_id=cve_id
                    )
                )

                for tag in ref.tags:
                    tags.append(
                        ReferenceTagModel(
                            reference_id=ref_digest,
                            tag_id=self.tag_ids[tag]
                        )
                    )

        return tags, refs

    def get_commits(self, cve_id: str, commits: List[CommitReference]):
        repo_models = []
        commit_models = []

        for commit in commits:
            commit_digest = self.get_digest(commit.processed_url)
            repo_digest = self.get_digest(f"{commit.owner}/{commit.repo}")

            if not self.has_id(repo_digest, 'repos'):
                self.add_id(repo_digest, 'repos')
                repo_models.append(
                    RepositoryModel(
                        id=repo_digest,
                        name=commit.repo,
                        owner=commit.owner
                    )
                )

            if not self.has_id(commit_digest, 'commits'):
                self.add_id(commit_digest, 'commits')
                commit_models.append(
                    CommitModel(
                        id=commit_digest,
                        url=commit.processed_url,
                        sha=commit.sha,
                        kind='|'.join(commit.tags),
                        vulnerability_id=cve_id,
                        repository_id=repo_digest
                    )
                )

        return repo_models, commit_models

    def get_configurations(self, cve_id: str, configurations: List[Configuration]):
        configs = []
        vendors = []
        products = []
        rels = []

        for config in configurations:
            # TODO: this needs a Node table
            for node in config.nodes:
                # TODO: this needs a CPE table
                for cpe_match in node.cpe_match:
                    config_vuln = f"{cpe_match.criteria_id}_{cve_id}"

                    if not self.has_id(cpe_match.criteria_id, 'configs'):
                        self.add_id(cpe_match.criteria_id, 'configs')

                        vendor_digest = self.get_digest(cpe_match.cpe.vendor)

                        if not self.has_id(vendor_digest, 'vendors'):
                            self.add_id(vendor_digest, 'vendors')
                            vendors.append(
                                VendorModel(
                                    id=vendor_digest,
                                    name=cpe_match.cpe.vendor
                                )
                            )

                        product_digest = self.get_digest(f"{cpe_match.cpe.vendor}:{cpe_match.cpe.product}")

                        if not self.has_id(product_digest, 'products'):
                            self.add_id(product_digest, 'products')
                            products.append(
                                ProductModel(
                                    id=product_digest,
                                    name=cpe_match.cpe.product,
                                    vendor_id=vendor_digest,
                                    product_type_id=8
                                )
                            )

                        # TODO: the vulnerability_id should not be part of the ConfigurationModel since configurations
                        # can occur in multiple vulnerabilities
                        # TODO: update ConfigurationModel to CPEModel
                        configs.append(
                            ConfigurationModel(
                                id=cpe_match.criteria_id,
                                vulnerable=cpe_match.vulnerable,
                                part=cpe_match.cpe.part,
                                version=cpe_match.cpe.version,
                                update=cpe_match.cpe.update,
                                edition=cpe_match.cpe.edition,
                                language=cpe_match.cpe.language,
                                sw_edition=cpe_match.cpe.sw_edition,
                                target_sw=cpe_match.cpe.target_sw,
                                target_hw=cpe_match.cpe.target_hw,
                                other=cpe_match.cpe.other,
                                vendor_id=vendor_digest,
                                product_id=product_digest
                            )
                        )

                        if not self.has_id(config_vuln, 'config_vuln'):
                            self.add_id(config_vuln, 'config_vuln')

                            rels.append(
                                ConfigurationVulnerabilityModel(
                                    configuration_id=cpe_match.criteria_id,
                                    vulnerability_id=cve_id
                                )
                            )

        return configs, vendors, products, rels

    def get_v2_metrics(self, cve_id: str, cvss_v2: List[CVSSv2]):
        metrics = []

        for cvss in cvss_v2:
            cvss_dict = cvss.to_dict()
            # TODO: cve_id should not be part of the id
            cvss_dict.update({"cve_id": cve_id})
            cvss_v2_id = self.get_digest(json.dumps(cvss_dict))

            if not self.has_id(cvss_v2_id, 'cvss2'):
                self.add_id(cvss_v2_id, 'cvss2')
                metrics.append(
                    CVSS2Model(
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
                )

                # TODO: add instance with cvss_v2_id and vulnerability_id to CVSS2Vulnerability table
        return metrics

    def get_v3_metrics(self, cve_id: str, cvss_v3: List[CVSSv3]):
        metrics = []

        for cvss in cvss_v3:
            cvss_dict = cvss.to_dict()
            # TODO: cve_id should not be part of the id
            cvss_dict.update({"cve_id": cve_id})
            cvss_v3_id = self.get_digest(json.dumps(cvss_dict))

            # Create a CVSS3 instance with the extracted data
            if not self.has_id(cvss_v3_id, 'cvss3'):
                self.add_id(cvss_v3_id, 'cvss3')
                # TODO: vulnerability_id should not be part of the CVSS3 table
                metrics.append(
                    CVSS3Model(
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
                )

                # TODO: add instance with cvss_v3_id and vulnerability_id to CVSS3Vulnerability table
        return metrics


def load(app):
    app.handler.register(NVDHandler)
