import json

import pandas as pd

from sqlalchemy.exc import IntegrityError
from tqdm import tqdm
from pathlib import Path
from flask.ctx import AppContext
from cpeparser import CpeParser

from sator.core.exc import SatorError
from sator.core.models import CVSS2, CVSS3, Vulnerability, db, Reference, VulnerabilityCWE, ReferenceTag, Repository, \
    Commit, Configuration, ConfigurationVulnerability, Vendor, Product
from sator.handlers.source import SourceHandler

# TODO: Get metrics for version 3.0


class NVDHandler(SourceHandler):
    class Meta:
        label = 'nvd'

    def __init__(self, **kw):
        super().__init__(**kw)

    def run(self):
        base_url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.zip'

        # download from source and extract
        for year in tqdm(range(1988, 2025, 1)):
            url = base_url.format(year=year)
            self.multi_task_handler.add(url=url, extract=True)

        self.multi_task_handler(func=self.download_file_from_url)
        results = self.multi_task_handler.results()
        del self.multi_task_handler

        self.init_global_context()

        # parse json files into a single dataframe
        for _, file_path in tqdm(results):
            self.multi_task_handler.add(file_path=file_path)

        self.multi_task_handler(func=self.parse)
        self.multi_task_handler.results()

    def parse(self, file_path: Path):
        self.app.log.info(f"Parsing {file_path}...")

        with file_path.open(mode='r') as f:
            cve_ids = json.load(f)["CVE_Items"]

            for cve in tqdm(cve_ids, desc=f"Parsing {file_path}"):
                cve_id = self.get_cve(cve)

                try:
                    self._process_cve(cve_id=cve_id, cve=cve)
                except IntegrityError as ie:
                    self.app.log.warning(f"{ie}")

    def _process_cve(self, cve_id: str, cve: dict):
        if not self.has_id(cve_id, 'vulns'):
            self.add_id(cve_id, 'vulns')

            db.session.add(Vulnerability(id=cve_id, description=self.get_description(cve),
                                         assigner=self.get_assigner(cve),
                                         published_date=self.get_published_date(cve),
                                         last_modified_date=self.get_last_modified_date(cve),
                                         vulnStatus = ""))
            db.session.commit()

            for cwe in self.get_cwe_ids(cve):
                if cwe in self.cwe_ids:
                    db.session.add(VulnerabilityCWE(vulnerability_id=cve_id, cwe_id=cwe))

            db.session.commit()

        for ref in self.get_references(cve):
            ref_digest = self.get_digest(ref['url'])

            if not self.has_id(ref_digest, 'refs'):
                self.add_id(ref_digest, 'refs')
                db.session.add(Reference(id=ref_digest, url=ref['url'], vulnerability_id=cve_id))
                db.session.commit()

                for tag in ref['tags']:
                    db.session.add(ReferenceTag(reference_id=ref_digest, tag_id=self.tag_ids[tag]))
                db.session.commit()

            if self.is_commit_reference(ref['url']):
                

                try:
                    normalized_commit = self.normalize_commit(ref['url'])
                    commit_digest = self.get_digest(normalized_commit.url)
                    repo_digest = self.get_digest(f"{normalized_commit.owner}/{normalized_commit.repo}")

                    if not self.has_id(repo_digest, 'repos'):
                        self.add_id(repo_digest, 'repos')
          
                        db.session.add(Repository(id=repo_digest, name=normalized_commit.repo,
                                                  owner=normalized_commit.owner))
                        db.session.commit()

                    if not self.has_id(commit_digest, 'commits'):
                        self.add_id(commit_digest, 'commits')
                        db.session.add(Commit(id=commit_digest, url=normalized_commit.url, sha=normalized_commit.sha,
                                              kind='|'.join(ref['tags']), vulnerability_id=cve_id,
                                              repository_id=repo_digest))
                        db.session.commit()

                except SatorError:
                    continue

            configurations = self.get_configs(cve)

            for raw_config in configurations:
                config = self.parse_config(raw_config)
                config_digest = self.get_digest(config['cpe'])
                config_vuln = f"{config_digest}_{cve_id}"

                if not self.has_id(config_digest, 'configs'):
                    self.add_id(config_digest, 'configs')

                    vendor_digest = self.get_digest(config['vendor'])

                    if not self.has_id(vendor_digest, 'vendors'):
                        self.add_id(vendor_digest, 'vendors')
                        db.session.add(Vendor(id=vendor_digest, name=config['vendor']))
                        db.session.commit()

                    product_digest = self.get_digest(f"{config['vendor']}:{config['product']}")

                    if not self.has_id(product_digest, 'products'):
                        self.add_id(product_digest, 'products')
                        db.session.add(Product(id=product_digest, name=config['product'], vendor_id=vendor_digest,
                                               product_type_id=8))
                        db.session.commit()
                    # TODO: the vulnerablity_id should not be part of the Configuration since configurations can occur
                    #  in multiple vulnerabilities
                    db.session.add(Configuration(id=config_digest, vulnerable=config['vulnerable'],
                                                 part=config['part'], version=config['version'],
                                                 update=config['update'], edition=config['edition'],
                                                 language=config['language'], sw_edition=config['sw_edition'],
                                                 target_sw=config['target_sw'], target_hw=config['target_hw'],
                                                 other=config['other'], vulnerability_id=cve_id,
                                                 vendor_id=vendor_digest, product_id=product_digest))
                    db.session.commit()
                    db.session.add(ConfigurationVulnerability(configuration_id=config_digest,
                                                              vulnerability_id=cve_id))
                    self.add_id(config_vuln, 'config_vuln')
                    db.session.commit()

                if not self.has_id(config_vuln, 'config_vuln'):
                    db.session.add(ConfigurationVulnerability(configuration_id=config_digest, vulnerability_id=cve_id))
                    self.add_id(config_vuln, 'config_vuln')
                    db.session.commit() 
        

        
        if cve["impact"]:

            metrics = cve["impact"]
            if "baseMetricV3" in metrics:
                base_metric_v3 = metrics["baseMetricV3"]
                cvss_v3 = base_metric_v3["cvssV3"]  # Access the 'cvssV3' dictionary directly
                cvss_v3_id = self.get_digest(json.dumps(cvss_v3))
                # Create a CVSS3 instance with the extracted data
                if not self.has_id(cvss_v3_id, 'cvss3'):
                    self.add_id(cvss_v3_id, 'cvss3')
                    cvss3_instance = CVSS3(
                        id = cvss_v3_id,
                        vulnerability_id=cve_id,
                        # The original code incorrectly accessed 'source' and 'type' which aren't in the 'cvssV3' structure
                        # Assuming 'source' and 'type' need to be handled differently or removed if not applicable
                        exploitabilityScore=base_metric_v3['exploitabilityScore'],
                        impactScore=base_metric_v3['impactScore'],
                        cvssData_version=cvss_v3['version'],
                        cvssData_vectorString=cvss_v3['vectorString'],
                        cvssData_attackVector=cvss_v3['attackVector'],
                        cvssData_attackComplexity=cvss_v3['attackComplexity'],
                        cvssData_privilegesRequired=cvss_v3['privilegesRequired'],
                        cvssData_userInteraction=cvss_v3['userInteraction'],
                        cvssData_scope=cvss_v3['scope'],
                        cvssData_confidentialityImpact=cvss_v3['confidentialityImpact'],
                        cvssData_integrityImpact=cvss_v3['integrityImpact'],
                        cvssData_availabilityImpact=cvss_v3['availabilityImpact'],
                        cvssData_baseScore=cvss_v3['baseScore'],
                        cvssData_baseSeverity=cvss_v3['baseSeverity']
                    )
                    db.session.add(cvss3_instance)
                    db.session.commit()



            if "baseMetricV2" in metrics:
                base_metric_v2 = metrics["baseMetricV2"]
                cvss_v2 = base_metric_v2["cvssV2"]  # Direct access to the "cvssV2" dictionary
                cvss_v2_id = self.get_digest(json.dumps(cvss_v2))
                if not self.has_id(cvss_v2_id, 'cvss2'):
                    self.add_id(cvss_v2_id, 'cvss2')
                    cvss2_instance = CVSS2(
                        id = cvss_v2_id,
                        vulnerability_id=cve_id,
                        cvssData_version=cvss_v2['version'],
                        cvssData_vectorString=cvss_v2['vectorString'],
                        cvssData_accessVector=cvss_v2['accessVector'],
                        cvssData_accessComplexity=cvss_v2['accessComplexity'],
                        cvssData_authentication=cvss_v2['authentication'],
                        cvssData_confidentialityImpact=cvss_v2['confidentialityImpact'],
                        cvssData_integrityImpact=cvss_v2['integrityImpact'],
                        cvssData_availabilityImpact=cvss_v2['availabilityImpact'],
                        cvssData_baseScore=cvss_v2['baseScore'],
                        baseSeverity=base_metric_v2['severity'],
                        exploitabilityScore=base_metric_v2['exploitabilityScore'],
                        impactScore=base_metric_v2['impactScore'],
                        acInsufInfo=base_metric_v2.get("acInsufInfo",False),
                        obtainAllPrivilege=base_metric_v2['obtainAllPrivilege'],
                        obtainUserPrivilege=base_metric_v2['obtainUserPrivilege'],
                        obtainOtherPrivilege=base_metric_v2['obtainOtherPrivilege'],
                        userInteractionRequired=base_metric_v2['userInteractionRequired']
                    )
                    db.session.add(cvss2_instance)
                    db.session.commit()


    @staticmethod
    def parse_config(config: dict):
        cpe = CpeParser()
        result = cpe.parser(config['cpe23Uri'])
        result['vulnerable'] = config.get('vulnerable', None)
        result['cpe'] = config['cpe23Uri']

        return result

    @staticmethod
    def get_cwe_ids(cve):
        cwes = set()

        for data in cve["cve"]["problemtype"]["problemtype_data"]:
            for cwe in data["description"]:
                if cwe["value"] and cwe['value'] not in ['NVD-CWE-Other', 'NVD-CWE-noinfo']:

                    try:
                        cwe_id = int(cwe['value'].split('-')[-1])
                        cwes.add(cwe_id)
                    except ValueError:
                        continue

        return cwes

    @staticmethod
    def get_cve(data: pd.DataFrame):
        return data["cve"]["CVE_data_meta"]["ID"]

    @staticmethod
    def get_description(data):
        return data["cve"]["description"]["description_data"][0]["value"]

    @staticmethod
    def get_published_date(data):
        return data["publishedDate"]

    @staticmethod
    def get_last_modified_date(data):
        return data["lastModifiedDate"]

    @staticmethod
    def get_severity(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["severity"]
        return None

    @staticmethod
    def get_exploitability(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["exploitabilityScore"]
        return None

    @staticmethod
    def get_impact(data):
        if data["impact"]:
            if "baseMetricV2" in data["impact"].keys():
                return data["impact"]["baseMetricV2"]["impactScore"]
        return None

    @staticmethod
    def get_assigner(data):
        return data["cve"]["CVE_data_meta"]["ASSIGNER"]

    @staticmethod
    def get_references(data):
        refs = set()
        refs_list = []

        for ref in data["cve"]["references"]["reference_data"]:
            if ref['url'] not in refs:
                refs.add(ref['url'])
                refs_list.append(ref)

        return refs_list

    @staticmethod
    def get_configs(data):
        configs = []

        for node in data['configurations']['nodes']:
            for cpe in node['cpe_match']:
                configs.append(cpe)

        return configs


def load(app):
    app.handler.register(NVDHandler)
