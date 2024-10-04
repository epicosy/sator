import json
import requests
import traceback
import pandas as pd


from cpeparser import CpeParser
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError


from sator.core.exc import SatorError
from sator.handlers.source import SourceHandler

from arepo.models.vcs.core import RepositoryModel, CommitModel
from arepo.models.common.scoring import CVSS3Model, CVSS2Model, SourceModel, CVSS3SourceModel, CVSS2SourceModel
from arepo.models.common.vulnerability import (VulnerabilityModel, ReferenceModel, VulnerabilityCWEModel,
                                               ReferenceTagModel)
from arepo.models.common.platform import ConfigurationModel, ConfigurationVulnerabilityModel, VendorModel, ProductModel


# TODO: Get metrics for version 3.0


class NVDAPIHandler(SourceHandler):
    class Meta:
        label = 'nvd_api'

    def __init__(self, **kw):
        super().__init__(**kw)

    def send_request_and_parse(self, base_url, params):
        # base_url = kwargs.get('base_url')
        # params = kwargs.get('params')   
        print("requesting vulnerabilities from pubStartDate " + str(params["pubStartDate"]) + " to pubEndDate " + str(
            params["pubEndDate"]))
        response = requests.get(base_url, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        start_index = params["startIndex"]
        if response.json():
            print("total result")
            print(response.json()['totalResults'])
            self.parse(response.json())
            if response.json()['totalResults'] > 2000 * (start_index + 1):
                params["startIndex"] = start_index + 1
                self.send_request_and_parse(base_url, params)

        # return response

    def run(self, start, end):

        # self.init_global_context()
        for year in range(start, end):
            start_date = datetime(year, 1, 1)  # Start from January 1st of the current year
            while start_date.year == year:
                end_date = start_date + timedelta(days=119)  # 119 days later
                # Ensure the end_date does not exceed the current year
                if end_date.year > year:
                    end_date = datetime(year, 12, 31)

                # Format the start and end dates
                pub_start_date = start_date.strftime('%Y-%m-%dT00:00:00.000')
                pub_end_date = end_date.strftime('%Y-%m-%dT23:59:59.999')

                # Prepare the URL and parameters for the request
                base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
                params = {
                    'pubStartDate': pub_start_date,
                    'pubEndDate': pub_end_date,
                    'startIndex': 0
                }

                # Add task for processing
                self.multi_task_handler.add(base_url=base_url, params=params)

                # Update start_date for the next loop iteration
                start_date = end_date + timedelta(days=1)  # Start the next period the day after the current end_date

        # Initialize global context and start processing tasks
        self.init_global_context()
        self.multi_task_handler(func=self.send_request_and_parse)

    def parse(self, json_file):

        try:
            vulnerabilities = json_file["vulnerabilities"]
            for cve_dict in vulnerabilities:
                cve = cve_dict["cve"]
                cve_id = self.get_cve(cve)
                try:
                    self._process_cve(cve_id=cve_id, cve=cve)
                except IntegrityError as ie:
                    # Use traceback.format_exc() to get the stack trace information as a string
                    self.app.log.warning("here")

                    self.app.log.warning(f"{ie}\n{traceback.format_exc()}")
        except Exception as e:
            # Similarly, log the general exception with traceback
            self.app.log.warning("here2")

            self.app.log.warning(f"General Error: {e}\n{traceback.format_exc()}")

    def _process_cve(self, cve_id: str, cve: dict):
        session = self.app.db_con.get_session(True)

        if not self.has_id(cve_id, 'vulns'):
            self.add_id(cve_id, 'vulns')

            session.add(VulnerabilityModel(id=cve_id, description=self.get_description(cve),
                                           assigner=self.get_assigner(cve),
                                           published_date=self.get_published_date(cve),
                                           last_modified_date=self.get_last_modified_date(cve),
                                           vulnStatus=self.get_status(cve)),
                        )

            session.commit()

            for cwe in self.get_cwe_ids(cve):
                if cwe in self.cwe_ids:
                    session.add(VulnerabilityCWEModel(vulnerability_id=cve_id, cwe_id=cwe))

            session.commit()

        for ref in self.get_references(cve):
            ref_digest = self.get_digest(ref['url'])
            # print("ref")
            # print(ref)

            if not self.has_id(ref_digest, 'refs'):
                self.add_id(ref_digest, 'refs')
                session.add(ReferenceModel(id=ref_digest, url=ref['url'], vulnerability_id=cve_id))
                session.commit()
                for tag in ref.get("tags", []):
                    # for tag in ref['tags']:
                    session.add(ReferenceTagModel(reference_id=ref_digest, tag_id=self.tag_ids[tag]))
                session.commit()

            if self.is_commit_reference(ref['url']):

                try:
                    normalized_commit = self.normalize_commit(ref['url'])
                    commit_digest = self.get_digest(normalized_commit.url)
                    repo_digest = self.get_digest(f"{normalized_commit.owner}/{normalized_commit.repo}")

                    if not self.has_id(repo_digest, 'repos'):
                        self.add_id(repo_digest, 'repos')
                        session.add(RepositoryModel(id=repo_digest, name=normalized_commit.repo,
                                                    owner=normalized_commit.owner))
                        session.commit()

                    if not self.has_id(commit_digest, 'commits'):
                        self.add_id(commit_digest, 'commits')
                        session.add(CommitModel(id=commit_digest, url=normalized_commit.url, sha=normalized_commit.sha,
                                                kind='|'.join(ref.get("tags", [])), vulnerability_id=cve_id,
                                                repository_id=repo_digest))
                        session.commit()

                except SatorError:
                    continue

            configurations = self.get_configs(cve)

            for raw_config in configurations:
                config = self.parse_config(raw_config)
                print(config["language"])
                config_digest = self.get_digest(config['cpe'])
                config_vuln = f"{config_digest}_{cve_id}"

                if not self.has_id(config_digest, 'configs'):
                    self.add_id(config_digest, 'configs')

                    vendor_digest = self.get_digest(config['vendor'])

                    if not self.has_id(vendor_digest, 'vendors'):
                        self.add_id(vendor_digest, 'vendors')
                        session.add(VendorModel(id=vendor_digest, name=config['vendor']))
                        session.commit()

                    product_digest = self.get_digest(f"{config['vendor']}:{config['product']}")

                    if not self.has_id(product_digest, 'products'):
                        self.add_id(product_digest, 'products')
                        session.add(ProductModel(id=product_digest, name=config['product'], vendor_id=vendor_digest,
                                                 product_type_id=8))
                        session.commit()
                    # TODO: the vulnerablity_id should not be part of the Configuration since configurations can occur
                    #  in multiple vulnerabilities
                    session.add(ConfigurationModel(id=config_digest, vulnerable=config['vulnerable'],
                                                   part=config['part'], version=config['version'],
                                                   update=config['update'], edition=config['edition'],
                                                   language=config['language'], sw_edition=config['sw_edition'],
                                                   target_sw=config['target_sw'], target_hw=config['target_hw'],
                                                   other=config['other'], vulnerability_id=cve_id,
                                                   vendor_id=vendor_digest, product_id=product_digest))
                    session.commit()
                    session.add(ConfigurationVulnerabilityModel(configuration_id=config_digest,
                                                                vulnerability_id=cve_id))
                    self.add_id(config_vuln, 'config_vuln')
                    session.commit()

                if not self.has_id(config_vuln, 'config_vuln'):
                    session.add(
                        ConfigurationVulnerabilityModel(configuration_id=config_digest, vulnerability_id=cve_id))
                    self.add_id(config_vuln, 'config_vuln')
                    session.commit()
        if cve["metrics"]:
            metrics = cve["metrics"]
            # miss v3.0
            # place for loop outside to check version first
            cvss_datas = []
            if "cvssMetricV31" in metrics:
                cvss_datas += metrics["cvssMetricV31"]
            if "cvssMetricV30" in metrics:
                cvss_datas += metrics["cvssMetricV30"]
            for cvss_data in cvss_datas:
                cvss_v3_id = self.get_digest(json.dumps(cvss_data))
                if not self.has_id(cvss_v3_id, 'cvss3'):
                    self.add_id(cvss_v3_id, 'cvss3')

                    cvss3_instance = CVSS3Model(
                        id=cvss_v3_id,
                        # vulnerability_id = cve_id,
                        # source=cvss_data['source'],
                        type=cvss_data['type'],
                        exploitabilityScore=cvss_data['exploitabilityScore'],
                        impactScore=cvss_data['impactScore'],
                        cvssData_version=cvss_data['cvssData']['version'],
                        cvssData_vectorString=cvss_data['cvssData']['vectorString'],
                        cvssData_attackVector=cvss_data['cvssData']['attackVector'],
                        cvssData_attackComplexity=cvss_data['cvssData']['attackComplexity'],
                        cvssData_privilegesRequired=cvss_data['cvssData']['privilegesRequired'],
                        cvssData_userInteraction=cvss_data['cvssData']['userInteraction'],
                        cvssData_scope=cvss_data['cvssData']['scope'],
                        cvssData_confidentialityImpact=cvss_data['cvssData']['confidentialityImpact'],
                        cvssData_integrityImpact=cvss_data['cvssData']['integrityImpact'],
                        cvssData_availabilityImpact=cvss_data['cvssData']['availabilityImpact'],
                        cvssData_baseScore=cvss_data['cvssData']['baseScore'],
                        cvssData_baseSeverity=cvss_data['cvssData']['baseSeverity']
                    )

                    session.add(cvss3_instance)
                    session.commit()

                    if cvss_data['source']:
                        source_name = cvss_data['source'].split("@")[0]
                        source_link = cvss_data['source']
                        source = SourceModel.query.filter_by(name=source_name, link=source_link).first()
                        if not source:
                            source = SourceModel(name=source_name, link=source_link)
                            session.add(source)
                            session.commit()

                        source_id = int(SourceModel.query.filter_by(name=source_name, link=source_link).first().id)
                        # print("source id")
                        # print(source_id)
                        # Create or update CVSS3Source link
                        cvss3_source = CVSS3SourceModel.query.filter_by(cvss=cvss_v3_id, source_id=source_id).first()
                        # print("cvss3_source")
                        # print(cvss3_source)
                        if cvss3_source is None:
                            cvss3_source = CVSS3SourceModel(cvss=cvss_v3_id, source_id=source_id)
                            session.add(cvss3_source)

                        session.commit()

            if "cvssMetricV2" in metrics:
                for cvss_data_v2 in metrics["cvssMetricV2"]:
                    cvss_v2_id = self.get_digest(json.dumps(cvss_data_v2))
                    if not self.has_id(cvss_v2_id, 'cvss2'):
                        self.add_id(cvss_v2_id, 'cvss2')
                        cvss2_instance = CVSS2Model(
                            id=cvss_v2_id,
                            # vulnerability_id = cve_id,
                            # source=cvss_data_v2['source'],
                            type=cvss_data_v2['type'],
                            cvssData_version=cvss_data_v2['cvssData']['version'],
                            cvssData_vectorString=cvss_data_v2['cvssData']['vectorString'],
                            cvssData_accessVector=cvss_data_v2['cvssData']['accessVector'],
                            cvssData_accessComplexity=cvss_data_v2['cvssData']['accessComplexity'],
                            cvssData_authentication=cvss_data_v2['cvssData']['authentication'],
                            cvssData_confidentialityImpact=cvss_data_v2['cvssData']['confidentialityImpact'],
                            cvssData_integrityImpact=cvss_data_v2['cvssData']['integrityImpact'],
                            cvssData_availabilityImpact=cvss_data_v2['cvssData']['availabilityImpact'],
                            cvssData_baseScore=cvss_data_v2['cvssData']['baseScore'],
                            baseSeverity=cvss_data_v2['baseSeverity'],
                            exploitabilityScore=cvss_data_v2['exploitabilityScore'],
                            impactScore=cvss_data_v2['impactScore'],
                            acInsufInfo=cvss_data_v2['acInsufInfo'],
                            obtainAllPrivilege=cvss_data_v2['obtainAllPrivilege'],
                            obtainUserPrivilege=cvss_data_v2['obtainUserPrivilege'],
                            obtainOtherPrivilege=cvss_data_v2['obtainOtherPrivilege'],
                            userInteractionRequired=cvss_data_v2['userInteractionRequired']
                        )
                        session.add(cvss2_instance)
                        session.commit()

                        if cvss_data_v2['source']:
                            source_name = cvss_data_v2['source'].split("@")[0]
                            source_link = cvss_data_v2['source']
                            source = SourceModel.query.filter_by(name=source_name, link=source_link).first()
                            if not source:
                                source = SourceModel(name=source_name, link=source_link)
                                session.add(source)
                                session.commit()

                            source_id = int(SourceModel.query.filter_by(name=source_name, link=source_link).first().id)

                            cvss2_source = CVSS2SourceModel.query.filter_by(cvss=cvss_v2_id,
                                                                            source_id=source_id).first()

                            if cvss2_source is None:
                                cvss2_source = CVSS2SourceModel(cvss=cvss_v2_id, source_id=source_id)
                                session.add(cvss2_source)

                            session.commit()

    @staticmethod
    def parse_config(config: dict):
        cpe = CpeParser()
        result = cpe.parser(config['criteria'])
        result['vulnerable'] = config.get('vulnerable', None)
        result['cpe'] = config['criteria']
        return result

    @staticmethod
    def get_cwe_ids(cve):
        # print("input")
        # print(cve)
        cwes = set()

        # for data in cve["cve"]["problemtype"]["problemtype_data"]:
        for cwe in cve["descriptions"]:
            if cwe["value"] and cwe['value'] not in ['NVD-CWE-Other', 'NVD-CWE-noinfo']:

                try:
                    cwe_id = int(cwe['value'].split('-')[-1])
                    cwes.add(cwe_id)
                except ValueError:
                    continue

        return cwes

    @staticmethod
    def get_cve(data: pd.DataFrame):
        return data["id"]

    @staticmethod
    def get_description(data):
        return data["descriptions"][0]["value"]

    @staticmethod
    def get_published_date(data):
        return data["published"]

    @staticmethod
    def get_last_modified_date(data):
        return data["lastModified"]

    @staticmethod
    def get_severity(data):
        if "cvssMetricV2" in data['metrics']:
            return data['metrics']['cvssMetricV2'][0]["baseSeverity"]
        else:
            return None

    @staticmethod
    def get_exploitability(data):
        if "cvssMetricV2" in data['metrics']:
            return data['metrics']['cvssMetricV2'][0]["exploitabilityScore"]
        return None

    @staticmethod
    def get_impact(data):

        if "cvssMetricV2" in data['metrics']:
            return data['metrics']['cvssMetricV2'][0]["impactScore"]
        return None

    @staticmethod
    def get_assigner(data):
        return data['sourceIdentifier']

    @staticmethod
    def get_references(data):
        refs = set()
        refs_list = []

        for ref in data["references"]:
            if ref['url'] not in refs:
                refs.add(ref['url'])
                refs_list.append(ref)

        return refs_list

    @staticmethod
    def get_configs(data):
        configs = []
        if 'configurations' not in data:
            return []
        for node in data['configurations'][0]['nodes']:
            for cpe in node['cpeMatch']:
                configs.append(cpe)

        return configs

    @staticmethod
    def get_status(data):
        if 'vulnStatus' not in data:
            return ""
        else:
            return data['vulnStatus']


def load(app):
    app.handler.register(NVDAPIHandler)
