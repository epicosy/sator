from pathlib import Path

from cement import Controller, ex


class Database(Controller):
    class Meta:
        label = 'database'

        stacked_on = 'base'
        stacked_type = 'nested'

        # text displayed at the top of --help output
        description = 'database controller'

        # text displayed at the bottom of --help output
        epilog = 'Usage: sator database'

    def __init__(self, **kw):
        super().__init__(**kw)

    @ex(
        help='Initialize the database'
    )
    def init(self):

        """Init sub-command."""
        tables_path = Path(__file__).parent.parent / 'config' / 'tables'
        from sator.core.models import init_db

        init_db(self.app.flask_configs.get('SQLALCHEMY_DATABASE_URI'), tables_path, self.app.log)

    @ex(
        help='Label with the root cause the vulnerabilities in a dataset',
        arguments=[(['-d', '--dataset'], {'help': 'Name of the dataset.', 'type': str, 'required': True}),
                   (['-ot', '--openai_token'], {'help': 'OpenAI API token.', 'type': str, 'required': True})]
    )
    def label(self):
        """Label sub-command."""
        from sator.core.models import set_db, DatasetVulnerability, Dataset
        set_db(self.app.flask_configs.get('SQLALCHEMY_DATABASE_URI'))

        dataset = Dataset.query.filter(Dataset.name == self.app.pargs.dataset).first()

        if not dataset:
            self.app.log.error(f"Dataset {self.app.pargs.dataset} not found")
            return

        results = DatasetVulnerability.query.filter(DatasetVulnerability.dataset_id == dataset.id).all()

        if not results:
            self.app.log.error(f"No vulnerabilities found for dataset {self.app.pargs.dataset}")
            return

        vuln_ids = [result.vulnerability_id for result in results]

        from sator.core.models import Vulnerability, Commit, CommitFile, VulnerabilityCWE, Weakness
        from ast import literal_eval
        openai_handler = self.app.handler.get('handlers', 'openai', setup=True)

        for vuln in Vulnerability.query.filter(Vulnerability.id.in_(vuln_ids)).all():
            self.app.log.info(f"Processing vulnerability {vuln.id}")
            # skip if in weaknesses table
            if Weakness.query.filter(Weakness.vulnerability_id == vuln.id).first():
                continue

            cwes = VulnerabilityCWE.query.filter(VulnerabilityCWE.vulnerability_id == vuln.id).all()

            if not cwes:
                self.app.log.error(f"Vulnerability {vuln.id} has no CWE associated")
                continue

            if len(cwes) > 1:
                self.app.log.error(f"Vulnerability {vuln.id} has more than one CWE associated")
                continue

            cwe_id = cwes[0].cwe_id

            patches = Commit.query.filter(Commit.vulnerability_id == vuln.id).filter(Commit.kind != 'parent').all()

            if not patches:
                self.app.log.error(f"Vulnerability {vuln.id} has no patches associated")
                continue

            if len(patches) > 1:
                self.app.log.error(f"Vulnerability {vuln.id} has more than one patch associated")
                continue

            patch_files = CommitFile.query.filter(CommitFile.commit_id == patches[0].id).all()

            if not patch_files:
                self.app.log.error(f"Vulnerability {vuln.id} has no patch file associated")
                continue

            if len(patch_files) > 1:
                self.app.log.error(f"Vulnerability {vuln.id} has more than one patch file associated")
                continue

            patch_diff = patch_files[0].patch

            if not patch_diff:
                self.app.log.error(f"Vulnerability {vuln.id} has no patch diff associated")
                continue

            if len(patch_diff) > 1000:
                self.app.log.error(f"Vulnerability {vuln.id} has a patch diff larger than 1000 characters")
                continue

            completion = openai_handler.label_diff(patch_diff, f"CWE-{cwe_id}")

            if not completion:
                self.app.log.error(f"Vulnerability {vuln.id} has no completion")
                continue

            # check if the completion is a tuple

            try:
                improper_state = literal_eval(completion.completion)

                if not isinstance(improper_state, tuple):
                    self.app.log.error(f"Vulnerability {vuln.id} completion is not a tuple")
                    continue

                weakness = Weakness(completion_id=completion.id, vulnerability_id=vuln.id, tuple=completion.completion)
                weakness.save()

            except ValueError as e:
                self.app.log.error(f"Vulnerability {vuln.id} completion is not a tuple")
                continue
