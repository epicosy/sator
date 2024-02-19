import time
from typing import Union

import openai

from tqdm import tqdm

from sator.core.models import Repository, ProductType, RepositoryProductType, db, Completion
from sator.handlers.source import SourceHandler
from sator.core.openai.prompts import get_repository_software_type, label_patch_root_cause
from sator.core.openai.utils import extract_dictionary
from github.GithubException import UnknownObjectException


class OpenAIHandler(SourceHandler):
    class Meta:
        label = 'openai'

    def __init__(self, **kw):
        super().__init__(**kw)
        self.timed_out = False

    def _setup(self, app):
        super(OpenAIHandler, self)._setup(app)
        self.app.log.info(f"Setting up OpenAIHandler...")
        openai.api_key = self.app.pargs.openai_token

        try:
            available_models = [m['id'] for m in openai.Model.list()['data']]
            # self.app.log.info(f"Available models: {available_models}")
        except openai.error.OpenAIError as e:
            self.app.log.error(f"Error while connecting to OpenAI API: {e}")
            exit(1)

    def label_diff(self, diff: str, cwe_id: str) -> Union[Completion, None]:
        try:
            messages = label_patch_root_cause(diff=diff, cwe_id=cwe_id)
            completion = openai.ChatCompletion.create(model='gpt-3.5-turbo', max_tokens=100, n=1, messages=messages)
            # TODO: should we keep the completions for later access or save in our database and delete them from openai?
            completion_model = Completion(id=completion.id, model=completion.model, object=completion.object,
                                          created=completion.created, prompt=str(messages),
                                          completion=completion.choices[0].message['content'],
                                          finish_reason=completion.choices[0]['finish_reason'],
                                          prompt_tokens=completion.usage["prompt_tokens"],
                                          total_tokens=completion.usage["total_tokens"],
                                          completion_tokens=completion.usage["completion_tokens"])
            completion_model.save()
            time.sleep(1.5)
            return completion_model
        except openai.error.RateLimitError as e:
            self.app.log.error(f"Rate limit error: {e}")

            if self.timed_out:
                self.app.log.warning(f"API exhausted. Terminating.")
                exit(1)

            self.timed_out = True
            time.sleep(1.5)

        except openai.error.OpenAIError as e:
            self.app.log.error(f"Error while generating text: {e}")
        except ValueError as e:
            self.app.log.error(f"Error while generating text: {e}")

        return None


    def _generate_software_type(self, name: str, description: str, read_me: str) -> Union[str, None]:
        try:
            prompt = get_repository_software_type(name=name, description=description, read_me=read_me, prompt=True)
            # TODO: change api calls depending on the model
            completion = openai.Completion.create(model=self.app.pargs.model, prompt=prompt, n=1, max_tokens=50)
            self.app.log.info(completion.choices[0].text)
            result = extract_dictionary(completion.choices[0].text)
            self.app.log.info(result)
            time.sleep(1.5)

            if result:
                for column in ['software_type', 'Software Type', 'Software_Type', 'software type', 'Software type',
                               'Software_type', 'software Type', 'software_Type']:
                    if column in result:
                        return result[column]

            return None

        except openai.error.RateLimitError as e:
            self.app.log.error(f"Rate limit error: {e}")

            if self.timed_out:
                self.app.log.warning(f"API exhausted. Terminating.")
                exit(1)

            self.timed_out = True
            time.sleep(1.5)

        except openai.error.OpenAIError as e:
            self.app.log.error(f"Error while generating text: {e}")

        return None

    def generate(self):

        with self.app.flask_app.app_context():
            software_types_mapping = {pt.name: pt.id for pt in ProductType.query.all()}
            skip = [rpt.repository_id for rpt in RepositoryProductType.query.all()]

            for repo_model in tqdm(Repository.query.filter_by(available=True).filter(~Repository.id.in_(skip)).all()):
                repo = self.github_handler.get_repo(repo_model.owner, project=repo_model.name)
                self.app.log.info(f"Finding software type for {repo_model.owner}/{repo_model.name}...")

                if not repo:
                    self.app.log.warning(f"Skipping repository {repo_model.owner}/{repo_model.name}")
                    continue

                try:
                    read_me = repo.get_readme().decoded_content.decode('utf-8')
                except UnknownObjectException:
                    self.app.log.warning(f"Repository {repo_model.owner}/{repo_model.name} has no README file.")
                    topics = repo.get_topics()

                    if topics:
                        read_me = ", ".join(repo.get_topics())
                        self.app.log.info(f"Using topics {topics} as README.")
                    else:
                        read_me = ""

                try:
                    software_type = self._generate_software_type(repo_model.owner, repo_model.name, read_me)
                except ValueError:
                    continue

                product_type_id = software_types_mapping[software_type] if software_type in software_types_mapping else 8
                repo_sw_type = RepositoryProductType(repository_id=repo_model.id, product_type_id=product_type_id)

                db.session.add(repo_sw_type)
                db.session.commit()
