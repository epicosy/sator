import pandas as pd

from sator.core.deltas.parser import DiffParser

from arepo.models.vcs.core import CommitModel
from arepo.models.vcs.diff import DiffBlockModel, ChangeModel
from arepo.utils.misc import generate_id
from sqlalchemy.exc import IntegrityError

from typing import Union

from tqdm import tqdm
from typing import List
from github import BadCredentialsException

from cement import Handler
from sator.core.interfaces import HandlersInterface
from sator.handlers.github import GithubHandler
from sator.handlers.multi_task import MultiTaskHandler


class DiffParserHandler(HandlersInterface, Handler):
    """
        Collector plugin
    """

    class Meta:
        label = "parser"

    def __init__(self, **kw):
        super().__init__(**kw)
        self._multi_task_handler: MultiTaskHandler = None
        self._github_handler: GithubHandler = None

    @property
    def multi_task_handler(self):
        if not self._multi_task_handler:
            self._multi_task_handler = self.app.handler.get('handlers', 'multi_task', setup=True)
        return self._multi_task_handler

    @multi_task_handler.deleter
    def multi_task_handler(self):
        self._multi_task_handler = None

    @property
    def github_handler(self):
        if not self._github_handler:
            self._github_handler = self.app.handler.get('handlers', 'github', setup=True)
        return self._github_handler

    @github_handler.deleter
    def github_handler(self):
        self._github_handler = None
        
    def run(self, commits: List[CommitModel]) -> Union[pd.DataFrame, None]:
        """
            runs the plugin
        """

        self.app.log.info(f"Creating {len(commits)} tasks.")

        for commit in tqdm(commits):
            self.multi_task_handler.add(commit=commit)

        self.multi_task_handler(func=self.parse_diffs)
        diff_ids = self.multi_task_handler.results(expand=True)

        if diff_ids:
            df_data = []
            session = self.app.db_con.get_session()

            for df_id in diff_ids:
                df = session.query(DiffBlockModel).filter(DiffBlockModel.id == df_id).first()
                df_changes = session.query(ChangeModel).filter(ChangeModel.diff_block_id == df_id).all()
                for c in df_changes:
                    row = {'diff_id': df_id, 'order': df.order, 'a_path': df.a_path, 'commit_file_id': df.commit_file_id,
                           'change_id': c.id, 'line': c.line, 'content': c.content, 'start_col': c.start_col,
                           'end_col': c.end_col, 'type': c.type}

                    df_data.append(row)

            df = pd.DataFrame.from_dict(df_data)

            return df

        return None

    def parse_diffs(self, commit: CommitModel):
        if len(commit.parents) == 0:
            self.app.log.warning(f"[{commit.vulnerability_id}] Commit {commit.sha} has no parent. Skipping.")
            return None

        if len(commit.parents) > 1:
            self.app.log.warning(f"[{commit.vulnerability_id}] Commit {commit.sha} has more than one parent. Skipping.")
            return None

        try:
            repo = self.github_handler.get_repo(owner=commit.repository.owner, project=commit.repository.name)
        except BadCredentialsException as bde:
            self.app.log.error(f"could not get repo {commit.repository.name}: {bde}")
            return None

        fix_commit = self.github_handler.get_commit(repo, commit_sha=commit.sha)
        vuln_commit = self.github_handler.get_commit(repo, commit_sha=commit.parents[0].sha)

        if fix_commit and vuln_commit:
            # Get the diff string using GitHub API
            diff_text = self.github_handler.get_diff(commit=fix_commit)

            if not diff_text:
                self.app.log.warning(f"[{commit.vulnerability_id}] Commit {commit.sha} has no diff. Skipping.")
                return None

            if len(diff_text) > 1000:
                self.app.log.warning(f"[{commit.vulnerability_id}] Commit {commit.sha} has a large diff. Skipping.")
                return None

            self.app.log.warning(diff_text)

            # Parse the diff string and collect diff information
            # TODO: find how to pass the extensions (config is definitely not good for this purpose)
            diff_blocks = self.github_handler.get_blocks_from_diff(diff_text=diff_text)
            self.app.log.warning(diff_blocks)
            a_files = {}
            b_files = {}

            db_diff_blocks = {db.id: db for cf in commit.files for db in cf.diff_blocks}

            if len(diff_blocks) == len(db_diff_blocks):
                self.app.log.info(f"[{commit.vulnerability_id}] Commit {commit.sha} has already been parsed. Skipping.")
                return db_diff_blocks.keys()

            id_path = f"{repo.owner.name}_{repo.name}_{fix_commit.sha}"

            for diff_block in diff_blocks:
                for cf in commit.files:
                    if cf.filename == diff_block.b_path:
                        commit_file = cf
                        # TODO: id generation should be handled by the DiffBlockModel
                        diff_block_id = generate_id(f"{id_path}_{cf.filename}_{diff_block.start}")
                        break
                else:
                    self.app.log.warning(f"[{commit.vulnerability_id}] Commit {commit.sha} has no file "
                                         f"{diff_block.a_path}. Skipping.")
                    continue

                if diff_block_id in db_diff_blocks:
                    self.app.log.info(f"[{commit.vulnerability_id}] Diff Block {diff_block_id} has already been parsed. "
                                      f"Skipping.")
                    continue

                # Get the contents of the two files using GitHub API
                if diff_block.a_path in a_files:
                    a_str = a_files[diff_block.a_path]
                else:
                    a_str, _ = self.github_handler.get_file_from_commit(commit=vuln_commit,
                                                                        repo_file_path=diff_block.a_path)
                    a_files[diff_block.a_path] = a_str

                if diff_block.b_path in b_files:
                    b_str = b_files[diff_block.b_path]
                else:
                    b_str, _ = self.github_handler.get_file_from_commit(commit=fix_commit,
                                                                        repo_file_path=diff_block.b_path)
                    b_files[diff_block.b_path] = b_str

                diff_block_model = DiffBlockModel(id=diff_block_id, order=diff_block.start, a_path=diff_block.a_path,
                                                  commit_file_id=commit_file.id)
                session = self.app.db_con.get_session()

                try:
                    # Perform pretty-printing and diff comparison
                    labeler = DiffParser(a_str=a_str, b_str=b_str)
                                          # , extension=Path(diff_block.a_path).suffix[1:])

                    changes = []

                    for el in labeler():
                        if el['sline'] != el['eline']:
                            # TODO: to be implemented changes covering multiple lines
                            self.app.log.warning(f"[{commit.vulnerability_id}] Skipped {el['type']} change with "
                                                 f"multiple lines.")
                            continue
                        # TODO: id generation should be handled by the ChangeModelModel
                        change_id = generate_id(f"{id_path}_{el['sline']}_{el['type']}")
                        change = ChangeModel(id=change_id, line=el['sline'], content=el['content'],
                                             start_col=el['scol'], end_col=el['ecol'], type=el['type'],
                                             diff_block_id=diff_block_model.id)

                        changes.append(change)

                    session.add(diff_block_model)
                    session.add_all(changes)
                    session.commit()
                    db_diff_blocks.update({diff_block_id: diff_block_model})

                except (AssertionError, ValueError, IndexError) as e:
                    # TODO: fix the IndexError
                    self.app.log.error(f"{commit.vulnerability_id}_{diff_block.a_path} {e}")
                except IntegrityError as ie:
                    self.app.log.error(f"{commit.vulnerability_id}_{diff_block.a_path} {ie}")
                    session.rollback()

            return db_diff_blocks.keys()
        return None


def load(app):
    app.handler.register(DiffParserHandler)
