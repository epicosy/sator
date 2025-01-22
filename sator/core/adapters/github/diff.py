from sator.core.adapters.base import BaseAdapter

from arepo.models.vcs.diff import DiffBlockModel, ChangeModel

from gitlib.models.diff import Diff


class DiffAdapter(BaseAdapter):
    def __init__(self, commit_file_id: str, diff: Diff):
        super().__init__()
        self.commit_file_id = commit_file_id
        self.diff = diff

    def __call__(self):
        # TODO: convert diff object to model and add to results
        for patch in self.diff.patches:
            # TODO: convert patch object to model and add to results
            for diff_hunk in patch.hunks:
                # TODO: DiffBlockModel should be updated to DiffHunk and its attributes
                diff_hunk_model = DiffBlockModel(order=diff_hunk.order, a_path=patch.old_file,
                                                 commit_file_id=self.commit_file_id)

                yield from self.yield_if_new(diff_hunk_model, DiffBlockModel.__tablename__)

                for diff_line in diff_hunk.ordered_lines:
                    # TODO: ChangeModel should be updated to DiffLine and be a Mixin
                    diff_line_model = ChangeModel(line=diff_line.lineno, content=diff_line.content, type=diff_line.type,
                                                  start_col=diff_line.start_col, end_col=diff_line.end_col,
                                                  diff_block_id=diff_hunk_model.id)

                    yield from self.yield_if_new(diff_line_model, ChangeModel.__tablename__)
