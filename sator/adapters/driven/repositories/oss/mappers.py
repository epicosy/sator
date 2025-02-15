from gitlib.common.enums import DiffLineType
from sator.core.models.oss.diff import Diff, Patch, DiffHunk, DiffLine


class GithubDiffMapper:
    @staticmethod
    def map_diff(sha: str, parent_commit_sha: str, diff_data) -> Diff:
        patches = [GithubDiffMapper.map_patch(patch) for patch in diff_data.patches]
        return Diff(commit_sha=sha, parent_commit_sha=parent_commit_sha, patches=patches)

    @staticmethod
    def map_patch(patch_data) -> Patch:
        hunks = [GithubDiffMapper.map_hunk(i, hunk) for i, hunk in enumerate(patch_data.hunks)]
        return Patch(old_file=patch_data.old_file, new_file=patch_data.new_file, hunks=hunks)

    @staticmethod
    def map_hunk(order: int, hunk_data) -> DiffHunk:
        old_lines, new_lines = GithubDiffMapper.categorize_lines(hunk_data.ordered_lines)
        return DiffHunk(
            order=order,
            old_start=hunk_data.old_start,
            old_lines=old_lines,
            new_start=hunk_data.new_start,
            new_lines=new_lines,
        )

    @staticmethod
    def categorize_lines(lines) -> tuple:
        old_lines, new_lines = [], []
        for line in lines:
            diff_line = DiffLine(
                type=line.type.value,
                lineno=line.lineno,
                content=line.content,
            )
            if line.type == DiffLineType.ADDITION:
                new_lines.append(diff_line)
            else:
                old_lines.append(diff_line)
        return old_lines, new_lines
