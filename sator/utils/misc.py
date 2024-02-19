from typing import List

import requests
import hashlib
import re
import javalang
from javalang.tree import MethodDeclaration
from sator.data.parsing import Method


def get_file_content_from_url(url: str):
    request = requests.get(url)

    if request.status_code == 200:
        return request.text
    else:
        raise Exception(f'Request code {request.status_code} for {url}')


def get_digest(string: str):
    return hashlib.md5(string.encode('utf-8')).hexdigest()


def extract_company(email: str):
    res = re.findall(r"\@(.*?)\.", email)

    if res:
        return res[0]


def remove_comments(string):
    pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
    # first group captures quoted strings (double or single)
    # second group captures comments (//single-line or /* multi-line */)
    regex = re.compile(pattern, re.MULTILINE | re.DOTALL)

    def _replacer(match):
        # if the 2nd group (capturing comments) is not None,
        # it means we have captured a non-quoted (real) comment string.
        if match.group(2) is not None:
            return ""  # so we will return empty to remove the comment
        else:  # otherwise, we will return the 1st group
            return match.group(1)  # captured quoted-string

    return regex.sub(_replacer, string)


def clean_code(code):
    # Remove comments
    code = remove_comments(code)

    # Replace consecutive newlines with a single newline in code, and newlines with spaces in code
    code = code.strip()
    code = re.sub(r'\s+', ' ', code)

    return code


class JavaMethodExtractor:
    def __init__(self, code_lines: List[str]):
        self.code_lines = code_lines
        self.tree = javalang.parse.parse('\n'.join(code_lines))
        self.methods: List[Method] = []
        self.last_end_line_idx = None

        self._get_methods()

    def _get_methods(self):
        if not self.methods:
            for asd, method_node in self.tree.filter(MethodDeclaration):
                self._get_method_boundaries(method_node)

    def _get_method_boundaries(self, method_node: MethodDeclaration):
        # TODO: calculate the end line and column for abstract methods
        start_pos = None
        end_pos = None
        start_line = None
        end_line = None

        for path, node in self.tree:
            if start_pos is not None and method_node not in path:
                end_pos = node.position
                end_line = node.position.line if node.position is not None else None
                break
            if start_pos is None and node == method_node:
                start_pos = node.position
                start_line = node.position.line if node.position is not None else None

        if start_pos is None:
            self.last_end_line_idx = None
            return None

        start_line_idx = start_line - 1
        end_line_idx = end_line - 1 if end_pos is not None else None

        # check for and fetch annotations
        start_line_idx = self._adjust_start_line_idx(method_node, start_line_idx)
        end_line_idx = self._adjust_end_line_idx(method_node, end_line_idx)

        meth_text = self._get_method_text(method_node, start_line_idx, end_line_idx)
        # remove trailing rbrace for last methods & any external content/comments
        meth_text = self.remove_trailing_rbrace(meth_text)

        meth_lines = meth_text.split("<ST>")
        meth_text = "".join(meth_lines)
        self.last_end_line_idx = start_line_idx + (len(meth_lines) - 1)
        modifiers_size = len(' '.join(list(method_node.modifiers))) + 1 if method_node.modifiers else 0
        start_col = (method_node.position.column - modifiers_size) if method_node.position is not None else None
        start_line = start_line_idx + 1
        end_line = self.last_end_line_idx + 1
        close_bracket_idx = meth_lines[-1].rfind("}")

        if close_bracket_idx != -1:
            end_col = close_bracket_idx + 1
        else:
            end_col = meth_lines[-1].rfind(";") + 1

        method = Method(name=method_node.name, start_line=start_line, start_col=start_col, end_line=end_line,
                        end_col=end_col, code=meth_text)

        self.methods.append(method)

    def _adjust_start_line_idx(self, method_node: MethodDeclaration, start_line_idx: int):
        # TODO: check if this covers all cases
        if self.last_end_line_idx is not None and method_node.annotations:
            for line in self.code_lines[(self.last_end_line_idx + 1):start_line_idx]:
                if line.strip().startswith("@"):
                    start_line_idx -= 1

        return start_line_idx

    def _adjust_end_line_idx(self, method_node: MethodDeclaration, end_line_idx: int):
        # TODO: check if this covers all cases
        if 'abstract' in method_node.modifiers and method_node.position.line != end_line_idx:
            for idx in range(end_line_idx-1, method_node.position.line, -1):
                end_line_idx -= 1

                if self.code_lines[idx].rfind(";") != -1:
                    return idx + 1

        return end_line_idx

    def _get_method_text(self, method_node: MethodDeclaration, start_line_idx: int, end_line_idx: int):
        meth_text = "<ST>".join(self.code_lines[start_line_idx:end_line_idx])

        if 'abstract' in method_node.modifiers:
            return meth_text[:meth_text.rfind(";") + 1]

        return meth_text[:meth_text.rfind("}") + 1]

    @staticmethod
    def remove_trailing_rbrace(meth_text):
        if not abs(meth_text.count("}") - meth_text.count("{")) == 0:
            brace_diff = abs(meth_text.count("}") - meth_text.count("{"))

            for _ in range(brace_diff):
                meth_text = meth_text[:meth_text.rfind("}")]
                meth_text = meth_text[:meth_text.rfind("}") + 1]

        return meth_text


def get_allowed_origins():
    import os
    origins = os.environ.get('ALLOWED_ORIGINS', [])

    if isinstance(origins, str):
        return origins.split(',')

    return origins
