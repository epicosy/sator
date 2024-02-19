from dataclasses import dataclass, field


@dataclass
class Method:
    name: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int
    code: str

    def __len__(self):
        return len(self.code.splitlines())

    def __repr__(self):
        return f"Method(name={self.name}, start_line={self.start_line}, start_pos={self.start_col}, " \
               f"end_line={self.end_line}, end_pos={self.end_col}, code={self.code})"
