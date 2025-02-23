
from pydantic import BaseModel


class PatchLocator(BaseModel):
    repository_id: int
    diff_id: str
    file_path: str
    start_lineno: int
    end_lineno: int

    def __str__(self):
        return (f"Repository Id - {self.repository_id} | Diff Id - {self.diff_id} | File Path - {self.file_path} | "
                f"Patch Diff Hunk - ({self.start_lineno},{self.end_lineno})")
