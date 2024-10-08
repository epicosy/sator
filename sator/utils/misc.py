import hashlib
from typing import List


def get_digest(string: str):
    return hashlib.md5(string.encode('utf-8')).hexdigest()


def split_dict(cve_data: dict, batch_size: int) -> List[dict]:
    batches = []
    batch = {}
    count = 0

    for cve_id, cve in cve_data.items():
        if count == batch_size:
            batches.append(batch)
            batch = {}
            count = 0

        batch[cve_id] = cve
        count += 1

    if count > 0:
        batches.append(batch)

    return batches
