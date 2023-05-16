import re
import time
from typing import Optional


def str_sanitize_cc(string: str) -> str:
    newstr = ""
    for x in string:
        if ord(x) < 32:
            newstr += ' '
        else:
            newstr += x
    return newstr


def str_sanitize(string: str) -> str:
    return re.sub(r"\s", ' ', string)


def merge_bytearray(
        buffer: bytearray, insert_index,
        inserted: bytearray,
        inserted_size: Optional[int] = None) -> None:
    """Inserts <inserted> into the target buffer."""
    if inserted_size is None:
        inserted_size = len(inserted)
    for x in range(insert_index, insert_index + inserted_size):
        buffer[x] = inserted[x - insert_index]


def time_get() -> int:
    return time.time_ns()


def time_freq() -> int:
    # nanoseconds
    return 1000000000


def str_sanitize_strong(string: str) -> str:
    newstr = ""
    for x in string:
        if ord(x) < 32 or ord(x) > 127:
            newstr += " "
        else:
            newstr += x
    return newstr
