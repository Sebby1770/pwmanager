"""Crash-resistant, private atomic writes for secret-bearing files."""

from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from typing import Iterator, Optional, TextIO, Union

PathLike = Union[str, os.PathLike[str]]


def _fsync_directory(path: str) -> None:
    """Persist a completed rename when the platform supports directory fsync."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        directory_fd = os.open(path, flags)
    except OSError:
        # Windows and some filesystems do not allow opening directories this way.
        return
    try:
        try:
            os.fsync(directory_fd)
        except OSError:
            # The file itself was already flushed; directory fsync is best-effort
            # on platforms/filesystems that do not implement it.
            pass
    finally:
        os.close(directory_fd)


@contextmanager
def atomic_private_text_writer(
    path: PathLike,
    *,
    newline: Optional[str] = None,
) -> Iterator[TextIO]:
    """Yield a private temporary file and atomically replace ``path``.

    The temporary file is unpredictable, exclusively created in the destination
    directory, and explicitly mode ``0600``.  Successful writes are flushed and
    fsynced before the rename; the containing directory is then fsynced where
    supported.  ``os.replace`` replaces a destination symlink itself rather than
    following it, so neither a pre-planted destination nor the former predictable
    ``<vault>.tmp`` name can redirect secret data into another file.
    """
    destination = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(destination) or os.curdir
    basename = os.path.basename(destination) or "secret"

    file_fd: Optional[int] = None
    temporary_path: Optional[str] = None
    try:
        file_fd, temporary_path = tempfile.mkstemp(
            prefix=f".{basename}.",
            suffix=".tmp",
            dir=directory,
            text=True,
        )
        if hasattr(os, "fchmod"):
            os.fchmod(file_fd, 0o600)
        with os.fdopen(
            file_fd,
            "w",
            encoding="utf-8",
            newline=newline,
        ) as output:
            file_fd = None
            yield output
            output.flush()
            os.fsync(output.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None
        _fsync_directory(directory)
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


__all__ = ["atomic_private_text_writer"]
