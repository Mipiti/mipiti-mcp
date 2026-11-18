"""``mipiti-mcp install-skill``: write the review skill where a coding agent
reads skills.

The skill (``skills/mipiti-review/SKILL.md``, in the Agent Skills format)
tells an agent to read ``get_review_playbook`` and follow it; the procedure
itself stays on the server, so an installed copy never goes stale. It is
written under ``.agents/skills/`` by default, under the directory a named
agent reads (``--for``), or under ``--dir``. A file already there is replaced
only when this command wrote it (it carries the marker line); any other is
left alone and the command fails, naming it.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
import tempfile
from pathlib import Path

SKILL_NAME = "mipiti-review"
SOURCE = Path(__file__).with_name("skills") / SKILL_NAME / "SKILL.md"
MARKER = "<!-- mipiti-mcp install-skill:"

#: Where each agent reads project skills, relative to the project.
TARGETS = {
    "agents": Path(".agents/skills"),
    "claude": Path(".claude/skills"),
    "gemini": Path(".gemini/skills"),
    "copilot": Path(".github/skills"),
}


class InstallRefused(Exception):
    """The skill's file exists and was not written by this command."""


def _no_link(path: Path, stop: Path) -> None:
    """Refuse ``path`` when it, or any directory between ``stop`` and it, is a
    symbolic link: a link planted in a repository would send the write
    elsewhere."""
    for p in [path, *path.parents]:
        if p == stop or p == p.parent:
            break
        if p.is_symlink():
            raise InstallRefused(f"{p} is a symbolic link; the skill is not written through one.")


def install(root: Path, *, target: str = "agents", directory: Path | None = None) -> Path:
    """Write the skill under ``directory`` (relative to ``root`` unless
    absolute), or under ``target``'s skills directory in ``root``; returns the
    file written. Raises ``InstallRefused`` where a file this command did not
    write is in the way, where a symbolic link is on the path below the
    expected folder, or where the folder written to does not resolve inside
    the expected folder: the project (``root``), or ``directory`` when the
    person named an absolute one.

    Three checks, each closing what the others leave: no link on the path
    (a planted one is refused by name, before anything is created); the
    resolved folder inside the resolved expected one (whatever the path's
    spelling or its links, the folder written to is where it was meant to
    be); and the file written under a fresh random name created exclusively
    (``mkstemp``: it neither follows nor reuses a planted file) in that
    resolved folder, then moved onto the skill's name, which replaces a link
    there rather than following it."""
    base = directory if directory is not None else TARGETS[target]
    stop = base if base.is_absolute() else root
    if not base.is_absolute():
        base = root / base
    dest = base / SKILL_NAME / "SKILL.md"
    _no_link(dest, stop)
    if dest.exists() and MARKER not in dest.read_text(encoding="utf-8"):
        raise InstallRefused(f"{dest} exists and was not written by mipiti-mcp install-skill; "
                             "move it away to install the skill there.")
    # The project exists; an absolute --dir may not yet, and is the person's.
    expected = stop.resolve(strict=False)

    def contained(folder: Path) -> Path:
        if not folder.is_relative_to(expected):
            raise InstallRefused(
                f"{dest.parent} resolves to {folder}, outside {expected}; name an absolute "
                "--dir to install the skill elsewhere.")
        return folder

    # Before anything is created, as far as the path exists; and again once
    # it does, the folder written to being the one resolved then.
    contained(dest.parent.resolve(strict=False))
    dest.parent.mkdir(parents=True, exist_ok=True)
    _no_link(dest, stop)
    folder = contained(dest.parent.resolve(strict=True))
    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".SKILL.md.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(SOURCE.read_text(encoding="utf-8"))
        os.replace(tmp, folder / "SKILL.md")
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
    return folder / "SKILL.md"


def main(argv: list[str]) -> int:
    """``mipiti-mcp install-skill [--for AGENT | --dir DIR]``."""
    parser = argparse.ArgumentParser(
        prog="mipiti-mcp install-skill",
        description="Write the Mipiti review skill where a coding agent reads skills.")
    where = parser.add_mutually_exclusive_group()
    where.add_argument("--for", dest="target", choices=sorted(TARGETS), default="agents",
                       help="the agent whose skills directory to write to "
                            "(default: agents, i.e. .agents/skills)")
    where.add_argument("--dir", dest="directory", type=Path,
                       help="the skills directory to write to instead")
    args = parser.parse_args(argv)
    try:
        dest = install(Path.cwd(), target=args.target, directory=args.directory)
    except InstallRefused as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError as exc:
        # Permission denied, a read-only folder, a path past the system's
        # limit: said in one line; nothing was written.
        where = exc.filename or args.directory or args.target
        print(f"Could not install the skill at {where}: {exc.strerror or exc}", file=sys.stderr)
        return 1
    print(dest)
    return 0
