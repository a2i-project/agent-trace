#!/usr/bin/env python3
"""Keep the documentation consistent with the code, commit by commit.

The rules are in docs/methodology/dev_workflow.md ("Documentation"). This
script enforces the mechanical part of them. Standard library only.

  check-docs.py lint                 check the published docs tree
  check-docs.py commits BASE HEAD    check every commit in BASE..HEAD
  check-docs.py commit-msg FILE      check one commit message (git hook)

Exit status: 0 when clean, 1 when a rule is broken (each violation printed).
"""

import os
import re
import subprocess
import sys

ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                      text=True, check=True).stdout.strip()

# Published documentation. Local folders (docs/todo, docs/eval, docs/research,
# docs/archive) are gitignored and never checked here.
PUBLISHED_DIRS = ["docs/architecture", "docs/decisions", "docs/methodology", "docs/related_work"]
PUBLISHED_FILES = ["README.md", "AGENTS.md", "CLAUDE.md", "CODEX.md", "GEMINI.md", "docs/README.md"]

# Each code path belongs to one architecture page. A commit that changes
# non-test code under a path must change that page, or say in its Docs
# trailer why no documented behaviour changed.
PAGE_OF = [
    ("pkg/verification/completeness.go", "docs/architecture/10_probes_common.md"),
    ("pkg/probe/proc/", "docs/architecture/11_probe_proc.md"),
    ("pkg/probe/fs/", "docs/architecture/12_probe_fs.md"),
    ("pkg/content/", "docs/architecture/12_probe_fs.md"),
    ("pkg/probe/net/", "docs/architecture/13_probe_net.md"),
    ("pkg/tlsoffset/", "docs/architecture/13_probe_net.md"),
    ("pkg/tlsparse/", "docs/architecture/13_probe_net.md"),
    ("pkg/probe/probe.go", "docs/architecture/10_probes_common.md"),
    ("pkg/models/", "docs/architecture/10_probes_common.md"),
    ("pkg/verification/", "docs/architecture/20_verifier.md"),
    ("pkg/matching/", "docs/architecture/20_verifier.md"),
    ("pkg/agent/", "docs/architecture/30_agent_adapters.md"),
    ("pkg/attack/", "docs/architecture/50_attack_generators.md"),
    ("cmd/attack/", "docs/architecture/50_attack_generators.md"),
    ("cmd/", "docs/architecture/40_tools.md"),
    ("scripts/capture-claude-code.sh", "docs/architecture/40_tools.md"),
    ("scripts/make-capture-fixture.py", "docs/architecture/40_tools.md"),
    ("Makefile", "docs/architecture/40_tools.md"),
    ("scripts/check-docs.py", "docs/methodology/dev_workflow.md"),
    ("scripts/hooks/", "docs/methodology/dev_workflow.md"),
    (".github/workflows/", "docs/methodology/dev_workflow.md"),
]
LOCAL_DIRS = ("docs/todo/", "docs/eval/", "docs/research/", "docs/archive/")
PAGE_SECTIONS = ["Objective", "Structure", "Technologies", "Workflow",
                 "Guarantees and loss accounting", "Known limits"]
LOCAL_ID = re.compile(r"\b(?:OBS|VER|ADP|RM|DOC)-\d+\b")
DECISION_REF = re.compile(r"\b(?:(?:P|N|I|E|O|V)-\d+|N-D\d|V\d)\b")
DECISION_HEAD = re.compile(r"^### ((?:P|N|I|E|O|V)-\d+|N-D\d|V\d|D\d+|[A-Z0-9.\-]+):", re.M)
CHECKED = re.compile(r"^Checked against commit ([0-9a-f]{7,40}) on (\d{4}-\d{2}-\d{2})\.$", re.M)
DOCS_TRAILER = re.compile(r"^Docs: (updated|none \(.+\))\s*$", re.M)
FIXES_TRAILER = re.compile(r"^Docs-Fixes: (.+)$", re.M)
EXEMPT_SUBJECT = re.compile(r"^(Merge |Revert \")")

errors = []


def err(where, msg):
    errors.append(f"{where}: {msg}")


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          check=check).stdout


def published_files():
    out = []
    for d in PUBLISHED_DIRS:
        for name in sorted(os.listdir(os.path.join(ROOT, d))):
            if name.endswith(".md"):
                out.append(f"{d}/{name}")
    out += [f for f in PUBLISHED_FILES if os.path.exists(os.path.join(ROOT, f))]
    return out


def read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def decision_ids():
    ids, closed = set(), set()
    for name in os.listdir(os.path.join(ROOT, "docs/decisions")):
        text = read(f"docs/decisions/{name}")
        ids.update(DECISION_HEAD.findall(text))
        m = re.search(r"^Closed: (.*)$", text, re.M)
        if m:
            closed.update(re.findall(r"\bO-\d+\b", m.group(1)))
    return ids, closed


def lint():
    ids, closed = decision_ids()
    for path in published_files():
        text = read(path)
        for n, line in enumerate(text.splitlines(), 1):
            if "—" in line or "–" in line:
                err(f"{path}:{n}", "em or en dash (house style: none)")
            if "docs/plan/" in line:
                err(f"{path}:{n}", "reference to docs/plan/ (moved to the local docs/archive/)")
            if LOCAL_ID.search(line) and "local only" not in line:
                err(f"{path}:{n}", f"local todo ID {LOCAL_ID.search(line).group(0)} without '(local only)'")
            for ref in DECISION_REF.findall(line):
                if ref not in ids and ref not in closed:
                    err(f"{path}:{n}", f"decision ID {ref} does not exist (and is not listed as Closed in open.md)")
        for target in re.findall(r"\]\(([^)#\s]+)(?:#[^)]*)?\)", text):
            if target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = os.path.relpath(os.path.normpath(os.path.join(ROOT, os.path.dirname(path), target)), ROOT)
            if resolved.startswith(LOCAL_DIRS):
                err(path, f"link {target} points into a local-only folder, which a reader of the repository does not have")
            elif not os.path.exists(os.path.join(ROOT, resolved)):
                err(path, f"broken link {target}")
    lint_architecture()
    lint_decisions()
    lint_code_comments()
    lint_not_yet_implemented()


def lint_architecture():
    for name in sorted(os.listdir(os.path.join(ROOT, "docs/architecture"))):
        if not name.endswith(".md"):
            continue
        path = f"docs/architecture/{name}"
        text = read(path)
        m = CHECKED.search(text)
        if not m:
            err(path, "missing line 'Checked against commit <sha> on <YYYY-MM-DD>.' (exactly that sentence, on one line)")
            continue
        if subprocess.run(["git", "cat-file", "-e", m.group(1) + "^{commit}"], cwd=ROOT,
                          capture_output=True).returncode != 0:
            err(path, f"'Checked against' names {m.group(1)}, which is not a commit")
        if name.startswith("00_"):
            continue
        heads = re.findall(r"^## (.+)$", text, re.M)
        pos = [heads.index(s) if s in heads else -1 for s in PAGE_SECTIONS]
        if -1 in pos or pos != sorted(pos):
            err(path, f"sections must include, in order: {', '.join(PAGE_SECTIONS)}")


def lint_decisions():
    for name in sorted(os.listdir(os.path.join(ROOT, "docs/decisions"))):
        path = f"docs/decisions/{name}"
        text = read(path)
        ids, closed = decision_ids()
        for block in re.split(r"(?m)^### ", text)[1:]:
            head = block.splitlines()[0]
            if not re.search(r"(?m)^Status: ", block):
                err(path, f"entry '{head}' has no Status line")
            if not re.search(r"(?m)^Date: ", block):
                err(path, f"entry '{head}' has no Date line")
            for sup in re.findall(r"Superseded(?: \([^)]*\))? by ((?:[PNIEOV]-\d+)|V\d|N-D\d)", block):
                if sup not in ids:
                    err(path, f"entry '{head}' is superseded by {sup}, which does not exist")
            if name == "open.md" and re.search(r"(?m)^Status: (Decided|Accepted|Superseded)", block):
                err(path, f"entry '{head}' is decided: record it in its area file, delete it here, and add it to the Closed line")


def lint_code_comments():
    tracked = git("ls-files", "*.go", "*.c", "*.sh", "*.py").split()
    for path in tracked:
        if path.endswith("vmlinux.h") or path == "scripts/check-docs.py":
            continue
        for n, line in enumerate(read(path).splitlines(), 1):
            if "docs/plan/" in line:
                err(f"{path}:{n}", "reference to docs/plan/")
            m = LOCAL_ID.search(line)
            if m and "local only" not in line:
                err(f"{path}:{n}", f"local todo ID {m.group(0)} in tracked code (cite a decision ID instead)")


def lint_not_yet_implemented():
    """A page that says something is not yet implemented must name a decision
    whose Status still says so, so the mention cannot outlive the work."""
    pending = set()
    for name in os.listdir(os.path.join(ROOT, "docs/decisions")):
        for block in re.split(r"(?m)^### ", read(f"docs/decisions/{name}"))[1:]:
            status = re.search(r"(?m)^Status: (.*)$", block)
            if status and "not yet implemented" in status.group(1):
                pending.add(block.split(":", 1)[0])
    for path in published_files():
        if not (path.startswith("docs/architecture/") or path == "README.md"):
            continue
        for n, line in enumerate(read(path).splitlines(), 1):
            if "not yet implemented" in line and not set(DECISION_REF.findall(line)) & pending:
                err(f"{path}:{n}", "'not yet implemented' without a decision ID whose Status still says so")


def page_for(path):
    if path.endswith("_test.go") or "/testdata/" in path:
        return None
    for prefix, page in PAGE_OF:
        if path.startswith(prefix):
            return page
    return None


def code_paths_of(page):
    """Pathspecs for the code a page describes, excluding more specific
    prefixes that belong to another page (cmd/attack/ under cmd/)."""
    own = [prefix for prefix, p in PAGE_OF if p == page]
    other = [prefix for prefix, p in PAGE_OF if p != page]
    excl = [f":(exclude){o}" for o in other if any(o != x and o.startswith(x) for x in own)]
    # Tests and fixtures describe no behaviour a page documents (as in page_for).
    return own + excl + [":(exclude,glob)**/*_test.go", ":(exclude,glob)**/testdata/**"]


def check_message(where, msg, files=None, parent=None, sha=None):
    if EXEMPT_SUBJECT.match(msg):
        return  # merges and reverts: the commits they merge or undo carry the trailer
    m = DOCS_TRAILER.search(msg)
    if not m:
        err(where, "no 'Docs:' trailer. Add 'Docs: updated' or 'Docs: none (<why no documented behaviour changed>)'")
        return
    changed_docs = None
    if files is not None:
        changed_docs = {f for f in files if f.startswith("docs/") or f in PUBLISHED_FILES}
        needed = {page_for(f) for f in files} - {None}
        if m.group(1) == "updated" and files:
            if not changed_docs:
                err(where, "'Docs: updated' but the commit changes no published doc")
            missing = needed - changed_docs
            if missing:
                err(where, f"code changed under {', '.join(sorted(missing))}'s component but the page is not updated; update it or write 'Docs: none (<why>)'")
        for page in sorted(changed_docs):
            if page.startswith("docs/architecture/") and not page.endswith("00_overview.md"):
                check_freshness(where, page, sha, parent)
    for ref in re.findall(r"^Implements: (.+)$", msg, re.M):
        for did in re.split(r"[,\s]+", ref.strip()):
            if not did:
                continue
            text = "\n".join(read(f"docs/decisions/{n}") if sha is None else
                             git("show", f"{sha}:docs/decisions/{n}", check=False)
                             for n in os.listdir(os.path.join(ROOT, "docs/decisions")))
            block = re.search(rf"(?ms)^### {re.escape(did)}:.*?(?=^### |\Z)", text)
            if not block:
                err(where, f"Implements: {did}, which does not exist")
            elif re.search(r"(?m)^Status: .*not yet implemented", block.group(0)):
                err(where, f"Implements: {did}, but its Status still says 'not yet implemented'")
    todo_dir = os.path.join(ROOT, "docs/todo")
    for ref in re.findall(r"^Closes-Todo: (.+)$", msg, re.M):
        for tid in re.split(r"[,\s]+", ref.strip()):
            if not tid or not os.path.isdir(todo_dir):
                continue
            for name in os.listdir(todo_dir):
                if re.search(rf"(?m)^### {re.escape(tid)}:", read(f"docs/todo/{name}")):
                    err(where, f"Closes-Todo: {tid}, but docs/todo/{name} still lists it (delete the item; move any open remainder)")


def check_freshness(where, page, sha, parent):
    text = git("show", f"{sha}:{page}", check=False)
    m = CHECKED.search(text)
    if not m or not parent:
        return
    paths = code_paths_of(page)
    if not paths:
        return
    diff = subprocess.run(["git", "diff", "--quiet", m.group(1), parent, "--", *paths], cwd=ROOT)
    if diff.returncode != 0:
        err(where, f"{page} names commit {m.group(1)}, but its component's code differs between that commit and this commit's parent {parent[:7]}; re-check the page and name the parent")


def commits(base, head):
    """Check every commit in base..head. A later commit in the range with a
    'Docs-Fixes: <sha>' trailer clears the errors of the commit it repairs, so
    a branch is fixed by adding a commit, never by rewriting history."""
    global errors
    per_commit, fixed = {}, set()
    for sha in git("rev-list", "--reverse", "--no-merges", f"{base}..{head}").split():
        author = git("log", "-1", "--format=%ae", sha)
        if "[bot]" in author or "dependabot" in author:
            continue  # dependency bumps carry no documented behaviour
        msg = git("log", "-1", "--format=%B", sha)
        for ref in FIXES_TRAILER.findall(msg):
            fixed.update(x[:7] for x in re.split(r"[,\s]+", ref.strip()) if x)
        files = git("diff-tree", "--no-commit-id", "--name-only", "-r", sha).split()
        parent = git("rev-parse", f"{sha}^", check=False).strip() or None
        before = len(errors)
        check_message(sha[:7], msg, files, parent, sha)
        per_commit[sha[:7]] = errors[before:]
        errors = errors[:before]
    for sha, errs in per_commit.items():
        if sha not in fixed:
            errors.extend(errs)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    mode = sys.argv[1]
    if mode == "lint":
        lint()
    elif mode == "commits" and len(sys.argv) == 4:
        commits(sys.argv[2], sys.argv[3])
    elif mode == "commit-msg" and len(sys.argv) == 3:
        with open(sys.argv[2], encoding="utf-8") as f:
            msg = f.read()
        if subprocess.run(["git", "rev-parse", "-q", "--verify", "MERGE_HEAD"], cwd=ROOT,
                          capture_output=True).returncode == 0:
            return 0  # a merge commit
        staged = git("diff", "--cached", "--name-only").split()
        # An empty index is a message-only amend: the trailer is still checked,
        # the file rules are not (the amended commit's files are not visible here).
        check_message("commit message", msg, staged or None)
    else:
        print(__doc__)
        return 2
    for e in errors:
        print(e)
    if errors:
        print(f"\n{len(errors)} documentation rule(s) broken. See docs/methodology/dev_workflow.md, Documentation.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
