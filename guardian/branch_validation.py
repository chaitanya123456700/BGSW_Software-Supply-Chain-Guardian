"""Portable, sanitized two-branch evidence for one exactly approved proposal."""
import os
import tempfile
from pathlib import Path

from .files import safe_file, write_json
from .process import run_tool


def compatibility(before, after):
    required = {'build', 'test'}
    if before.get('status') == 'failed':
        return {'status': 'baseline_failed', 'claim': 'The original application checks failed; no no-regression claim is made.'}
    if after.get('status') == 'failed':
        return {'status': 'failed', 'claim': 'The patched application checks failed.'}
    if all(r.get('status') == 'passed' and required.issubset(r.get('commands', [])) for r in (before, after)):
        return {'status': 'passed', 'claim': 'The same declared build and test checks passed before and after this patch. Untested behavior is not established.'}
    return {'status': 'not_verified', 'claim': 'Passing build and test checks on both versions are required to establish tested compatibility.'}


def export_branches(repo, proposal, artifacts, saved):
    """New snapshot history, not rewritten upstream history. No network or push."""
    from .remediation import digest, snapshot
    with tempfile.TemporaryDirectory(prefix='guardian-branches-') as directory:
        checkout = Path(directory)
        for relative, checksum in snapshot(repo).items():
            raw = safe_file(repo, relative).read_bytes()
            if digest(raw) != checksum:
                raise ValueError('Source changed while exporting branches')
            target = checkout / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        def git(*args):
            return run_tool(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                '-c', 'user.name=' + os.getenv('GUARDIAN_GIT_NAME', 'Guardian'),
                '-c', 'user.email=' + os.getenv('GUARDIAN_GIT_EMAIL', 'guardian@localhost'), *args], checkout, timeout=30).stdout.strip()
        git('init', '--initial-branch=vulnerable', '--template=')
        # Keep approved bytes exact despite source-controlled attributes.
        (checkout / '.git/info').mkdir(exist_ok=True)
        (checkout / '.git/info/attributes').write_text('* -text -filter -ident -working-tree-encoding\n')
        # Explicit paths include ignored source files; no repository config is loaded.
        git('add', '-f', '--all', '--', '.')
        git('commit', '--allow-empty', '-m', 'Vulnerable source snapshot for validation')
        before = git('rev-parse', 'HEAD')
        git('checkout', '-b', 'guardian-fixed')
        for relative, checksum in proposal['after'].items():
            if digest(safe_file(repo, relative).read_bytes()) != proposal['before'][relative]:
                raise ValueError('Source differs from reviewed proposal')
            raw = safe_file(artifacts, f"remediation/proposals/{proposal['id']}/{Path(relative).name}").read_bytes()
            if digest(raw) != checksum:
                raise ValueError('Patch differs from reviewed proposal')
            (checkout / relative).write_bytes(raw)
            git('add', '-f', '--', relative)
        git('commit', '-m', f"Apply reviewed Guardian upgrade for {proposal['name']}")
        after = git('rev-parse', 'HEAD')
        diff = git('diff', '--no-ext-diff', '--no-textconv', 'vulnerable', 'guardian-fixed', '--')
        (saved / 'branch-diff.patch').write_text(diff)
        git('bundle', 'create', str((saved / 'branches.bundle').resolve()), 'vulnerable', 'guardian-fixed')
        result = {'status': 'created', 'before_branch': 'vulnerable', 'after_branch': 'guardian-fixed',
                  'before_commit': before, 'after_commit': after, 'bundle_sha256': digest((saved / 'branches.bundle').read_bytes()),
                  'scope': 'One approved proposal; sanitized snapshot history, not upstream commit history. No remote branches were pushed.'}
        write_json(saved / 'branch-comparison.json', result)
        return result
