"""
compile_check.py — Compile / syntax-check Stage-1 PASSED files.
Updates filtered_files.compile_status in corpus.db.

Features:
  - Absolute DB_PATH derived from __file__.
  - Uses sys.executable for Python syntax check (portable).
  - Preflight checks for gcc and node at startup.
  - C files marked COMPILED, REPAIR_COMPILED, COMPILE_FAIL, or COMPILE_SKIPPED (if gcc missing).
  - Python files marked SYNTAX_OK or SYNTAX_FAIL.
  - JavaScript files marked SYNTAX_OK (if node available) or NOT_APPLICABLE.
"""

import sqlite3
import subprocess
import tempfile
import os
import sys
import shutil

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DB_PATH  = os.path.join(BASE_DIR, 'corpus.db')

COMMON_HEADERS = [
    '#include <stdio.h>',
    '#include <stdlib.h>',
    '#include <string.h>',
    '#include <stdint.h>',
    '#include <stdbool.h>',
]

# --------------------------------------------------------------------------- #
# Preflight checks
# --------------------------------------------------------------------------- #
GCC_AVAILABLE  = shutil.which('gcc') is not None or shutil.which('wsl') is not None
NODE_AVAILABLE = shutil.which('node') is not None

def _preflight_report():
    if shutil.which('gcc') is not None:
        try:
            v = subprocess.run(['gcc', '--version'], capture_output=True, text=True, timeout=5)
            print(f'gcc found: {v.stdout.splitlines()[0]}')
        except Exception:
            pass
    elif shutil.which('wsl') is not None:
        try:
            v = subprocess.run(['wsl', 'gcc', '--version'], capture_output=True, text=True, timeout=5)
            print(f'gcc (via WSL) found: {v.stdout.splitlines()[0]}')
        except Exception:
            pass
    else:
        print('WARNING: gcc not found on PATH — C files will be marked COMPILE_SKIPPED.')

    if NODE_AVAILABLE:
        print('node found for JavaScript syntax checks.')
    else:
        print('INFO: node not found on PATH — JS files will be marked NOT_APPLICABLE.')


# --------------------------------------------------------------------------- #
# Language compilation & syntax checking helpers
# --------------------------------------------------------------------------- #
def try_compile_c(content):
    """Returns (success: bool, stderr: str)."""
    with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False, encoding='utf-8') as f:
        f.write(content)
        tmp_path = f.name
    try:
        if shutil.which('gcc') is not None:
            cmd = ['gcc', '-Wall', '-Wno-unused', '-fsyntax-only', tmp_path]
        else:
            wsl_path = tmp_path.replace('\\', '/')
            if len(wsl_path) > 2 and wsl_path[1:3] == ':/':
                wsl_path = f"/mnt/{wsl_path[0].lower()}{wsl_path[2:]}"
            cmd = ['wsl', 'gcc', '-Wall', '-Wno-unused', '-fsyntax-only', wsl_path]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0, result.stderr
    finally:
        os.unlink(tmp_path)


def try_repair_and_compile(content):
    header_block = '\n'.join(COMMON_HEADERS) + '\n\n'
    repaired = header_block + content
    success, stderr = try_compile_c(repaired)
    if success:
        return 'REPAIR_COMPILED', repaired, stderr
    return 'COMPILE_FAIL', content, stderr


def try_compile_python(content):
    """Uses sys.executable (portable on Windows and Linux)."""
    with tempfile.NamedTemporaryFile(suffix='.py', mode='w', delete=False, encoding='utf-8') as f:
        f.write(content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'py_compile', tmp_path],
            capture_output=True, text=True, timeout=10
        )
        return ('SYNTAX_OK' if result.returncode == 0 else 'SYNTAX_FAIL'), result.stderr
    finally:
        os.unlink(tmp_path)


def try_check_javascript(content):
    """Syntax check JS if node is available, else return NOT_APPLICABLE."""
    if not NODE_AVAILABLE:
        return 'NOT_APPLICABLE', ''
    with tempfile.NamedTemporaryFile(suffix='.js', mode='w', delete=False, encoding='utf-8') as f:
        f.write(content)
        tmp_path = f.name
    try:
        result = subprocess.run(
            ['node', '--check', tmp_path],
            capture_output=True, text=True, timeout=10
        )
        return ('SYNTAX_OK' if result.returncode == 0 else 'SYNTAX_FAIL'), result.stderr
    finally:
        os.unlink(tmp_path)


# --------------------------------------------------------------------------- #
# Main execution
# --------------------------------------------------------------------------- #
def run_compile_checks():
    _preflight_report()

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    rows = c.execute(
        'SELECT ff.program_id, ff.language, r.file_content '
        'FROM filtered_files ff '
        'JOIN raw_files r ON ff.raw_file_id = r.id '
        'WHERE ff.stage1 = "PASSED" AND ff.compile_status IS NULL'
    ).fetchall()

    print(f'Running compile checks on {len(rows)} files...')
    print(f'Using DB: {DB_PATH}')
    results = {}

    for program_id, language, content in rows:
        if content is None:
            status = 'COMPILE_FAIL'

        elif language == 'Python':
            status, _ = try_compile_python(content)

        elif language == 'C':
            if not GCC_AVAILABLE:
                status = 'COMPILE_SKIPPED'
            else:
                ok, stderr = try_compile_c(content)
                if ok:
                    status = 'COMPILED'
                else:
                    status, _, _ = try_repair_and_compile(content)

        elif language == 'JavaScript':
            status, _ = try_check_javascript(content)

        else:
            status = f'UNKNOWN_LANGUAGE:{language}'

        c.execute(
            'UPDATE filtered_files SET compile_status = ? WHERE program_id = ?',
            (status, program_id)
        )
        results[status] = results.get(status, 0) + 1

    conn.commit()
    conn.close()

    print('Compile results:')
    for status, count in sorted(results.items(), key=lambda x: -x[1]):
        print(f'  {status}: {count}')
    if not results:
        print('  No files to check yet (run filter_stage1.py first)')


if __name__ == '__main__':
    run_compile_checks()
