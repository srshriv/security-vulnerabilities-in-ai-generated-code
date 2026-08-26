import sqlite3, subprocess, os, shutil

DB_PATH = '../corpus.db'
XML_DIR = '../results/cbmc_out'
os.makedirs(XML_DIR, exist_ok=True)
UNWIND = 10

def run_cbmc():
    if shutil.which('cbmc') is None:
        print("CBMC not installed — skipping.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""SELECT f.program_id, r.file_content FROM raw_files r
                       JOIN filtered_files f ON r.id = f.raw_file_id
                       WHERE f.stage1='PASSED' AND r.language='C'""")
    files = cursor.fetchall()
    print(f"Running CBMC on {len(files)} C programs (unwind={UNWIND})...")

    if not files:
        print("WARNING: no filtered C programs found.")
        return

    import tempfile
    tmp_dir = tempfile.gettempdir()

    for pid, content in files:
        src_path = os.path.join(tmp_dir, f'cbmc_{pid}.c')
        with open(src_path, 'w', encoding='utf-8') as f:
            f.write(content or '')
        xml_out = f'{XML_DIR}/{pid}.xml'
        try:
            with open(xml_out, 'w') as out:
                subprocess.run(
                    ['cbmc', src_path, '--unwind', str(UNWIND), '--timeout', '30',
                     '--xml-ui', '--bounds-check', '--signed-overflow-check',
                     '--pointer-check', '--div-by-zero-check', '--nil-pointer-check'],
                     stdout=out, stderr=subprocess.STDOUT, timeout=35
                )
        except subprocess.TimeoutExpired:
            print(f"  program {pid}: TIMEOUT")
        if os.path.exists(src_path):
            os.remove(src_path)

    print(f"CBMC batch complete. XML output in {XML_DIR}/")

if __name__ == "__main__":
    run_cbmc()
