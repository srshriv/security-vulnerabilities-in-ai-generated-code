import subprocess
import datetime

OUTPUT_FILE = "../tools_versions.txt"

tools = [
    ["python3", "--version"],
    ["clang", "--version"],
    ["gcc", "--version"],
    ["semgrep", "--version"],
    ["bandit", "--version"],
    ["eslint", "--version"],
    ["flawfinder", "--version"],
    ["cbmc", "--version"],
    ["klee", "--version"],
    ["afl-clang-fast", "--version"],
    ["codeql", "--version"],
]

def log_versions():
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"Toolchain Version Log - {datetime.datetime.now()}\n")
        f.write("-" * 40 + "\n")

        for cmd in tools:
            tool_name = cmd[0]
            f.write(f"Checking: {tool_name}\n")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                output = (result.stdout.strip() or result.stderr.strip())
                if result.returncode == 0:
                    f.write(f"{output}\n")
                else:
                    f.write(f"ERROR: installed but exited non-zero.\n{output}\n")
            except FileNotFoundError:
                f.write(f"MISSING: {tool_name} not found on PATH.\n")
            except PermissionError:
                f.write(f"BROKEN: {tool_name} found on PATH but not executable.\n")
            except subprocess.TimeoutExpired:
                f.write(f"TIMEOUT: {tool_name} did not respond within 5s.\n")

            f.write("-" * 40 + "\n")

    print(f"Successfully generated {OUTPUT_FILE}")

if __name__ == "__main__":
    log_versions()
