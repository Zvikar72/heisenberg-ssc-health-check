# heisenberg/sbom_utils.py

import os
import sys
import subprocess
import shutil

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def write_repos_file(target_dir: str, repos_list: list[str], repos_file_name: str) -> str:
    ensure_dir(target_dir)
    path = os.path.join(target_dir, repos_file_name)
    with open(path, "w", encoding="utf-8") as f:
        for r in repos_list:
            f.write(f"{r}\n")
    print(f"[INFO] Wrote repo list to {path}")
    return path

def load_repos_from_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def run_github_sbom_script(sbom_dir: str, org: str, repos_file_name: str) -> bool:
    ensure_dir(sbom_dir)
    cmd = [
        sys.executable, "-m", "heisenberg.github_sbom",
        "-a",
        "--org", org,
        "--repos-file", repos_file_name,
        "-out", ".",
    ]
    print(f"[INFO] Running SBOM generator: {' '.join(cmd)} (cwd={sbom_dir})")
    proc = subprocess.run(cmd, cwd=sbom_dir, text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout)
    if proc.returncode != 0:
        print("[ERROR] github_sbom module failed")
        if proc.stderr:
            print("STDERR:", proc.stderr)
        return False
    return True

def iter_selected_sboms(sbom_dir: str, selected_repos: list[str]):
    for repo in selected_repos:
        path = os.path.join(sbom_dir, f"{repo}_sbom.csv")
        if os.path.exists(path):
            yield repo, path
        else:
            print(f"[WARN] SBOM not found for repo '{repo}': {path}")

def cleanup_sbom_dir(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
            print(f"[INFO] Cleaned up SBOM directory: {path}")
    except Exception as e:
        print(f"[WARN] Failed to remove SBOM directory {path}: {e}") 
