#!/usr/bin/env python3
"""
A4 Injection System

Applies A4 patches to RISC Zero source files, similar to how Arguzz does injection.
This allows A4 hooks to survive repository rebuilds.

Usage:
    python3 -m a4.injection.inject --risc0-path /path/to/risc0
    
Or from the a4 directory:
    python3 injection/inject.py --risc0-path ../workspace/risc0-modified
"""

import argparse
import sys
from pathlib import Path


def apply_patch(file_path: Path, search: str, replace: str, description: str) -> bool:
    """Apply a single patch to a file.
    
    Returns True if patch was applied, False if already applied or not needed.
    """
    if not file_path.exists():
        print(f"  ERROR: File not found: {file_path}")
        return False
    
    content = file_path.read_text()
    
    # Check if already patched (replacement text exists)
    if ">>> A4:" in content or "A4 PREFLIGHT INSPECTION" in content:
        print(f"  SKIP: {description} (already patched)")
        return True
    
    # Check if the search pattern exists
    if search not in content:
        print(f"  ERROR: {description} - injection point not found")
        print(f"         Looking for: {search[:50]}...")
        return False
    
    # Apply the patch
    new_content = content.replace(search, replace, 1)
    
    if new_content == content:
        print(f"  ERROR: {description} - replacement failed")
        return False
    
    file_path.write_text(new_content)
    print(f"  OK: {description}")
    return True


def inject_a4(risc0_path: Path) -> bool:
    """Apply all A4 patches to the RISC Zero repository.
    
    Returns True if all patches were successful.
    """
    print(f"A4 Injection: {risc0_path}")
    print("=" * 60)
    
    success = True
    
    # Patch 1: mod.rs - A4 inspection and mutation hooks
    from a4.injection.patches.mod_rs_patch import get_patch
    mod_rs_path = risc0_path / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "witgen" / "mod.rs"
    
    patch = get_patch()
    if not apply_patch(mod_rs_path, patch['search'], patch['replace'], "mod.rs: A4 hooks"):
        success = False
    
    print("=" * 60)
    if success:
        print("A4 injection complete. Rebuild risc0 to apply changes:")
        print(f"  cd {risc0_path} && cargo build --release")
    else:
        print("A4 injection failed. Check errors above.")
    
    return success


def check_a4(risc0_path: Path) -> bool:
    """Check if A4 patches are applied.
    
    Returns True if all patches are present.
    """
    print(f"A4 Check: {risc0_path}")
    print("=" * 60)
    
    mod_rs_path = risc0_path / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "witgen" / "mod.rs"
    
    if not mod_rs_path.exists():
        print(f"  ERROR: mod.rs not found at {mod_rs_path}")
        return False
    
    content = mod_rs_path.read_text()
    
    if ">>> A4:" in content or "A4 PREFLIGHT INSPECTION" in content:
        print("  OK: mod.rs has A4 hooks")
        return True
    else:
        print("  MISSING: mod.rs does not have A4 hooks")
        print("  Run: python3 -m a4.injection.inject --risc0-path " + str(risc0_path))
        return False


def revert_a4(risc0_path: Path) -> bool:
    """Revert A4 patches using git.
    
    Returns True if successful.
    """
    import subprocess
    
    print(f"A4 Revert: {risc0_path}")
    print("=" * 60)
    
    mod_rs_path = risc0_path / "risc0" / "circuit" / "rv32im" / "src" / "prove" / "witgen" / "mod.rs"
    
    try:
        result = subprocess.run(
            ["git", "checkout", "HEAD", "--", str(mod_rs_path)],
            cwd=risc0_path,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"  OK: Reverted mod.rs")
            return True
        else:
            print(f"  ERROR: git checkout failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def main():
    # Add parent directory to path so we can import a4 modules
    script_dir = Path(__file__).parent
    a4_dir = script_dir.parent
    repo_root = a4_dir.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    
    parser = argparse.ArgumentParser(description='A4 Injection System')
    parser.add_argument('--risc0-path', type=str, required=True,
                        help='Path to RISC Zero repository')
    parser.add_argument('--check', action='store_true',
                        help='Check if patches are applied (do not modify)')
    parser.add_argument('--revert', action='store_true',
                        help='Revert patches using git checkout')
    
    args = parser.parse_args()
    risc0_path = Path(args.risc0_path).resolve()
    
    if not risc0_path.exists():
        print(f"ERROR: RISC Zero path does not exist: {risc0_path}")
        sys.exit(1)
    
    if args.revert:
        success = revert_a4(risc0_path)
    elif args.check:
        success = check_a4(risc0_path)
    else:
        success = inject_a4(risc0_path)
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
