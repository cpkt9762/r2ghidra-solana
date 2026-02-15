import argparse
import pathlib
import shutil
import subprocess

try:
    from colorama import Fore, Style, init
except ImportError:
    class _NoColor:
        def __getattr__(self, _name):
            return ""

    Fore = _NoColor()
    Style = _NoColor()

    def init(*_args, **_kwargs):
        return None

from build_crate import build_crate

init()

ROOT_DIR = pathlib.Path(__file__).resolve().parent
CRATES_DIR = ROOT_DIR / "crates"
RLIBS_DIR = ROOT_DIR / "rlibs"
DEFAULT_SOLANA_VERSION = "1.18.26"
DEFAULT_FALLBACK_COMPILER_VERSION = "1.18.16"


def resolve_versions_file(path_str: str):
    path = pathlib.Path(path_str)
    if path.exists():
        return path
    alt = ROOT_DIR / path_str
    if alt.exists():
        return alt
    raise FileNotFoundError(f"versions file not found: {path_str}")


def parse_versions(args):
    if args.versions_file:
        versions = []
        with open(resolve_versions_file(args.versions_file), "r") as f:
            for line in f:
                v = line.strip()
                if not v:
                    continue
                if v.startswith("v"):
                    versions.append(v[1:])
                else:
                    versions.append(v)
        return versions
    if args.version:
        return [args.version.strip()]
    raise ValueError("Either --versions-file or --version must be provided")


def needs_compiler_fallback(status: str):
    hints = (
        "requires rustc",
        "feature `edition2024` is required",
        "older than the `2024` edition",
        "lock file version 4 requires `-Znext-lockfile-bump`",
        "unknown feature `proc_macro_span_shrink`",
    )
    return any(h in status for h in hints)


def run_cleanup_solana(version: str):
    subprocess.run(
        ["bash", str(ROOT_DIR / "remove-solana.sh"), version],
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--solana-version",
        default=DEFAULT_SOLANA_VERSION,
        help="Default compiler Solana version for non-solana-program crates",
    )
    parser.add_argument(
        "--compiler-solana-version",
        help="Force one compiler Solana version for all crates",
    )
    parser.add_argument(
        "--fallback-compiler-solana-version",
        default=DEFAULT_FALLBACK_COMPILER_VERSION,
        help="Fallback compiler Solana version when rust/cargo compatibility fails",
    )
    parser.add_argument(
        "--disable-compiler-fallback",
        action="store_true",
        help="Do not retry failed builds with fallback compiler version",
    )
    parser.add_argument(
        "--platform-tools-version",
        help="Pass --tools-version to cargo-build-sbf (example: v1.48)",
    )
    parser.add_argument("--cleanup-target", action="store_true", help="Delete crate target/ after copying rlib")
    parser.add_argument("--cleanup-solana", action="store_true", help="Run remove-solana.sh after each version")
    parser.add_argument("--crate", required=True, help="The crate to get the rlib from")
    parser.add_argument("--versions-file", help="The file containing versions to build")
    parser.add_argument("--version", help="Single crate version to build")
    args = parser.parse_args()

    versions = parse_versions(args)
    crate = args.crate
    success_count = 0

    print(f"{Fore.BLUE}Getting rlibs for {crate} from {len(versions)} versions{Style.RESET_ALL}")
    for version in versions:
        version = version.strip()
        try:
            if args.compiler_solana_version:
                compiler_versions = [args.compiler_solana_version]
            elif crate == "solana-program":
                compiler_versions = [version]
            else:
                compiler_versions = [args.solana_version]

            if (not args.disable_compiler_fallback) and args.fallback_compiler_solana_version:
                if args.fallback_compiler_solana_version not in compiler_versions:
                    compiler_versions.append(args.fallback_compiler_solana_version)

            built = False
            last_status = ""
            used_compiler = None
            for i, compiler_version in enumerate(compiler_versions):
                used_compiler = compiler_version
                print(
                    f"{Fore.BLUE}Building {crate}:{version}{Style.RESET_ALL} "
                    f"with compiler Solana {compiler_version} "
                    f"(attempt {i + 1}/{len(compiler_versions)})"
                )
                ok, status = build_crate(
                    crate,
                    version,
                    compiler_version,
                    only_rlib=True,
                    tools_version=args.platform_tools_version,
                )
                last_status = status
                if ok:
                    built = True
                    break
                if i + 1 < len(compiler_versions) and not needs_compiler_fallback(status):
                    break

            if not built:
                print(
                    f"{Fore.RED}Error building {crate}:{version} with compilers "
                    f"{compiler_versions}: build failed{Style.RESET_ALL}"
                )
                continue

            rlib_path = (
                CRATES_DIR / f"{crate}-{version}" / "target" / "sbf-solana-solana" / "release" / f"lib{crate.replace('-', '_')}.rlib"
            )
            if not rlib_path.exists():
                print(f"{Fore.RED}Rlib for {crate}:{version} not found at {rlib_path}{Style.RESET_ALL}")
                continue

            target_path = RLIBS_DIR / crate / f"{crate.replace('-', '_')}-{version}.rlib"
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(rlib_path, target_path)
            print(
                f"{Fore.GREEN}Rlib for {crate}:{version} saved to {target_path} "
                f"(compiler={used_compiler}){Style.RESET_ALL}"
            )
            success_count += 1

            if args.cleanup_target:
                target_dir = CRATES_DIR / f"{crate}-{version}" / "target"
                if target_dir.exists():
                    shutil.rmtree(target_dir)

            if args.cleanup_solana and used_compiler:
                run_cleanup_solana(used_compiler)

        except KeyboardInterrupt:
            print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"{Fore.RED}Error building {crate}:{version}: {e}{Style.RESET_ALL}")
            continue

    total = len(versions)
    print(f"{Fore.BLUE}Done: {success_count}/{total} versions produced rlibs{Style.RESET_ALL}")
    if success_count == total:
        raise SystemExit(0)
    raise SystemExit(1)


if __name__ == "__main__":
    main()
