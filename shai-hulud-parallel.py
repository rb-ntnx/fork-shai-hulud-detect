#!/usr/bin/env python3
"""
Shai-Hulud Parallel Scanner
Scans multiple projects in parallel using the bash scanner as subprocess workers

Usage:
    ./shai-hulud-parallel.py /path/to/projects-directory
    ./shai-hulud-parallel.py --workers 16 /path/to/projects-directory
    ./shai-hulud-parallel.py --slim /path/to/projects-directory
"""

import argparse
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional
import time


@dataclass
class ScanResult:
    """Result from scanning a single project"""
    project_path: str
    exit_code: int
    duration: float
    high_risk: int = 0
    medium_risk: int = 0
    low_risk: int = 0
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None
    findings: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        """Human-readable status"""
        if self.error:
            return "ERROR"
        elif self.exit_code == 0:
            return "CLEAN"
        elif self.exit_code == 1:
            return "HIGH RISK"
        elif self.exit_code == 2:
            return "MEDIUM RISK"
        else:
            return f"UNKNOWN ({self.exit_code})"

    @property
    def total_issues(self) -> int:
        """Total issues found"""
        return self.high_risk + self.medium_risk


def find_projects(root_dir: Path, max_depth: int = 10, verbose: bool = False) -> tuple:
    """
    Find all project directories (containing package.json or lockfiles)
    
    Uses os.walk with directory pruning for fast discovery (30-60x faster than rglob)
    
    Args:
        root_dir: Root directory to search
        max_depth: Maximum depth to search (default: 10, use 0 for unlimited)
        verbose: Print discovery statistics
    
    Returns:
        Tuple of (list of project directories, statistics dict)
    """
    import os

    projects = set()

    # Directories to skip (beyond just node_modules)
    skip_dirs = {
        'node_modules', '.git', 'dist', 'build', '.cache',
        '.next', '.nuxt', 'coverage', '.venv', 'venv',
        '__pycache__', '.pytest_cache', '.tox',
        'temp', '.temp', '.vscode', '.idea', 'out', '.turbo',
        '.gradle', 'target', 'bin', 'obj', 'logs', '.logs'
    }

    # Statistics
    stats = {
        'total_found': 0,
        'skipped_excluded': 0,
        'skipped_depth': 0,
        'included': 0,
        'dirs_scanned': 0
    }

    # Fast walk with early directory pruning (avoids traversing node_modules entirely)
    for dirpath, dirnames, filenames in os.walk(root_dir):
        stats['dirs_scanned'] += 1

        # Show progress every 100 directories (not in verbose mode to avoid clutter)
        if not verbose and stats['dirs_scanned'] % 100 == 0:
            print(f"\r   Scanning directories... {stats['dirs_scanned']} scanned, {stats['total_found']} projects found", end='', flush=True)

        # Prune excluded directories BEFORE traversing them (critical for performance!)
        original_count = len(dirnames)
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        stats['skipped_excluded'] += (original_count - len(dirnames))

        # Check if package.json exists in this directory
        if 'package.json' in filenames:
            stats['total_found'] += 1
            project_path = Path(dirpath)

            # Check depth (0 = unlimited)
            if max_depth > 0:
                try:
                    depth = len(project_path.relative_to(root_dir).parts)
                    if depth > max_depth:
                        stats['skipped_depth'] += 1
                        if verbose:
                            print(f"  Skipping (depth {depth} > {max_depth}): {project_path}")
                        continue
                except ValueError:
                    # Path not relative to root_dir, skip
                    continue

            projects.add(project_path)
            stats['included'] += 1

            if verbose:
                print(f"  Found: {project_path}")

    # Clear progress line if it was shown
    if not verbose and stats['dirs_scanned'] > 0:
        print(f"\r   Scanning complete: {stats['dirs_scanned']} directories scanned, {stats['total_found']} projects found" + " " * 20)

    return sorted(projects), stats


def parse_summary(output: str) -> tuple:
    """
    Parse scanner output to extract risk counts and findings
    
    Returns:
        (high_risk, medium_risk, low_risk, findings_list)
    """
    high_risk = 0
    medium_risk = 0
    low_risk = 0
    findings = []

    lines = output.split('\n')
    in_high_risk_section = False
    in_medium_risk_section = False
    in_hooks_section = False

    for i, line in enumerate(lines):
        # Parse counts
        if 'High Risk:' in line:
            try:
                high_risk = int(line.split(':')[1].strip())
            except (IndexError, ValueError):
                pass
        elif 'Medium Risk:' in line:
            try:
                medium_risk = int(line.split(':')[1].strip())
            except (IndexError, ValueError):
                pass
        elif 'Low Risk' in line and 'informational' in line:
            try:
                low_risk = int(line.split(':')[1].strip().split()[0])
            except (IndexError, ValueError):
                pass

        # Track sections
        if 'HIGH RISK: Compromised packages' in line:
            in_high_risk_section = True
            in_medium_risk_section = False
            in_hooks_section = False
        elif 'HIGH RISK: Suspicious install hooks' in line:
            in_hooks_section = True
            in_high_risk_section = False
            in_medium_risk_section = False
        elif 'MEDIUM RISK: Suspicious package versions' in line:
            in_medium_risk_section = True
            in_high_risk_section = False
            in_hooks_section = False
        elif line.strip().startswith('=====') or 'SUMMARY:' in line:
            in_high_risk_section = False
            in_medium_risk_section = False
            in_hooks_section = False

        # Extract findings
        if (in_high_risk_section or in_medium_risk_section or in_hooks_section):
            stripped = line.strip()
            if stripped.startswith('- Package:'):
                # Extract package info
                pkg_info = stripped.replace('- Package:', '').strip()
                findings.append(pkg_info)
            elif stripped.startswith('- Hook:'):
                # Extract hook info
                hook_info = stripped.replace('- Hook:', '').strip()
                findings.append(f"Install hook: {hook_info}")

    return high_risk, medium_risk, low_risk, findings


def scan_project(project_path: Path, scanner_script: Path, timeout: int = 300) -> ScanResult:
    """
    Scan a single project using the bash scanner
    
    Args:
        project_path: Path to project directory
        scanner_script: Path to bash scanner script
        timeout: Timeout in seconds
    
    Returns:
        ScanResult with findings
    """
    start_time = time.time()

    try:
        result = subprocess.run(
            [str(scanner_script), str(project_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise exception on non-zero exit
        )

        duration = time.time() - start_time
        high_risk, medium_risk, low_risk, findings = parse_summary(result.stdout)

        return ScanResult(
            project_path=str(project_path),
            exit_code=result.returncode,
            duration=duration,
            high_risk=high_risk,
            medium_risk=medium_risk,
            low_risk=low_risk,
            stdout=result.stdout,
            stderr=result.stderr,
            findings=findings
        )

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return ScanResult(
            project_path=str(project_path),
            exit_code=-1,
            duration=duration,
            error=f"Timeout after {timeout}s"
        )

    except Exception as e:
        duration = time.time() - start_time
        return ScanResult(
            project_path=str(project_path),
            exit_code=-1,
            duration=duration,
            error=str(e)
        )


def print_progress(completed: int, total: int, result: ScanResult, root_dir: Path = None):
    """Print progress update"""
    percentage = (completed / total) * 100
    status_color = {
        "CLEAN": "\033[0;32m",      # Green
        "HIGH RISK": "\033[0;31m",   # Red
        "MEDIUM RISK": "\033[1;33m", # Yellow
        "ERROR": "\033[0;31m",       # Red
    }
    color = status_color.get(result.status, "\033[0;34m")  # Blue default
    reset = "\033[0m"

    # Show relative path if root_dir provided, otherwise just project name
    project_path = Path(result.project_path)
    if root_dir:
        try:
            relative_path = project_path.relative_to(root_dir)
            display_path = str(relative_path)
        except ValueError:
            # If path is not relative to root_dir, show full path
            display_path = str(project_path)
    else:
        display_path = project_path.name

    print(f"[{completed}/{total}] ({percentage:.1f}%) {color}{result.status}{reset} - {display_path} ({result.duration:.1f}s)")


def generate_report(results: List[ScanResult], output_format: str = "text") -> str:
    """Generate summary report"""

    # Calculate totals
    total_projects = len(results)
    clean_projects = sum(1 for r in results if r.exit_code == 0)
    high_risk_projects = sum(1 for r in results if r.exit_code == 1 or r.high_risk > 0)
    medium_risk_projects = sum(1 for r in results if r.exit_code == 2 or r.medium_risk > 0)
    error_projects = sum(1 for r in results if r.error)

    total_high_risk = sum(r.high_risk for r in results)
    total_medium_risk = sum(r.medium_risk for r in results)
    total_duration = sum(r.duration for r in results)

    if output_format == "json":
        return json.dumps({
            "summary": {
                "total_projects": total_projects,
                "clean_projects": clean_projects,
                "high_risk_projects": high_risk_projects,
                "medium_risk_projects": medium_risk_projects,
                "error_projects": error_projects,
                "total_high_risk_issues": total_high_risk,
                "total_medium_risk_issues": total_medium_risk,
                "total_duration_seconds": round(total_duration, 2)
            },
            "projects": [
                {
                    "path": r.project_path,
                    "status": r.status,
                    "high_risk": r.high_risk,
                    "medium_risk": r.medium_risk,
                    "duration": round(r.duration, 2),
                    "error": r.error
                }
                for r in results
            ]
        }, indent=2)

    # Text format
    blue = "\033[0;34m"
    red = "\033[0;31m"
    yellow = "\033[1;33m"
    green = "\033[0;32m"
    reset = "\033[0m"

    report = []
    report.append("")
    report.append(f"{blue}{'=' * 60}{reset}")
    report.append(f"{blue}        SHAI-HULUD PARALLEL SCAN REPORT{reset}")
    report.append(f"{blue}{'=' * 60}{reset}")
    report.append("")
    report.append(f"📊 {blue}Summary:{reset}")
    report.append(f"   Total Projects Scanned: {total_projects}")
    report.append(f"   {green}✓ Clean Projects: {clean_projects}{reset}")
    report.append(f"   {red}⚠ Projects with HIGH RISK: {high_risk_projects}{reset}")
    report.append(f"   {yellow}⚠ Projects with MEDIUM RISK: {medium_risk_projects}{reset}")
    if error_projects > 0:
        report.append(f"   {red}✗ Projects with Errors: {error_projects}{reset}")
    report.append("")
    report.append(f"🔍 {blue}Total Issues Found:{reset}")
    report.append(f"   {red}High Risk Issues: {total_high_risk}{reset}")
    report.append(f"   {yellow}Medium Risk Issues: {total_medium_risk}{reset}")
    report.append("")
    report.append(f"⏱️  {blue}Performance:{reset}")
    report.append(f"   Total Duration: {total_duration:.1f}s")
    report.append(f"   Average per Project: {total_duration/total_projects:.1f}s")
    report.append("")

    # List problematic projects
    if high_risk_projects > 0:
        report.append(f"{red}🚨 HIGH RISK Projects:{reset}")
        for result in sorted(results, key=lambda r: r.high_risk, reverse=True):
            if result.exit_code == 1 or result.high_risk > 0:
                issues_text = f"{result.high_risk} issue(s)" if result.high_risk > 0 else "detected"
                report.append(f"   - {Path(result.project_path).name}: {issues_text}")
                report.append(f"     Path: {result.project_path}")
                # Show findings if available
                if result.findings:
                    report.append(f"     Findings:")
                    for finding in result.findings[:5]:  # Limit to first 5 findings
                        report.append(f"       • {finding}")
                    if len(result.findings) > 5:
                        report.append(f"       • ... and {len(result.findings) - 5} more")
        report.append("")

    if medium_risk_projects > 0:
        report.append(f"{yellow}⚠️  MEDIUM RISK Projects:{reset}")
        for result in sorted(results, key=lambda r: r.medium_risk, reverse=True):
            if result.exit_code == 2 or result.medium_risk > 0:
                issues_text = f"{result.medium_risk} issue(s)" if result.medium_risk > 0 else "detected"
                report.append(f"   - {Path(result.project_path).name}: {issues_text}")
                report.append(f"     Path: {result.project_path}")
                # Show findings if available
                if result.findings:
                    report.append(f"     Findings:")
                    for finding in result.findings[:5]:  # Limit to first 5 findings
                        report.append(f"       • {finding}")
                    if len(result.findings) > 5:
                        report.append(f"       • ... and {len(result.findings) - 5} more")
        report.append("")

    if error_projects > 0:
        report.append(f"{red}✗ Projects with Errors:{reset}")
        for result in results:
            if result.error:
                report.append(f"   - {Path(result.project_path).name}: {result.error}")
        report.append("")

    report.append(f"{blue}{'=' * 60}{reset}")

    return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Scan multiple projects in parallel for Shai-Hulud supply chain attacks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all projects in a directory with default settings
  %(prog)s /path/to/projects

  # Use 16 parallel workers
  %(prog)s --workers 16 /path/to/projects

  # Use slim scanner for faster scanning
  %(prog)s --slim /path/to/projects

  # Unlimited depth for deeply nested projects
  %(prog)s --max-depth 0 /path/to/projects

  # Output results as JSON
  %(prog)s --format json /path/to/projects > results.json

  # Save detailed output for each project
  %(prog)s --save-output /path/to/projects
        """
    )

    parser.add_argument(
        "directory",
        type=Path,
        help="Root directory containing projects to scan"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="Number of parallel workers (default: 8)"
    )

    parser.add_argument(
        "--slim",
        action="store_true",
        help="Use slim scanner (faster, package checks only)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout per project in seconds (default: 300)"
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=10,
        help="Maximum directory depth to search for projects (default: 10, use 0 for unlimited)"
    )

    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--save-output",
        action="store_true",
        help="Save detailed output for each project to files"
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("scan-results"),
        help="Directory to save detailed outputs (default: scan-results)"
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed project discovery information"
    )

    args = parser.parse_args()

    # Validate directory
    if not args.directory.exists():
        print(f"Error: Directory '{args.directory}' does not exist", file=sys.stderr)
        sys.exit(1)

    if not args.directory.is_dir():
        print(f"Error: '{args.directory}' is not a directory", file=sys.stderr)
        sys.exit(1)

    # Find scanner script
    script_dir = Path(__file__).parent
    scanner_script = script_dir / ("shai-hulud-slim.sh" if args.slim else "shai-hulud-detector.sh")

    if not scanner_script.exists():
        print(f"Error: Scanner script not found: {scanner_script}", file=sys.stderr)
        sys.exit(1)

    # Find projects
    print(f"🔍 Discovering projects in {args.directory}...")
    projects, stats = find_projects(args.directory, max_depth=args.max_depth, verbose=args.verbose)

    if not projects:
        print("No projects found (no package.json files detected)")
        if args.verbose and stats['total_found'] > 0:
            print(f"   Found {stats['total_found']} package.json files, but all were excluded:")
            print(f"   - Skipped (in excluded dirs): {stats['skipped_excluded']}")
            print(f"   - Skipped (depth limit): {stats['skipped_depth']}")
        sys.exit(0)

    print(f"📦 Found {len(projects)} project(s) to scan")
    if args.verbose:
        print(f"   Total package.json files found: {stats['total_found']}")
        print(f"   Skipped (node_modules, .git, etc): {stats['skipped_excluded']}")
        print(f"   Skipped (depth > {args.max_depth}): {stats['skipped_depth']}")
        print(f"   Projects to scan: {stats['included']}")
    print(f"⚡ Using {args.workers} parallel workers")
    print(f"🔧 Scanner: {'slim' if args.slim else 'full'}")
    print("")

    # Create output directory if saving results
    if args.save_output:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        print(f"💾 Saving detailed outputs to: {args.output_dir}")
        print("")

    # Scan projects in parallel
    results = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        # Submit all jobs
        future_to_project = {
            executor.submit(scan_project, project, scanner_script, args.timeout): project
            for project in projects
        }

        # Process results as they complete
        for completed, future in enumerate(as_completed(future_to_project), 1):
            result = future.result()
            results.append(result)

            # Print progress
            if args.format == "text":
                print_progress(completed, len(projects), result, args.directory)

            # Save detailed output if requested
            if args.save_output:
                project_name = Path(result.project_path).name
                output_file = args.output_dir / f"{project_name}.txt"
                with open(output_file, 'w') as f:
                    f.write(f"Project: {result.project_path}\n")
                    f.write(f"Status: {result.status}\n")
                    f.write(f"Duration: {result.duration:.2f}s\n")
                    f.write(f"\n{'=' * 60}\n")
                    f.write(result.stdout)
                    if result.stderr:
                        f.write(f"\n\nSTDERR:\n{result.stderr}")
                    if result.error:
                        f.write(f"\n\nERROR: {result.error}")

    total_duration = time.time() - start_time

    # Generate and print report
    print("")
    report = generate_report(results, output_format=args.format)
    print(report)

    if args.format == "text":
        print(f"\n⏱️  Wall clock time: {total_duration:.1f}s")
        speedup = sum(r.duration for r in results) / total_duration
        print(f"⚡ Speedup: {speedup:.1f}x (vs sequential)")

    # Exit with appropriate code
    high_risk_count = sum(1 for r in results if r.high_risk > 0)
    medium_risk_count = sum(1 for r in results if r.medium_risk > 0)
    error_count = sum(1 for r in results if r.error)

    if high_risk_count > 0 or error_count > 0:
        sys.exit(1)
    elif medium_risk_count > 0:
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()

