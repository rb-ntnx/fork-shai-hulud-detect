#!/usr/bin/env python3
"""Demo of new relative path display"""

from pathlib import Path

# Simulate results with different path structures
test_cases = [
    ("/Users/rahul.bhooteshwar/dev/eslint", "/Users/rahul.bhooteshwar/dev"),
    ("/Users/rahul.bhooteshwar/dev/ubertower-ultimate-dashboard", "/Users/rahul.bhooteshwar/dev"),
    ("/Users/rahul.bhooteshwar/dev/ubertower-ultimate-dashboard/services/source_code", "/Users/rahul.bhooteshwar/dev"),
    ("/Users/rahul.bhooteshwar/dev/panacea-orchestrator", "/Users/rahul.bhooteshwar/dev"),
]

print("New Progress Output Format:\n")
print("=" * 80)

for i, (project_path, root_dir) in enumerate(test_cases, 1):
    project_path = Path(project_path)
    root_dir = Path(root_dir)

    try:
        relative_path = project_path.relative_to(root_dir)
        display_path = str(relative_path)
    except ValueError:
        display_path = str(project_path)

    # Simulate output
    status = "CLEAN"
    color = "\033[0;32m"
    reset = "\033[0m"

    print(f"[{i}/4] (25.0%) {color}{status}{reset} - {display_path} (84.4s)")

print("=" * 80)
print("\n✅ Now you can see the full relative path!")
print("   - Simple projects: eslint")
print("   - Nested projects: ubertower-ultimate-dashboard/services/source_code")

