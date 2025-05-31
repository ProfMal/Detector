import os
from analyse import analyse
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze a package for malicious behavior.")
    parser.add_argument(
        "--package_path",
        type=str,
        required=True,
        help="Path to the package source code directory."
    )
    parser.add_argument(
        "--workspace_path",
        type=str,
        required=True,
        help="Path to the workspace directory."
    )
    parser.add_argument(
        "--overwrite",
        action='store_true',
        help="Overwrite existing joern output."
    )

    args = parser.parse_args()
    package_name = os.path.basename(os.path.normpath(args.package_path))

    # dynamic support
    dynamic_support = True

    analyse(package_name, args.package_path, args.workspace_path, args.overwrite, dynamic_support, False)
