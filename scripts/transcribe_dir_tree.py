import os
import argparse
import sys

def generate_tree(root_dir, verbose=False, exclude=None):
    """
    Generates a visual tree representation of the directory structure,
    excluding specified directories.

    Args:
        root_dir (str): The root directory to start the tree from.
        verbose (bool): If True, prints detailed debug statements.
        exclude (set): A set of directory names to exclude from the tree.

    Returns:
        str: A string representing the visual tree.
    """
    tree_lines = []

    def walk(dir_path, prefix=""):
        if verbose:
            print(f"Entering directory: {dir_path}", file=sys.stderr)

        try:
            entries = sorted(os.listdir(dir_path))
        except PermissionError:
            if verbose:
                print(f"Permission denied: {dir_path}", file=sys.stderr)
            return
        except Exception as e:
            if verbose:
                print(f"Error accessing {dir_path}: {e}", file=sys.stderr)
            return

        entries_count = len(entries)
        for index, entry in enumerate(entries):
            path = os.path.join(dir_path, entry)
            # Check if entry is in the exclusion list
            if exclude and entry in exclude:
                if verbose:
                    print(f"Excluding directory: {path}", file=sys.stderr)
                continue

            is_last = index == entries_count - 1
            connector = "└── " if is_last else "├── "
            tree_lines.append(prefix + connector + entry + ("/" if os.path.isdir(path) else ""))

            if verbose:
                print(f"Processing {'directory' if os.path.isdir(path) else 'file'}: {path}", file=sys.stderr)

            if os.path.isdir(path):
                extension = "    " if is_last else "│   "
                walk(path, prefix + extension)

    root_name = os.path.basename(os.path.abspath(root_dir)) or os.path.abspath(root_dir)
    tree_lines.append(root_name + "/")
    walk(root_dir)
    return "\n".join(tree_lines)

def main():
    parser = argparse.ArgumentParser(description="Generate a visual tree diagram of a directory structure.")
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Root directory of the project (default: current directory)"
    )
    parser.add_argument(
        "-o", "--output",
        default="directory_tree.txt",
        help="Output file name (default: directory_tree.txt)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Increase output verbosity"
    )
    args = parser.parse_args()

    root_dir = args.directory
    output_file = args.output
    verbose = args.verbose

    # Define a set of directory names to exclude
    default_excludes = {
        ".git",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        ".idea",
        ".vscode",
        ".mypy_cache",
        ".pytest_cache",
        "coverage",
        "logs",
        "tmp",
        "temp"
    }

    if verbose:
        print(f"Starting directory tree generation for: {root_dir}", file=sys.stderr)
        print(f"Excluding directories: {', '.join(default_excludes)}", file=sys.stderr)

    if not os.path.isdir(root_dir):
        print(f"Error: The directory '{root_dir}' does not exist or is not a directory.", file=sys.stderr)
        sys.exit(1)

    tree = generate_tree(root_dir, verbose=verbose, exclude=default_excludes)

    if verbose:
        print(f"Writing directory tree to '{output_file}'", file=sys.stderr)

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(tree)
        if verbose:
            print(f"Directory tree successfully written to '{output_file}'.", file=sys.stderr)
    except Exception as e:
        print(f"Error writing to file '{output_file}': {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
