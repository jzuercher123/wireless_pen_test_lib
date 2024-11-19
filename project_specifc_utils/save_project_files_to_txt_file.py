import os
import sys
import argparse
import logging


def setup_logging(verbosity):
    """
    Set up logging configuration based on verbosity level.
    """
    log_levels = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG
    }
    level = log_levels.get(verbosity, logging.DEBUG)

    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


def get_default_exclusions():
    """
    Returns a set of default directory names to exclude from processing.
    """
    return {
        '.venv', 'venv', 'env', 'ENV', '__pycache__', 'site-packages',
        'build', 'dist', '.git', '.svn', '.hg', '.idea', '.mypy_cache',
        '.pytest_cache', '.tox', '.eggs', 'egg-info'
    }


def collect_py_files(project_dir, output_file, exclude_dirs):
    """
    Walk through the project directory recursively, find all .py files
    excluding specified directories, and append their contents to the
    output_file with the filename as a comment.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            logging.info(f"Opened output file: {output_file} for writing.")
            for root, dirs, files in os.walk(project_dir):
                logging.debug(f"Walking through directory: {root}")

                # Modify dirs in-place to exclude unwanted directories
                dirs_to_remove = [d for d in dirs if d in exclude_dirs]
                for d in dirs_to_remove:
                    dirs.remove(d)
                    logging.debug(f"Excluded directory from traversal: {d}")

                for file in files:
                    if file.endswith('.py'):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, project_dir)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as infile:
                                content = infile.read()
                            # Write the filename as a comment
                            outfile.write(f"# {relative_path}\n")
                            logging.debug(f"Writing header for file: {relative_path}")
                            # Write the file content
                            outfile.write(content + "\n\n")
                            logging.info(f"Appended: {relative_path}")
                        except FileNotFoundError:
                            logging.error(f"File not found: {file_path}")
                        except PermissionError:
                            logging.error(f"Permission denied: {file_path}")
                        except Exception as e:
                            logging.error(f"Failed to read {file_path}: {e}")
        logging.info(f"Successfully wrote to output file: {output_file}")
    except PermissionError:
        logging.critical(f"Permission denied when trying to write to output file: {output_file}")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred while opening the output file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Recursively collect all user-created .py files in a project and append their contents to a single .txt file."
    )
    parser.add_argument(
        'project_directory',
        nargs='?',
        default='.',
        help='Path to the Python project directory (default: current directory)'
    )
    parser.add_argument(
        '-o', '--output',
        default='combined_py_files.txt',
        help='Name of the output .txt file (default: combined_py_files.txt)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=2,
        help='Increase output verbosity (e.g., -v, -vv, -vvv)'
    )
    parser.add_argument(
        '-e', '--exclude',
        nargs='*',
        default=[],
        help='Additional directories to exclude from processing (space-separated)'
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    project_dir = os.path.abspath(args.project_directory)
    output_file = os.path.abspath(args.output)

    logging.info(f"Project Directory: {project_dir}")
    logging.info(f"Output File: {output_file}\n")

    if not os.path.isdir(project_dir):
        logging.critical(f"The specified project directory does not exist or is not a directory: {project_dir}")
        sys.exit(1)

    # Combine default exclusions with user-specified exclusions
    exclude_dirs = get_default_exclusions().union(set(args.exclude))
    logging.debug(f"Directories to exclude: {exclude_dirs}")

    collect_py_files(project_dir, output_file, exclude_dirs)

    logging.info("\nAll .py files have been processed.")
    logging.info(f"Combined file saved as: {output_file}")


if __name__ == "__main__":
    main()
