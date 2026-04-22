import yaml
from pathlib import Path
import format_helper

def load_yaml(path: str | Path) -> dict:
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if path.is_dir():
        raise IsADirectoryError(f"Expected a file, got a directory: {path}")

    ext = path.suffix.lower()
    if ext != ".yaml":
        raise ValueError(
            f"Unsupported file type '{ext}'. "
            f"Supported: .yaml"
        )

    if path.stat().st_size == 0:
        raise ValueError(f"File is empty: {path}")

    with open(path, 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)

    format_helper.progress(f"{len(data.keys())} KDEs loaded from {path}")
    return data


def detect_differences_names(data1: dict, filename1: str, data2: dict, filename2: str):
    differences = []
    for element in data1.keys():
        if element not in data2.keys() or data1[element]["name"] not in [data2[element]["name"] for element in data2.keys()]:
            differences.append(f"{data1[element]["name"]},ABSENT-IN-{filename2},PRESENT-IN-{filename1}")
    for element in data2.keys():
        if element not in data1.keys() or data2[element]["name"] not in [data1[element]["name"] for element in data1.keys()]:
            differences.append(f"{data2[element]["name"]},ABSENT-IN-{filename1},PRESENT-IN-{filename2}")
    format_helper.progress(f"{len(differences)} differences detected between {filename1} and {filename2}")
    return differences if len(differences) > 0 else "NO DIFFERENCES IN REGARDS TO ELEMENT NAMES"

def detect_differences_requirements(data1: dict, filename1: str, data2: dict, filename2: str):
    differences = []
    for element in data1.keys():
        if element not in data2.keys() or data1[element]["name"] not in [data2[element]["name"] for element in data2.keys()]:
            differences.append(f"{data1[element]["name"]},ABSENT-IN-{filename2},PRESENT-IN-{filename1},NA")
        else:
            for requirement in data1[element]["requirements"]:
                if requirement not in data2[element]["requirements"]:
                    differences.append(f"{data1[element]["name"]},ABSENT-IN-{filename2},PRESENT-IN-{filename1},{requirement}")
    for element in data2.keys():
        if element not in data1.keys() or data2[element]["name"] not in [data1[element]["name"] for element in data1.keys()]:
            differences.append(f"{data2[element]["name"]},ABSENT-IN-{filename1},PRESENT-IN-{filename2},NA")
        else:
            for requirement in data2[element]["requirements"]:
                if requirement not in data1[element]["requirements"]:
                    differences.append(f"{data1[element]["name"]},ABSENT-IN-{filename1},PRESENT-IN-{filename2},{requirement}")
    format_helper.progress(f"{len(differences)} element differences (including requirements) detected between {filename1} and {filename2}")
    return differences if len(differences) > 0 else "NO DIFFERENCES IN REGARDS TO ELEMENT REQUIREMENTS"

if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(
        description="Compare YAML files."
    )
    parser.add_argument("yaml1", help="Path to first YAML file")
    parser.add_argument("yaml2", help="Path to second YAML file")
    parser.add_argument(
        "--output-dir", default="comparator_outputs",
        help="Directory for TEXT output files (default: comparator_outputs)"
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    load_yaml(args.yaml1)
    differences_names = detect_differences_names(load_yaml(args.yaml1), Path(args.yaml1).name, load_yaml(args.yaml2), Path(args.yaml2).name)
    differences_requirements = detect_differences_requirements(load_yaml(args.yaml1), Path(args.yaml1).name, load_yaml(args.yaml2), Path(args.yaml2).name)

    with open(Path(args.output_dir) / Path("kde_name_diff.txt"), 'w', encoding='utf-8') as outfile:
        outfile.write('\n'.join(differences_names))
        format_helper.progress(f"Successfully written {len(differences_names)} lines to {Path(args.output_dir) / Path("kde_name_diff.txt")}")
    with open(Path(args.output_dir) / Path("kde_name_req_diff.txt"), 'w', encoding='utf-8') as outfile:
        format_helper.progress(f"Successfully written {len(differences_names)} lines to {Path(args.output_dir) / Path("kde_name_req_diff.txt")}")
        outfile.write('\n'.join(differences_requirements))