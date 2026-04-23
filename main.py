import argparse
import os
from pathlib import Path

parser = argparse.ArgumentParser(
    description="Use an LLM to automatically detect and analyze issues related to changing recurity requirements on a Kubernetes cluster."
)
parser.add_argument("document1", help="Path to first security requirements document")
parser.add_argument("document2", help="Path to second security requirements document")
parser.add_argument("kubescape_path", help="Path to Kubescape tool")
parser.add_argument("cluster_path", help="Path to target Kubernetes cluster")
parser.add_argument(
    "--output-dir", "-o", default="output",
    help="Directory for tool files (default: outputs)"
)
args = parser.parse_args()
os.makedirs(args.output_dir, exist_ok=True)
os.makedirs(Path(args.output_dir) / Path("extractor"), exist_ok=True)
os.makedirs(Path(args.output_dir) / Path("comparator"), exist_ok=True)
os.makedirs(Path(args.output_dir) / Path("executor"), exist_ok=True)

import extractor
extractor.extract(args.document1, args.document2, output_dir=Path(args.output_dir) / Path("extractor"))

import comparator
differences_names = comparator.detect_differences_names(comparator.load_yaml(Path(args.output_dir) / Path("extractor") / (Path(args.document1).stem + "-kdes.yaml")), (Path(args.document1).stem + "-kdes.yaml"), comparator.load_yaml(Path(args.output_dir) / Path("extractor") / (Path(args.document1).stem + "-kdes.yaml")), (Path(args.document1).stem + "-kdes.yaml"), Path(args.output_dir) / Path("comparator"))
differences_requirements = comparator.detect_differences_requirements(comparator.load_yaml(Path(args.output_dir) / Path("extractor") / (Path(args.document1).stem + "-kdes.yaml")), (Path(args.document1).stem + "-kdes.yaml"), comparator.load_yaml(Path(args.output_dir) / Path("extractor") / (Path(args.document1).stem + "-kdes.yaml")), (Path(args.document1).stem + "-kdes.yaml"), Path(args.output_dir) / Path("comparator"))

import executor
differences = executor.load_text(Path(args.output_dir) / Path("comparator/kde_name_req_diff.txt"))
executor.detect_controls(differences, Path(args.output_dir) / Path("executor"))
data = executor.kubescape_scan(args.kubescape_path, Path(args.output_dir) / Path("executor/controls.txt"), args.cluster_path, Path(args.output_dir) / Path("executor"))
executor.generate_csv(data, Path(args.output_dir) / Path("executor"))