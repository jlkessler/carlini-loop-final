import argparse
import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT_PATH = REPO_ROOT / "data" / "raw" / "diversevul.json"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "data" / "processed" / "ground_truth.json"


def build_ground_truth(
    input_path=DEFAULT_INPUT_PATH,
    output_path=DEFAULT_OUTPUT_PATH,
    project=None,
    target=None,
    commit_ids=None,
):
    commit_ids = set(commit_ids or [])
    matches = []

    with Path(input_path).open("r", encoding="utf-8") as dataset_file:
        for line in dataset_file:
            if not line.strip():
                continue

            entry = json.loads(line)

            if project is not None and entry.get("project") != project:
                continue

            if target is not None and entry.get("target") != target:
                continue

            if commit_ids and entry.get("commit_id") not in commit_ids:
                continue

            matches.append(entry)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    existing_entries = []
    if output_path.exists() and output_path.stat().st_size > 0:
        with output_path.open("r", encoding="utf-8") as ground_truth_file:
            existing_entries = json.load(ground_truth_file)

        if not isinstance(existing_entries, list):
            raise ValueError(f"{output_path} must contain a JSON array.")

    existing_entries.extend(matches)

    with output_path.open("w", encoding="utf-8") as ground_truth_file:
        json.dump(existing_entries, ground_truth_file, indent=2)
        ground_truth_file.write("\n")

    return len(matches)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Filter DiverseVul JSONL entries into a ground truth JSON file."
    )
    parser.add_argument(
        "--input-path",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Path to the DiverseVul JSONL file.",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Path to write the filtered JSON array.",
    )
    parser.add_argument(
        "--project",
        help="Only include entries from this project.",
    )
    parser.add_argument(
        "--target",
        type=int,
        choices=[0, 1],
        help="Only include entries with this target value.",
    )
    parser.add_argument(
        "--commit-id",
        action="append",
        dest="commit_ids",
        help="Only include this commit_id. Can be passed multiple times.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    count = build_ground_truth(
        input_path=args.input_path,
        output_path=args.output_path,
        project=args.project,
        target=args.target,
        commit_ids=args.commit_ids,
    )
    print(f"Appended {count} entries to {args.output_path}")
