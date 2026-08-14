from collections import Counter
import json
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parents[1] / "data" / "raw" /"diversevul.json"

print(f"Loading DiverseVul from {DATASET_PATH}...")

rows = 0
columns = None
first_example = None
label_counts = Counter()
cwe_counts = Counter()

with DATASET_PATH.open("r", encoding="utf-8") as dataset_file:
    for line in dataset_file:
        if not line.strip():
            continue

        example = json.loads(line)
        rows += 1

        if columns is None:
            columns = list(example.keys())
            first_example = example

        label = example.get("target")
        if label is not None:
            label_counts.update([label])

        cwes = example.get("cwe")
        if isinstance(cwes, list):
            cwe_counts.update(cwe for cwe in cwes if cwe is not None)
        elif cwes is not None:
            cwe_counts.update([cwes])

print("\n=== DATASET STRUCTURE ===")
print("Rows:", rows)
print("Columns:", columns)

print("\nLabel distribution:")
for label, count in label_counts.most_common():
    print(f"{label}    {count}")

print("\nCWE distribution:")
for cwe, count in cwe_counts.most_common(10):
    print(f"{cwe}    {count}")

print("\nExample:")
for key, value in first_example.items(): # type: ignore
    print(f"{key}: {value}")
