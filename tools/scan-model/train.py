"""Train qalaa-scan's PE model on the EMBER dataset and export it.

    python train.py --train train_features_*.jsonl --test test_features.jsonl --out model.json [--fpr 0.01]

EMBER's data (raw features of ~1M Windows PE files, MIT licence) comes from
https://github.com/elastic/ember. Only the data is used: records are
converted with vectorize.ember_to_raw and vectorized by our own vectorize(),
the same layout qalaa-scan computes from a file. EMBER's AGPL code isn't
used or needed. Unlabelled records (label -1) are skipped.

Needs lightgbm and numpy (training only; nothing here ships with Qalaa).
The threshold is chosen on the test set for the requested false-positive
rate, and that rate is written into the model, so the app can state it.
Then sign it into a bundle with tools/scan-bundle/build_bundle.py.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vectorize import FEATURE_VERSION, VECTOR_LEN, ember_to_raw, vectorize


def records(paths: list[Path]) -> Iterator[tuple[list[float], int]]:
    for p in paths:
        with p.open() as f:
            for line in f:
                r = json.loads(line)
                if r.get("label") in (0, 1):
                    yield vectorize(ember_to_raw(r)), int(r["label"])


def convert_tree(tree: dict[str, Any]) -> dict[str, Any]:
    """One LightGBM dump_model() tree as a flat node list with children after parents."""
    nodes: list[dict[str, Any]] = []

    def walk(n: dict[str, Any]) -> int:
        i = len(nodes)
        if "leaf_value" in n:
            nodes.append({"leaf": float(n["leaf_value"])})
            return i
        if n.get("decision_type", "<=") != "<=":
            raise ValueError("only numerical <= splits are supported")
        nodes.append({})
        left = walk(n["left_child"])
        right = walk(n["right_child"])
        nodes[i] = {"f": int(n["split_feature"]), "t": float(n["threshold"]), "l": left, "r": right, "d": bool(n.get("default_left", True))}
        return i

    walk(tree["tree_structure"])
    return {"nodes": nodes}


def convert(dump: dict[str, Any], threshold: float, fpr: float | None, name: str) -> dict[str, Any]:
    if dump.get("objective", "binary").split()[0] != "binary":
        raise ValueError("expected a binary classifier")
    return {
        "format": 1,
        "feature_version": FEATURE_VERSION,
        "feature_len": VECTOR_LEN,
        "formats": ["pe"],
        "base": 0.0,
        "threshold": threshold,
        "fpr": fpr,
        "name": name,
        "trees": [convert_tree(t) for t in dump["tree_info"]],
    }


def threshold_for_fpr(scores: list[float], labels: list[int], fpr: float) -> float:
    benign = sorted((s for s, y in zip(scores, labels, strict=True) if y == 0), reverse=True)
    if not benign:
        return 0.5
    allowed = int(len(benign) * fpr)
    return min(1.0, benign[allowed] + 1e-9) if allowed < len(benign) else 0.0


def main(argv: list[str]) -> None:  # pragma: no cover - needs the dataset
    import lightgbm as lgb
    import numpy as np

    p = argparse.ArgumentParser()
    p.add_argument("--train", type=Path, nargs="+", required=True)
    p.add_argument("--test", type=Path, nargs="+", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--fpr", type=float, default=0.01)
    p.add_argument("--name", default="qalaa-pe-ember")
    a = p.parse_args(argv)
    xs, ys = zip(*records(a.train), strict=True)
    tx, ty = zip(*records(a.test), strict=True)
    params = {"objective": "binary", "num_iterations": 1000, "learning_rate": 0.05, "num_leaves": 2048,
              "feature_fraction": 0.5, "bagging_fraction": 0.5, "bagging_freq": 1, "verbose": -1}  # fmt: skip
    booster = lgb.train(params, lgb.Dataset(np.array(xs), np.array(ys)))
    scores = booster.predict(np.array(tx)).tolist()
    threshold = threshold_for_fpr(scores, list(ty), a.fpr)
    caught = sum(1 for s, y in zip(scores, ty, strict=True) if y == 1 and s >= threshold) / max(1, sum(ty))
    a.out.write_text(json.dumps(convert(booster.dump_model(), threshold, a.fpr, a.name), separators=(",", ":")))
    print(f"threshold {threshold:.4f}: {caught:.1%} of test malware at {a.fpr:.1%} false positives")


if __name__ == "__main__":  # pragma: no cover
    main(sys.argv[1:])
