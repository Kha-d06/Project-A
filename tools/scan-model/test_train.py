import math

from train import convert, threshold_for_fpr
from vectorize import VECTOR_LEN


def test_a_lightgbm_dump_converts_to_parent_first_nodes() -> None:
    dump = {"objective": "binary sigmoid:1", "tree_info": [{"tree_structure": {
        "split_feature": 3, "threshold": 0.5, "decision_type": "<=", "default_left": False,
        "left_child": {"leaf_value": -1.0},
        "right_child": {"split_feature": 7, "threshold": 2.0, "decision_type": "<=", "default_left": True,
                        "left_child": {"leaf_value": 0.5}, "right_child": {"leaf_value": 2.0}}}}]}  # fmt: skip
    m = convert(dump, 0.9, 0.01, "t")
    nodes = m["trees"][0]["nodes"]
    assert nodes[0] == {"f": 3, "t": 0.5, "l": 1, "r": 2, "d": False}
    assert nodes[2]["l"] > 2 and nodes[2]["r"] > 2
    assert all(n.get("l", math.inf) > i and n.get("r", math.inf) > i for i, n in enumerate(nodes) if "f" in n)
    assert m["feature_len"] == VECTOR_LEN and m["formats"] == ["pe"]


def test_threshold_keeps_false_positives_at_the_rate_asked() -> None:
    scores = [i / 100 for i in range(100)] + [0.99] * 10
    labels = [0] * 100 + [1] * 10
    t = threshold_for_fpr(scores, labels, 0.05)
    assert sum(1 for s, y in zip(scores, labels, strict=True) if y == 0 and s >= t) <= 5
