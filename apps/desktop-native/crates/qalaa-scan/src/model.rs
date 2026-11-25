//! A gradient-boosted tree ensemble, evaluated locally.
//!
//! The file format is Qalaa's own small JSON (see `tools/scan-model`, which
//! converts a LightGBM model trained there). Each tree is a flat list of
//! nodes; a split sends `x <= threshold` left, and a missing value (NaN) the
//! way LightGBM recorded as its default. The raw sum goes through a sigmoid.
//!
//! The model can only ever make a file "suspicious": only signatures and
//! threat lists call anything known malware.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Node {
    Split {
        f: usize,
        t: f64,
        l: usize,
        r: usize,
        #[serde(default)]
        d: bool,
    },
    Leaf {
        leaf: f64,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Tree {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Model {
    pub format: u32,
    /// Which feature layout the model was trained on (features::FEATURE_VERSION).
    pub feature_version: u32,
    pub feature_len: usize,
    /// Which file formats the training data covered, e.g. ["pe"].
    pub formats: Vec<String>,
    #[serde(default)]
    pub base: f64,
    /// Score at or above which a file is reported as suspicious.
    pub threshold: f64,
    /// Expected false-positive rate at that threshold, from the held-out set.
    #[serde(default)]
    pub fpr: Option<f64>,
    pub trees: Vec<Tree>,
    #[serde(default)]
    pub name: String,
}

const MAX_TREES: usize = 10_000;
const MAX_NODES: usize = 1 << 16;

impl Model {
    pub fn parse(json: &[u8]) -> Result<Model, String> {
        let m: Model = serde_json::from_slice(json).map_err(|e| format!("model file is not valid: {e}"))?;
        m.validate()?;
        Ok(m)
    }

    /// Every index in range and every tree acyclic (children always later), so evaluation can't loop or panic.
    fn validate(&self) -> Result<(), String> {
        if self.format != 1 {
            return Err(format!("unsupported model format {}", self.format));
        }
        if self.feature_version != crate::features::FEATURE_VERSION || self.feature_len != crate::features::VECTOR_LEN {
            return Err("the model was built for a different feature layout".into());
        }
        if self.trees.len() > MAX_TREES || !(0.0..=1.0).contains(&self.threshold) {
            return Err("model limits exceeded".into());
        }
        for (ti, tree) in self.trees.iter().enumerate() {
            if tree.nodes.is_empty() || tree.nodes.len() > MAX_NODES {
                return Err(format!("tree {ti} has a bad size"));
            }
            for (i, n) in tree.nodes.iter().enumerate() {
                if let Node::Split { f, t, l, r, .. } = n {
                    if *f >= self.feature_len || t.is_nan() || *l <= i || *r <= i || *l >= tree.nodes.len() || *r >= tree.nodes.len() {
                        return Err(format!("tree {ti} node {i} is malformed"));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn applies_to(&self, format: &str) -> bool {
        self.formats.iter().any(|f| f == format)
    }

    pub fn raw(&self, x: &[f64]) -> f64 {
        let mut sum = self.base;
        for tree in &self.trees {
            let mut i = 0;
            loop {
                match &tree.nodes[i] {
                    Node::Leaf { leaf } => {
                        sum += leaf;
                        break;
                    }
                    Node::Split { f, t, l, r, d } => {
                        let v = x.get(*f).copied().unwrap_or(f64::NAN);
                        i = if v.is_nan() {
                            if *d {
                                *l
                            } else {
                                *r
                            }
                        } else if v <= *t {
                            *l
                        } else {
                            *r
                        };
                    }
                }
            }
        }
        sum
    }

    pub fn score(&self, x: &[f64]) -> f64 {
        1.0 / (1.0 + (-self.raw(x)).exp())
    }
}
