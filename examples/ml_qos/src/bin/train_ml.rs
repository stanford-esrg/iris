// Adapted from https://github.com/stanford-esrg/cato/tree/cc0ff3c99ce2ad674fd61757611a682008586ee2/scripts/train_rust_dt

use smartcore::dataset::Dataset;
use smartcore::ensemble::random_forest_classifier::{
    RandomForestClassifier, RandomForestClassifierParameters,
};
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::tree::decision_tree_classifier::SplitCriterion;

use anyhow::{Result, anyhow};
use clap::Parser;

use std::fs::File;
use std::time::Instant;

// Parameters extracted from original model
const CRITERION: SplitCriterion = SplitCriterion::Gini;
const MAX_DEPTH: Option<u16> = None;
const MIN_SAMPLES_LEAF: usize = 1;
const MIN_SAMPLES_SPLIT: usize = 2;

// Skip if `label` is this value to be 0
lazy_static::lazy_static! {
    static ref SKIP_IF: Vec<f64> = vec![
        0.0
    ];
}

// Labels
const LABEL_COLUMN: &str = "resolution";
lazy_static::lazy_static! {
    static ref FEATURE_SET: Vec<&'static str> = vec![
        "allprev_avg_chunksize",
        "allprev_max_chunksize",
        "allprev_std_chunksize",
        "10_min_chunksize",
        "cumsum_chunksizes",
        "10_std_chunksize",
        "10_max_chunksize",
        "10_avg_chunksize",
    ];
}

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_name = "TRAIN_DATASET")]
    train_dataset: String,
    #[clap(long, value_name = "MODEL_BIN")]
    model_bin: String,
}

/// Load preprocessed dataset from CSV and into a smartcore Dataset
fn load_dataset(dataset_file: &str) -> Result<Dataset<f64, usize>> {
    println!("Loading dataset: {}", dataset_file);
    let start = Instant::now();
    let mut data: Vec<f64> = vec![];
    let mut target: Vec<usize> = vec![];
    let mut target_vals: Vec<usize> = vec![];
    let mut n_rows = 0;
    let mut n_cols = 0;

    let mut rdr = csv::Reader::from_path(dataset_file)?;
    let mut headers: Vec<String> = vec![];
    let mut label_idx = None;
    let mut feature_idx = vec![];
    {
        for (i, header) in rdr.headers()?.iter().enumerate() {
            if header == LABEL_COLUMN {
                label_idx = Some(i);
            } else if FEATURE_SET.contains(&header) {
                headers.push(header.to_string());
                feature_idx.push(i);
                n_cols += 1;
            }
        }
    }
    let label_idx = label_idx.ok_or(anyhow!("No label."))?;

    let mut skipped_rows = 0;

    // Iterate through CSV rows
    for (_, record) in rdr.records().enumerate() {
        if let Ok(val) = record // Fails if not utf-8
            .as_ref()
            .unwrap()
            .get(label_idx) // Require label in row
            .ok_or(anyhow!("No target found."))?
            .parse::<f64>()
        {
            if SKIP_IF.contains(&val) {
                skipped_rows += 1;
                continue;
            }
            assert!(val.fract() == 0.0, "{} cannot be converted to usize", val);
            let val = val as usize;
            target.push(val); // Label for this row (everything else is a feature)
            if !target_vals.contains(&val) {
                // Space of possible targets
                target_vals.push(val);
            }
            n_rows += 1;
            for (i, item) in record?.iter().enumerate() {
                // Note - only adding data for the specified features
                if feature_idx.contains(&i) {
                    data.push(item.parse().unwrap_or(0.0));
                }
            }
        }
    }
    println!("Num samples: {}", n_rows);
    println!("Num features: {} ({})", n_cols, headers.join(","));
    println!("Num classes: {} ({:?})", target_vals.len(), target_vals);
    println!("Skipped (invalid) rows: {}", skipped_rows);

    let dataset = Dataset {
        data,
        target,
        num_samples: n_rows,
        num_features: n_cols,
        feature_names: headers,
        target_names: target_vals.iter().map(|v| v.to_string()).collect(),
        description: dataset_file.to_string(),
    };
    println!("Done loading data, elapsed: {:?}", start.elapsed());
    Ok(dataset)
}

/// Trains a random forest classifier from dataset
fn train_dt(
    train_dataset: Dataset<f64, usize>,
    params: RandomForestClassifierParameters,
) -> Result<RandomForestClassifier<f64, usize, DenseMatrix<f64>, Vec<usize>>> {
    println!("Training random forest classifier with params {:?}", params);
    let x_train = DenseMatrix::new(
        train_dataset.num_samples,
        train_dataset.num_features,
        train_dataset.data,
        false,
    )?;
    let y_train = train_dataset.target;

    let start = Instant::now();
    let clf = RandomForestClassifier::fit(&x_train, &y_train, params)?;
    println!("Done training, elapsed: {:?}", start.elapsed());

    Ok(clf)
}

// Note - testing skipped for this example, as we only care about system performance
fn main() -> Result<()> {
    let args = Args::parse();
    let train_dataset_fname = args.train_dataset;
    let model_bin_fname = args.model_bin;

    // Set up parameters
    let mut params = RandomForestClassifierParameters::default()
        .with_criterion(CRITERION)
        .with_min_samples_leaf(MIN_SAMPLES_LEAF)
        .with_min_samples_split(MIN_SAMPLES_SPLIT);
    params.max_depth = MAX_DEPTH;

    // Load training dataset
    let dataset = load_dataset(&train_dataset_fname)?;

    // Train model
    let clf = train_dt(dataset, params)?;

    // Save binary
    let mut file = File::create(&model_bin_fname)?;
    bincode::serialize_into(&mut file, &clf)?;
    println!("Rust model binary saved to {:?}", model_bin_fname);

    Ok(())
}
