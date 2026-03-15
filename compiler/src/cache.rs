use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::{fs::OpenOptions, path::PathBuf};

use crate::parse::*;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub(crate) static ref OUTFILE: Mutex<Option<PathBuf>> = Mutex::new(None);
    pub(crate) static ref CACHED_DATA: Mutex<Vec<ParsedInput>> = Mutex::new(Vec::new());
}

/// If code generation is spread across multiple crates, an intermediate
/// representation in a file is required. This sets the outfile for a crate.
pub(crate) fn set_crate_outfile(fp: String) {
    if OUTFILE.lock().unwrap().is_some() {
        panic!("Tried to set outfile twice");
    }

    // Env variable (e.g., $IRIS_HOME), $HOME, or unmodified
    let fp = parse_filepath(&fp);

    // Create or clear file
    let path = PathBuf::from(fp.clone());
    if !path.exists() {
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(&path)
            .expect(&format!("Failed to create file {}", fp));
    } else if std::fs::metadata(&path).unwrap().len() != 0 {
        println!("Warning - clearing existing contents of file {}", fp);
    }

    println!("GOT OUTPUT FILE NAME: {}", fp);

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .expect(&format!("Failed to open file {}", fp));

    let v = CACHED_DATA.lock().unwrap();
    for elem in v.iter() {
        let json = serde_json::to_string(&elem).expect("Failed to serialize input");
        writeln!(file, "{}", json).expect("Failed to write to file");
    }

    *OUTFILE.lock().unwrap() = Some(path);
}

/// Push a new parsed input from a macro to memory and file (if available)
pub(crate) fn push_input(input: ParsedInput) {
    let outfile = OUTFILE.lock().unwrap();
    match outfile.as_ref() {
        Some(fp) => {
            let mut file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(&fp)
                .expect("Failed to open file to append");
            let json = serde_json::to_string(&input).expect("Failed to convert json to string");
            writeln!(file, "{}", json).expect("Failed to append to file");
        }
        None => {
            println!("Caching input in memory");
        }
    }
    CACHED_DATA.lock().unwrap().push(input);
}

/// Read parsed data from input files (intermediate representation generated
/// by some other crate, e.g., datatypes).
pub(crate) fn set_input_files(fps: Vec<&str>) {
    let mut cached = CACHED_DATA.lock().unwrap();
    for fp in fps {
        let fp = parse_filepath(&String::from(fp));
        let file = File::open(fp.clone()).expect(&format!("Cannot find input file: {}", fp));
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.expect(&format!("Failed to read line from input file {}", fp));
            if line.trim().is_empty() {
                continue;
            }
            let inp: ParsedInput = serde_json::from_str(&line).unwrap();
            cached.push(inp);
        }
        println!("Got input from {}", fp);
    }
}

fn parse_filepath(fp: &String) -> String {
    if fp.starts_with("$") {
        let mut dirs = fp.split("/").collect::<Vec<_>>();
        let home = std::env::var(&dirs[0].replace("$", ""))
            .expect(&format!("Cannot find env variable {}", dirs[0]));
        dirs[0] = &home;
        dirs.join("/")
    } else if fp.starts_with("~") {
        let home = std::env::var("HOME").expect(&format!("Cannot find home directory"));
        fp.replace("~", &home)
    } else {
        fp.clone()
    }
}
