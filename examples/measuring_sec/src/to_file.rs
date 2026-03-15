use array_init::array_init;
use iris_core::CoreId;
use std::sync::atomic::{AtomicPtr, Ordering};

use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::OnceLock;

// Number of cores being used by the runtime; should match config file
// Should be defined at compile-time so that we can use a
// statically-sized array for results()
const NUM_CORES: usize = 8;
// Add 1 for ARR_LEN to avoid overflow; one core is used as main_core
const ARR_LEN: usize = NUM_CORES + 1;
// Temporary per-core files
pub const OUTFILE_PREFIX: &str = "sec_";

static RESULTS: OnceLock<[AtomicPtr<BufWriter<File>>; ARR_LEN]> = OnceLock::new();

fn results() -> &'static [AtomicPtr<BufWriter<File>>; ARR_LEN] {
    RESULTS.get_or_init(|| {
        let mut outp = vec![];
        for core_id in 0..ARR_LEN {
            let file_name = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
            let core_wtr = BufWriter::new(File::create(&file_name).unwrap());
            let core_wtr = Box::into_raw(Box::new(core_wtr));
            outp.push(core_wtr);
        }
        array_init(|i| AtomicPtr::new(outp[i]))
    })
}

pub fn init_files() {
    let _ = results();
}

pub fn write_result(value: String, core_id: &CoreId) {
    if value.is_empty() {
        return;
    }
    let ptr = results()[core_id.raw() as usize].load(Ordering::Relaxed);
    let wtr = unsafe { &mut *ptr };
    wtr.write_all(value.as_bytes()).unwrap();
}

pub fn dump_keys() {
    let fp = OUTFILE_PREFIX.to_owned() + "domains.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let doms = super::process_sessions::domains().lock();
    for (i, d) in doms.iter().enumerate() {
        let s = format!("{}={}\n", i, d);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "uris.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let uris = super::process_sessions::uris().lock();
    for (i, u) in uris.iter().enumerate() {
        let s = format!("{}={}\n", i, u);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "snis.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let snis = super::process_sessions::snis().lock();
    for (i, s) in snis.iter().enumerate() {
        let s = format!("{}={}\n", i, s);
        writer.write_all(s.as_bytes()).unwrap();
    }

    let fp = OUTFILE_PREFIX.to_owned() + "user_agents.txt";
    let mut writer = BufWriter::new(File::create(&fp).unwrap());
    let uas = super::process_sessions::user_agents().lock();
    for (ip, ua) in uas.iter() {
        let s = format!("{}=[{}]\n", ip, ua.join(","));
        writer.write_all(s.as_bytes()).unwrap();
    }

    for core_id in 0..ARR_LEN {
        let filename = String::from(OUTFILE_PREFIX) + &format!("{}", core_id) + ".jsonl";
        let file = std::path::Path::new(&filename);
        if let Ok(m) = std::fs::metadata(file) {
            if m.is_file() && m.len() == 0 {
                match std::fs::remove_file(file) {
                    Ok(_) => {}
                    Err(e) => println!("Failed to delete {}: {}", file.display(), e),
                }
            }
        }
    }
}
