use rpf_archive::crypto::cipher::{decrypt_ng, encrypt_ng};
use rpf_archive::crypto::keys::GtaKeys;
use std::path::Path;

// Encrypt/decrypt a single NG blob.
//
// Usage:
//   ngcrypt enc <keys_dir> <infile> <outfile> <entry_name> <entry_length>
//   ngcrypt dec <keys_dir> <infile> <outfile> <entry_name> <entry_length>
//
// <entry_name> is the archive-relative path of the entry (e.g. "common/data/dlclist.xml")
// and <entry_length> its UNCOMPRESSED size in bytes — together they select the key,
// exactly like the game does.
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 || (args[1] != "enc" && args[1] != "dec") {
        eprintln!("usage: ngcrypt enc|dec <keys_dir> <infile> <outfile> <entry_name> <uncompressed_len>");
        std::process::exit(1);
    }
    let mode = args[1].clone();
    let keys = GtaKeys::load_from_path(Path::new(&args[2])).unwrap();
    let data = std::fs::read(&args[3]).unwrap();
    let name = &args[5];
    let length: u32 = args[6].parse().unwrap();
    let out = match mode.as_str() {
        "enc" => encrypt_ng(&data, &keys, name, length),
        "dec" => decrypt_ng(&data, &keys, name, length),
        _ => unreachable!(),
    };
    std::fs::write(&args[4], out).unwrap();
}
