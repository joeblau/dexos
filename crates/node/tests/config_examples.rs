//! Every committed example config under `/config` must parse and validate.

use std::path::PathBuf;

#[test]
fn all_example_configs_parse_and_validate() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
    let mut parsed = 0;
    for entry in std::fs::read_dir(&dir).expect("config dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            node::NodeConfig::load(&path)
                .unwrap_or_else(|e| panic!("{} failed to parse: {e}", path.display()));
            parsed += 1;
        }
    }
    assert!(
        parsed >= 4,
        "expected several example configs, parsed {parsed}"
    );
}
