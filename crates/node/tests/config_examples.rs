//! Every committed node example config under `/config` must parse and validate.
//! Non-node TOML (e.g. `validators.toml`) is skipped.

use std::collections::HashSet;
use std::path::PathBuf;

#[test]
fn all_example_configs_parse_and_validate() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
    let mut parsed = 0;
    for entry in std::fs::read_dir(&dir).expect("config dir exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // Validator-set descriptors are not NodeConfig files.
        if name == "validators.toml" {
            assert!(
                path.is_file(),
                "example validators.toml must exist for multi-node demos"
            );
            continue;
        }
        node::NodeConfig::load(&path)
            .unwrap_or_else(|e| panic!("{} failed to parse: {e}", path.display()));
        parsed += 1;
    }
    assert!(
        parsed >= 4,
        "expected several example configs, parsed {parsed}"
    );
}

#[test]
fn multi_node_demo_configs_use_distinct_ports() {
    // us/eu/tokyo/light are designed to co-locate on one host for demos.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
    let multi = ["us.toml", "eu.toml", "tokyo.toml", "light.toml"];
    let mut listens = HashSet::new();
    for name in multi {
        let path = dir.join(name);
        let cfg = node::NodeConfig::load(&path)
            .unwrap_or_else(|e| panic!("{} failed: {e}", path.display()));
        assert!(
            listens.insert(cfg.network.listen.clone()),
            "duplicate network.listen {} in {name}",
            cfg.network.listen
        );
        assert!(
            listens.insert(format!("rpc:{}", cfg.rpc.listen)),
            "duplicate rpc.listen {} in {name}",
            cfg.rpc.listen
        );
        if !cfg.observability.metrics_listen.is_empty() {
            assert!(
                listens.insert(format!("metrics:{}", cfg.observability.metrics_listen)),
                "duplicate metrics_listen {} in {name}",
                cfg.observability.metrics_listen
            );
        }
    }
}

#[test]
fn example_configs_do_not_enable_unsupported_flags() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config");
    for entry in std::fs::read_dir(&dir).expect("config dir exists") {
        let path = entry.unwrap().path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.extension().and_then(|e| e.to_str()) != Some("toml") || name == "validators.toml" {
            continue;
        }
        let cfg = node::NodeConfig::load(&path).unwrap();
        assert!(!cfg.network.enable_quic, "{}", path.display());
        assert!(!cfg.network.enable_datagrams, "{}", path.display());
        assert!(!cfg.performance.busy_poll, "{}", path.display());
    }
}
