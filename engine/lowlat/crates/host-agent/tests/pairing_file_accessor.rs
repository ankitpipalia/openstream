use openstream_host_agent::ChildSpec;
use openstream_settings::default_config;
use std::fs;
use std::path::PathBuf;

fn private_pairing_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "openstream-host-agent-accessor-{}.json",
        std::process::id()
    ));
    fs::write(&path, b"{}\n").expect("write pairing fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("protect pairing fixture");
    }
    path
}

#[test]
fn pairing_file_accessor_reports_configured_and_absent_values() {
    let path = private_pairing_file();
    let configured =
        openstream_host_agent::HostAgentConfig::from_settings(&default_config(), "openstream-host")
            .expect("config")
            .with_pairing_file(&path)
            .expect("validated pairing file");

    assert_eq!(configured.child().pairing_file(), Some(path.as_path()));
    assert_eq!(
        ChildSpec::new("openstream-host")
            .expect("child spec")
            .pairing_file(),
        None
    );

    fs::remove_file(path).expect("remove pairing fixture");
}
