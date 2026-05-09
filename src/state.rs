use crate::challenge;
use crate::config::Config;
use crate::saml_server;
use std::path::Path;
use tracing::info;

#[derive(Debug)]
pub struct Error {
    message: String,
    code: i32,
}

impl Error {
    pub fn exit_code(&self) -> i32 {
        self.code
    }

    fn config(msg: impl Into<String>) -> Self {
        Error { message: msg.into(), code: 1 }
    }

    fn challenge(msg: impl Into<String>) -> Self {
        Error { message: msg.into(), code: 2 }
    }

    fn saml(msg: impl Into<String>) -> Self {
        Error { message: msg.into(), code: 3 }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error { message: s, code: 1 }
    }
}

pub struct StateMachine {
    config: Config,
}

impl StateMachine {
    pub fn new(config: Config) -> Self {
        StateMachine { config }
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        self.validate()?;

        let remote = challenge::resolve_remote(&self.config.ovpn_conf)
            .await
            .map_err(Error::config)?;

        info!(ip = %remote.ip, "phase 1: requesting CRV1 challenge");

        let challenge_data = challenge::get_challenge(
            &self.config.ovpn_bin,
            &self.config.ovpn_conf,
            &remote.ip,
            self.config.challenge_timeout,
        )
        .await
        .map_err(Error::challenge)?;

        info!("phase 2: waiting for SAML authentication");

        let saml_response = saml_server::listen_for_saml(
            self.config.port,
            challenge_data.saml_url,
            self.config.saml_timeout,
        )
        .await
        .map_err(Error::saml)?;

        info!("phase 3: outputting credentials");

        let password = format!(
            "CRV1::{}::{}",
            challenge_data.state_id,
            urlencoding::encode(&saml_response.response)
        );

        println!("N/A");
        println!("{password}");

        info!("done");
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        if !Path::new(&self.config.ovpn_bin).exists() {
            return Err(Error::config(format!(
                "OpenVPN binary not found: {}",
                self.config.ovpn_bin.display()
            )));
        }
        if !Path::new(&self.config.ovpn_conf).exists() {
            return Err(Error::config(format!(
                "OpenVPN config not found: {}",
                self.config.ovpn_conf.display()
            )));
        }
        Ok(())
    }
}
