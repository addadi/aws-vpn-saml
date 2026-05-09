use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "aws-vpn-saml",
    version,
    about = "SAML auth helper for AWS Client VPN"
)]
pub struct Config {
    #[arg(
        long,
        short = 'o',
        visible_alias = "ovpn",
        env = "AWS_VPN_OVPN_BIN",
        default_value = "/usr/bin/openvpn-aws"
    )]
    pub ovpn_bin: PathBuf,

    #[arg(long, short = 'c', visible_alias = "config", env = "AWS_VPN_OVPN_CONF")]
    pub ovpn_conf: PathBuf,

    #[arg(
        long,
        env = "AWS_VPN_ON_CHALLENGE",
        default_value = "listen",
        value_enum
    )]
    pub on_challenge: ChallengeMode,

    #[arg(long, default_value_t = 35001)]
    pub port: u16,

    #[arg(long, default_value_t = 30)]
    pub challenge_timeout: u64,

    #[arg(long, default_value_t = 120)]
    pub saml_timeout: u64,

    #[arg(long, short = 'v', env = "AWS_VPN_VERBOSE", default_value_t = false)]
    pub verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ChallengeMode {
    Listen,
    Auto,
}

impl std::fmt::Display for ChallengeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChallengeMode::Listen => write!(f, "listen"),
            ChallengeMode::Auto => write!(f, "auto"),
        }
    }
}
