
use simplelog::{
    ColorChoice, CombinedLogger, Config, ConfigBuilder, LevelFilter,
    TermLogger, TerminalMode, WriteLogger,
};

use crate::tuning::TuningSummary;

// ── ANSI helpers (banner only) ────────────────────────────────────────────────

const RESET:  &str = "\x1b[0m";
const DIM:    &str = "\x1b[2m";
const BOLD:   &str = "\x1b[1m";
const CYAN:   &str = "\x1b[1;96m";
const YELLOW: &str = "\x1b[1;93m";
const MAGENTA: &str = "\x1b[1;95m";

// ── Logger ────────────────────────────────────────────────────────────────────

/// Parse a level string into a [`LevelFilter`].
fn parse_level(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "warn"  => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _       => LevelFilter::Info,
    }
}

/// Build a `simplelog` [`Config`].
fn build_config() -> Config {
    ConfigBuilder::new()
        .set_time_format_rfc3339()          
        .set_time_offset_to_local()         
        .unwrap_or_else(|b| b)              
        .set_target_level(LevelFilter::Error) 
        .set_thread_level(LevelFilter::Off)   
        .build()
}

/// Initialise the global logger.
pub fn init_logging(level: &str) {
    init_logging_with_file(level, None::<&str>);
}

/// Initialise the global logger with an optional log file path.
pub fn init_logging_with_file<P: AsRef<std::path::Path>>(level: &str, log_file: Option<P>) {
    let filter = parse_level(level);
    let cfg    = build_config();

    let term = TermLogger::new(
        filter,
        cfg.clone(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    );

    if let Some(path) = log_file {
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(file) => {
                CombinedLogger::init(vec![
                    term,
                    WriteLogger::new(filter, cfg, file),
                ])
                .unwrap_or_else(|e| eprintln!("logger init error: {e}"));
            }
            Err(e) => {
                eprintln!("cannot open log file {:?}: {e}", path.as_ref());
                let _ = CombinedLogger::init(vec![term]);
            }
        }
    } else {
        let _ = CombinedLogger::init(vec![term]);
    }
}

// ── Banner ────────────────────────────────────────────────────────────────────

/// Print the SuitsSpoof startup banner to stderr.
pub fn print_banner(role: &str, version: &str) {
    eprintln!(
        r#"{c1} ███████╗██╗   ██╗██╗████████╗███████╗███████╗██████╗  ██████╗  ██████╗ ███████╗{R}
{c2} ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝{R}
{c3} ███████╗██║   ██║██║   ██║   ███████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  {R}
{c4} ╚════██║██║   ██║██║   ██║   ╚════██║╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  {R}
{c5} ███████║╚██████╔╝██║   ██║   ███████║███████║██║     ╚██████╔╝╚██████╔╝██║     {R}
{c6} ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     {R}
{DIM} ───────────────────────────────────────────────────────────────────────────────{R}
 {BOLD}{MAGENTA}SuitsSpoof{R}  {DIM}v{version}{R}  {YELLOW}{role}{R}
{DIM} ───────────────────────────────────────────────────────────────────────────────{R}"#,
        c1 = "\x1b[1;38;5;63m",
        c2 = "\x1b[1;38;5;69m",
        c3 = "\x1b[1;38;5;75m",
        c4 = "\x1b[1;38;5;81m",
        c5 = "\x1b[1;38;5;117m",
        c6 = "\x1b[1;38;5;123m",
        R       = RESET,
        DIM     = DIM,
        BOLD    = BOLD,
        MAGENTA = MAGENTA,
        YELLOW  = YELLOW,
        version = version,
        role    = role.to_uppercase(),
    );
}

// ── Tune summary ──────────────────────────────────────────────────────────────

pub fn log_tune_summary(s: &TuningSummary) {
    log::info!("┌─ Auto-Tune ────────────────────────────────────");
    log::info!("│  mode={:?}  cores={}  mem={:.1}GB  nic={nic}Mbps",
        s.perf_mode, s.profile.cpu_cores, s.profile.mem_gb,
        nic = s.profile.nic_mbps.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
    );
    log::info!("│  threads={}  tunnels={}  chan={}  io_chan={}",
        s.runtime
