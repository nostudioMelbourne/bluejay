from pathlib import Path

APP_NAME = "Blue Jay"
MODEL_NAME = "bluejay"
MODEL_DEFAULTS = {
    "chat": "bluejay",
    "analysis": "bluejay-analyst",
    "explain": "bluejay-explainer",
}

SCANS_DIR = Path("scans")
LOGS_DIR = Path("logs")
REPORTS_DIR = Path("reports")
CHATS_DIR = Path("chats")
DATA_DIR = Path("data")
BASELINES_DIR = DATA_DIR / "baselines"
FINDINGS_FILE = DATA_DIR / "findings.jsonl"
DB_FILE = DATA_DIR / "bluejay.db"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_FILE = DATA_DIR / "history.txt"
ALLOWED_TARGETS_FILE = Path("allowed_targets.txt")
MAX_ANALYSIS_BYTES = 200_000
MAX_CHAT_CHARS = 4_000
CHAT_CONTEXT_CHARS = 24_000
CHAT_HISTORY_LIMIT = 32
OLLAMA_TIMEOUT_SECONDS = 300
NMAP_TIMEOUT_SECONDS = 180
DIG_TIMEOUT_SECONDS = 20
HTTP_TIMEOUT_SECONDS = 15
NUCLEI_TIMEOUT_SECONDS = 240
MAX_SITE_PAGES = 8
MAX_SITE_LINKS = 40
MAX_SITE_BYTES = 500_000

SCAN_PROFILES = {
    "quiet": ["quiet-scan"],
    "quick": ["dns", "scan"],
    "standard": ["dns", "scan", "web"],
    "deep": ["dns", "scan", "vuln", "web"],
    "web": ["dns", "web"],
    "report": ["report"],
}

SEVERITY_ORDER = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Info": 0,
    "Unknown": -1,
}

VALID_MODES = {
    "nmap",
    "vulnerability",
    "dns",
    "web-check",
    "auth-log",
    "web-log",
    "firewall-log",
    "general",
}

MODEL_PROFILES = ("chat", "analysis", "explain")
MODEL_PROFILE_ALIASES = {
    "chat": "chat",
    "analysis": "analysis",
    "analyse": "analysis",
    "report": "analysis",
    "reports": "analysis",
    "explain": "explain",
    "finding": "explain",
}

COMMANDS = [
    ("/help", "", "Show commands"),
    ("/status", "", "Show tools, counts, and paths"),
    ("/allowed", "", "Show authorised targets"),
    ("/model", "", "Show configured Ollama model"),
    ("/config", "[show|model|reset] ...", "Configure model profiles"),
    ("/newchat", "", "Start a fresh saved chat transcript"),
    ("/resume", "[number|file]", "Resume a saved chat transcript"),
    ("/chatlog", "", "Show current chat file and context settings"),
    ("/files", "", "List scan/log files"),
    ("/reports", "", "List recent reports"),
    ("/scan", "<target> [profile] [options]", "Run controlled Nmap scan"),
    ("/vuln", "<target>", "Run bounded Nmap vulnerability scripts"),
    ("/dig", "<domain>", "Collect DNS records and analyse them"),
    ("/web", "<host-or-url>", "Check HTTP, TLS, headers, and cookies"),
    ("/site", "<host-or-url>", "Audit a local website workflow"),
    ("/nuclei", "<host-or-url> [severity-list]", "Run optional bounded Nuclei scan"),
    ("/profile", "<quiet|quick|standard|deep|web|report> <target|all>", "Run repeatable workflow"),
    ("/analyse", "<file> <mode>", "Analyse a saved file"),
    ("/assets", "", "List known assets"),
    ("/asset", "<target>", "Show one asset"),
    ("/history", "[target]", "Show scan history"),
    ("/findings", "[open|resolved|all] [target]", "List findings"),
    ("/finding", "<id>", "Show one finding"),
    ("/triage", "[target]", "Show priority summary"),
    ("/next", "[target]", "Show next priority finding"),
    ("/remediate", "<id>", "Show remediation workflow"),
    ("/explain", "<id>", "Explain finding with local model"),
    ("/retest", "<id>", "Rerun closest safe check"),
    ("/baseline", "[target|all]", "Save or list finding baselines"),
    ("/diff", "<target|all>", "Compare current findings to baseline"),
    ("/resolve", "<id>", "Mark finding resolved"),
    ("/reopen", "<id>", "Reopen finding"),
    ("/report", "[mode] [target|all]", "Generate findings report"),
    ("/view", "<number>", "View recent report"),
    ("/clear", "", "Clear terminal"),
    ("/about", "", "Show project info"),
    ("/exit", "", "Exit Blue Jay"),
]
COMMAND_NAMES = [command for command, _, _ in COMMANDS]
