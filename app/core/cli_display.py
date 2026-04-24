"""
CLI Display — Pixel-style terminal UI for moku-analyzer.
"""
import os
import shutil
from colorama import init, Fore, Back, Style
import pyfiglet

init(autoreset=True)

TERMINAL_WIDTH = min(shutil.get_terminal_size().columns, 100)


def _center(text):
    return text.center(TERMINAL_WIDTH)


def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print()

    art = [
        "  ██╗    ██╗███████╗██████╗ ",
        "  ██║    ██║██╔════╝██╔══██╗",
        "  ██║ █╗ ██║█████╗  ██████╔╝",
        "  ██║███╗██║██╔══╝  ██╔══██╗",
        "  ╚███╔███╔╝███████╗██████╔╝",
        "   ╚══╝╚══╝ ╚══════╝╚═════╝ ",
        "",
        "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██╗██╗     ██╗████████╗██╗   ██╗",
        "  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██║██║     ██║╚══██╔══╝╚██╗ ██╔╝",
        "  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██║██║     ██║   ██║    ╚████╔╝ ",
        "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔══██╗██║██║     ██║   ██║     ╚██╔╝  ",
        "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║██████╔╝██║███████╗██║   ██║      ██║   ",
        "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝   ",
        "",
        "   █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ ",
        "  ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚════██║██╔════╝██╔══██╗",
        "  ███████║██╔██╗ ██║███████║██║   ╚████╔╝     ██╔╝█████╗  ██████╔╝",
        "  ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝     ██╔╝ ██╔══╝  ██╔══██╗",
        "  ██║  ██║██║ ╚████║██║  ██║███████╗██║      ███████╗██║  ██║  ██║",
        "  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝      ╚══════╝╚═╝  ╚═╝  ╚═╝",
    ]

    for line in art:
        print(Fore.CYAN + Style.BRIGHT + line + Style.RESET_ALL)

    print()
    print(Style.BRIGHT + Fore.WHITE + _center("moku-analyzer  ·  v1.0.0") + Style.RESET_ALL)
    print()


def print_status(db_ok=True, adapter_statuses=None):
    """Show all adapter statuses."""
    print(Style.BRIGHT + Fore.WHITE + "  Status" + Style.RESET_ALL)
    print("  " + "─" * 50)

    # Database
    dot = Fore.GREEN + "●" if db_ok else Fore.RED + "●"
    label = "Database connected" if db_ok else "Database error"
    print(f"  {dot}{Style.RESET_ALL}  {label}")

    if adapter_statuses:
        for name, status, note in adapter_statuses:
            if status == "ok":
                dot = Fore.GREEN + "●"
            elif status == "warn":
                dot = Fore.YELLOW + "●"
            else:
                dot = Fore.RED + "●"
            print(f"  {dot}{Style.RESET_ALL}  {name:<20}{Fore.WHITE + Style.DIM}{note}{Style.RESET_ALL}")

    print()


def print_menu():
    """Display main menu."""
    print("  " + "─" * 50)
    print(Style.BRIGHT + Fore.WHITE + "  What would you like to do?" + Style.RESET_ALL)
    print("  " + "─" * 50)
    items = [
        ("1", "Scan a target URL"),
        ("2", "View past scans"),
        ("3", "Download a report"),
        ("4", "Export all scans"),
        ("5", "Exit"),
    ]
    for num, label in items:
        print(f"  {Fore.CYAN + Style.BRIGHT}[{num}]{Style.RESET_ALL}  {Fore.WHITE}{label}{Style.RESET_ALL}")
    print()


def print_adapters():
    """Display available adapters."""
    print()
    print("  " + "─" * 50)
    print(Style.BRIGHT + Fore.WHITE + "  Select a scanner:" + Style.RESET_ALL)
    print("  " + "─" * 50)
    adapters = [
        ("1", "builtin",     "XSS, SQL Injection, CSRF detection"),
        ("2", "nuclei",      "9000+ vulnerability templates"),
        ("3", "nikto",       "Web server scanner"),
        ("4", "shodan",      "Passive recon via Shodan"),
        ("5", "virustotal",  "URL reputation check"),
        ("6", "zap",         "OWASP ZAP active scanner"),
    ]
    for num, name, desc in adapters:
        color = Fore.GREEN if name == "builtin" else Fore.WHITE
        print(f"  {Fore.CYAN + Style.BRIGHT}[{num}]{Style.RESET_ALL}  {color + Style.BRIGHT}{name:<15}{Style.RESET_ALL}{Fore.WHITE + Style.DIM}{desc}{Style.RESET_ALL}")
    print()


def print_scanning(url, adapter):
    """Display scanning in progress."""
    print()
    print(f"  {Fore.CYAN + Style.BRIGHT}Scanning...{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Target :{Style.RESET_ALL}  {url}")
    print(f"  {Fore.WHITE}Scanner:{Style.RESET_ALL}  {adapter}")
    print(f"  {Fore.YELLOW}Please wait...{Style.RESET_ALL}")
    print()


def print_results(vulnerabilities):
    """Display scan results."""
    print()
    if not vulnerabilities:
        print(f"  {Fore.GREEN + Style.BRIGHT}✓  No vulnerabilities found.{Style.RESET_ALL}")
        print()
        return

    print(f"  {Fore.RED + Style.BRIGHT}⚠  Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
    print("  " + "─" * 50)

    severity_colors = {
        'critical': Fore.RED,
        'high':     Fore.RED,
        'medium':   Fore.YELLOW,
        'low':      Fore.BLUE,
        'info':     Fore.CYAN,
    }

    for v in vulnerabilities:
        sev = v.get('severity', 'info').upper()
        color = severity_colors.get(sev.lower(), Fore.WHITE)
        print(f"\n  {color + Style.BRIGHT}[{sev}]{Style.RESET_ALL}  {Fore.WHITE + Style.BRIGHT}{v.get('type', '')}{Style.RESET_ALL}")
        print(f"        {v.get('description', '')}")
        if v.get('evidence'):
            print(f"        {Fore.WHITE + Style.DIM}Evidence: {v['evidence']}{Style.RESET_ALL}")
    print()


def print_history_table(scans):
    """Display scan history table."""
    print()
    print(Style.BRIGHT + Fore.WHITE + "  Scan History" + Style.RESET_ALL)
    print("  " + "─" * 70)
    print(f"  {Fore.CYAN}{'Scan ID':<15} {'Target URL':<35} {'Scanner':<12} {'Issues'}{Style.RESET_ALL}")
    print("  " + "─" * 70)
    for s in scans:
        url = s['url'][:35] if len(s['url']) > 35 else s['url']
        issues = s['total_vulns']
        color = Fore.RED if issues > 0 else Fore.GREEN
        print(f"  {Fore.WHITE}{s['id']:<15} {url:<35} {s['adapter']:<12} {color}{issues}{Style.RESET_ALL}")
    print()


def print_success(msg):
    print(f"  {Fore.GREEN + Style.BRIGHT}✓  {msg}{Style.RESET_ALL}")


def print_error(msg):
    print(f"  {Fore.RED + Style.BRIGHT}✗  {msg}{Style.RESET_ALL}")


def print_info(msg):
    print(f"  {Fore.CYAN}ℹ  {msg}{Style.RESET_ALL}")


def get_input(prompt):
    return input(f"  {Fore.CYAN + Style.BRIGHT}>{Style.RESET_ALL}  {prompt}: ").strip()