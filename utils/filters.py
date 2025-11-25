"""Filter utilities for graph pruning."""

from pathlib import Path

IGNORED_PREFIXES = (
    "/lib/",
    "/usr/lib/",
    "/usr/share/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/etc/ld.so.cache",
    "/etc/localtime",
    "/run/",
    "/var/lib/",
    "/snap/",
    "/tmp/go-build",
)

IGNORED_BINARIES = {
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/bash",
    "/bin/bash",
    "/usr/bin/curl",
    "/usr/bin/chmod",
    "/usr/bin/touch",
    "/usr/bin/rm",
}

# Ports to ignore (0=interface check, 53=DNS)
IGNORED_PORTS = {0, 53, 5353}

# Exact paths to ignore (usually directories that show up as write targets)
IGNORED_EXACT_PATHS = {
    "/home/attacker",
    "/home/attacker/",
    "/home/student/proj_tools",
    "/home/student/Downloads",
    "/home/student/Downloads/",
}


def is_noise_file(path: str) -> bool:
    """Check if a file path is system noise."""
    if not path:
        return True

    # 1. Exact matches (directories etc.)
    if path.rstrip("/") in IGNORED_EXACT_PATHS:
        return True

    # 2. Known binaries
    if path in IGNORED_BINARIES:
        return True

    # 3. Prefixes
    return path.startswith(IGNORED_PREFIXES)


def is_noise_socket(addr_str: str) -> bool:
    """Check if a socket address (IP:Port) is noise."""
    if not addr_str:
        return False

    if ":" in addr_str:
        try:
            port_str = addr_str.split(":")[-1]
            if port_str.isdigit():
                port = int(port_str)
                if port in IGNORED_PORTS:
                    return True
        except ValueError:
            pass

    if "127.0.0.53" in addr_str:
        return True

    return False

