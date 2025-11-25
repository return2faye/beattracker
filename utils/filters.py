"""Filter utilities for graph pruning."""

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
)

# Specific binaries that create high-degree nodes but add little forensic value
IGNORED_BINARIES = {
    "/usr/bin/sudo",
    "/bin/sudo",
    "/usr/bin/bash",
    "/bin/bash",
}

IGNORED_PORTS = {53, 5353}


def is_noise_file(path: str) -> bool:
    """Check if a file path is system noise."""
    if not path:
        return True
    if path in IGNORED_BINARIES:
        return True
    return path.startswith(IGNORED_PREFIXES)


def is_noise_socket(addr_str: str) -> bool:
    """Check if a socket address (IP:Port) is noise (e.g., DNS)."""
    if not addr_str:
        return False
    if ":53" in addr_str or addr_str.endswith(":5353"):
        return True
    if "127.0.0.53" in addr_str:
        return True
    return False


