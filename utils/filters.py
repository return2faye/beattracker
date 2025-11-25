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
)


def is_noise_file(path: str) -> bool:
    """Return True when the path should be treated as noise."""
    if not path:
        return True
    return path.startswith(IGNORED_PREFIXES)


