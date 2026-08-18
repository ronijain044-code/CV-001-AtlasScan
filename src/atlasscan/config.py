from dataclasses import dataclass


@dataclass(frozen=True)
class ScanProfile:
    name: str
    ports: str
    timeout: float
    workers: int

    # Scan-depth controls
    dns: bool = True
    subdomains: bool = True
    banners: bool = True
    http: bool = True
    technologies: bool = True
    vulnerabilities: bool = True
    web: bool = True
    security: bool = True
    robots: bool = True
    web_paths: bool = True


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        ports="21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080",
        timeout=0.5,
        workers=100,
        dns=True,
        subdomains=False,
        banners=True,
        http=True,
        technologies=True,
        vulnerabilities=True,
        web=False,
        security=True,
        robots=False,
        web_paths=False,
    ),

    "standard": ScanProfile(
        name="standard",
        ports="1-1000",
        timeout=1.0,
        workers=100,
        dns=True,
        subdomains=True,
        banners=True,
        http=True,
        technologies=True,
        vulnerabilities=True,
        web=True,
        security=True,
        robots=True,
        web_paths=True,
    ),

    "thorough": ScanProfile(
        name="thorough",
        ports="1-10000",
        timeout=1.5,
        workers=100,
        dns=True,
        subdomains=True,
        banners=True,
        http=True,
        technologies=True,
        vulnerabilities=True,
        web=True,
        security=True,
        robots=True,
        web_paths=True,
    ),
}


def get_profile(name: str) -> ScanProfile:
    """
    Return a configured scan profile by name.
    """

    profile = PROFILES.get(name.strip().lower())

    if profile is None:
        available = ", ".join(sorted(PROFILES))
        raise ValueError(
            f"Unknown profile '{name}'. "
            f"Available profiles: {available}"
        )

    return profile
