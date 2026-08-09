from src.atlasscan.technology import fingerprint_technology


def technology_names(result):
    return {item["name"] for item in result}


def test_detect_openssh():
    result = fingerprint_technology(
        service="ssh",
        version="6.6.1p1",
        banner="SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
    )

    assert "OpenSSH 6.6.1p1" in technology_names(result)


def test_detect_apache():
    result = fingerprint_technology(
        service="http",
        version="2.4.7",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)",
        http_details={
            "server": "Apache/2.4.7 (Ubuntu)",
        },
    )

    assert "Apache 2.4.7" in technology_names(result)


def test_detect_php():
    result = fingerprint_technology(
        service="http",
        version="2.4.7",
        http_details={
            "headers": {
                "x-powered-by": "PHP/8.2.0",
            },
        },
    )

    assert "PHP 8.2.0" in technology_names(result)


def test_detect_jquery():
    result = fingerprint_technology(
        service="http",
        http_details={
            "body": '<script src="/jquery.min.js"></script>',
        },
    )

    assert "jQuery" in technology_names(result)


def test_detect_bootstrap():
    result = fingerprint_technology(
        service="http",
        http_details={
            "body": '<link href="/bootstrap.min.css" rel="stylesheet">',
        },
    )

    assert "Bootstrap" in technology_names(result)


def test_detect_wordpress():
    result = fingerprint_technology(
        service="http",
        http_details={
            "body": '<link rel="stylesheet" href="/wp-content/themes/test/style.css">',
        },
    )

    assert "WordPress" in technology_names(result)


def test_detect_nextjs():
    result = fingerprint_technology(
        service="http",
        http_details={
            "body": '<script src="/_next/static/chunks/app.js"></script>',
        },
    )

    assert "Next.js" in technology_names(result)
    assert "React" in technology_names(result)


def test_detect_nginx():
    result = fingerprint_technology(
        service="http",
        http_details={
            "server": "nginx/1.24.0",
        },
    )

    assert "Nginx 1.24.0" in technology_names(result)


def test_detect_express():
    result = fingerprint_technology(
        service="http",
        http_details={
            "headers": {
                "x-powered-by": "Express",
            },
        },
    )

    assert "Express" in technology_names(result)


def test_no_duplicate_technology():
    result = fingerprint_technology(
        service="http",
        version="2.4.7",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.7 (Ubuntu)",
        http_details={
            "server": "Apache/2.4.7 (Ubuntu)",
        },
    )

    names = [
        item["name"]
        for item in result
    ]

    assert names.count("Apache 2.4.7") == 1
