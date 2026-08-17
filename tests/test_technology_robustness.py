from src.atlasscan.technology import fingerprint_technology


def technology_names(result):
    return {item["name"] for item in result}


def test_empty_inputs_return_empty_result():
    result = fingerprint_technology()

    assert result == []


def test_none_values_are_handled():
    result = fingerprint_technology(
        service=None,
        version=None,
        banner=None,
        http_details=None,
    )

    assert isinstance(result, list)
    assert result == []


def test_detect_iis():
    result = fingerprint_technology(
        service="http",
        http_details={
            "server": "Microsoft-IIS/10.0",
        },
    )

    assert "Microsoft IIS 10.0" in technology_names(result)


def test_detect_caddy():
    result = fingerprint_technology(
        service="http",
        http_details={
            "server": "Caddy/2.7.6",
        },
    )

    assert "Caddy 2.7.6" in technology_names(result)


def test_detect_asp_net():
    result = fingerprint_technology(
        service="http",
        http_details={
            "headers": {
                "x-powered-by": "ASP.NET",
            },
        },
    )

    assert "ASP.NET" in technology_names(result)


def test_detect_nodejs():
    result = fingerprint_technology(
        service="http",
        http_details={
            "headers": {
                "x-powered-by": "Node.js",
            },
        },
    )

    assert "Node.js" in technology_names(result)


def test_detect_react():
    result = fingerprint_technology(
        service="http",
        http_details={
            "body": '<div id="root"></div><script src="/react.production.min.js"></script>',
        },
    )

    assert "React" in technology_names(result)


def test_detect_multiple_technologies():
    result = fingerprint_technology(
        service="http",
        banner="HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
        http_details={
            "server": "nginx/1.24.0",
            "headers": {
                "x-powered-by": "PHP/8.2.0",
            },
            "body": """
                <script src="/jquery.min.js"></script>
                <link href="/bootstrap.min.css" rel="stylesheet">
            """,
        },
    )

    names = technology_names(result)

    assert "Nginx 1.24.0" in names
    assert "PHP 8.2.0" in names
    assert "jQuery" in names
    assert "Bootstrap" in names


def test_technology_result_has_expected_shape():
    result = fingerprint_technology(
        service="http",
        http_details={
            "server": "Apache/2.4.7",
        },
    )

    assert result

    for item in result:
        assert set(item) == {
            "name",
            "category",
            "detected_from",
        }

        assert isinstance(item["name"], str)
        assert isinstance(item["category"], str)
        assert isinstance(item["detected_from"], str)


def test_duplicate_detection_is_case_insensitive():
    result = fingerprint_technology(
        service="http",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.7",
        http_details={
            "server": "apache/2.4.7",
        },
    )

    names = [
        item["name"]
        for item in result
    ]

    assert names.count("Apache 2.4.7") == 1


def test_unknown_service_does_not_crash():
    result = fingerprint_technology(
        service="something-unknown",
        version="1.0",
        banner="some completely unknown banner",
    )

    assert isinstance(result, list)


def test_whitespace_is_normalized():
    result = fingerprint_technology(
        service="http",
        http_details={
            "server": "  Apache/2.4.7 (Ubuntu)  ",
        },
    )

    assert "Apache 2.4.7" in technology_names(result)


def test_version_from_service_and_banner():
    result = fingerprint_technology(
        service="ssh",
        version="9.6p1",
        banner="SSH-2.0-OpenSSH_9.6p1",
    )

    assert "OpenSSH 9.6p1" in technology_names(result)


def test_results_are_unique_by_name_and_category():
    result = fingerprint_technology(
        service="http",
        banner="HTTP/1.1 200 OK\r\nServer: Apache/2.4.7",
        http_details={
            "server": "Apache/2.4.7",
            "headers": {},
        },
    )

    keys = [
        (
            item["name"].lower(),
            item["category"].lower(),
        )
        for item in result
    ]

    assert len(keys) == len(set(keys))
