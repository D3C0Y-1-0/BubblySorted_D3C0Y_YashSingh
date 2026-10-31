from hedwig.core import versions


def test_compare_orders_numerically():
    assert versions.compare("4.17.15", "4.17.21") < 0
    assert versions.compare("2.14.1", "2.3.1") > 0
    assert versions.compare("5.4", "5.4.0") == 0
    assert versions.compare("v6.4.1", "6.4.1") == 0


def test_prerelease_sorts_before_release():
    assert versions.compare("2.0.0-beta1", "2.0.0") < 0
    assert versions.compare("5.3.1.RELEASE", "5.3.1") == 0


def test_major():
    assert versions.major("8.5.1") == 8
    assert versions.major("v9.0.0") == 9


def test_in_range_introduced_and_fixed():
    events = [{"introduced": "2.13.0"}, {"fixed": "2.15.0"}]
    assert versions.in_range("2.14.1", events)
    assert not versions.in_range("2.15.0", events)
    assert not versions.in_range("2.12.0", events)


def test_in_range_multiple_branches_and_last_affected():
    events = [
        {"introduced": "0"},
        {"fixed": "1.0.5"},
        {"introduced": "2.0.0"},
        {"last_affected": "2.2.0"},
    ]
    assert versions.in_range("1.0.4", events)
    assert not versions.in_range("1.5.0", events)
    assert versions.in_range("2.2.0", events)
    assert not versions.in_range("2.2.1", events)
