from config.settings import ASCII_BANNER


def test_ascii_banner_border_lines_align():
    lines = [line for line in ASCII_BANNER.format(version="2.0.0").splitlines() if line]

    assert len({len(line) for line in lines}) == 1
    assert all(line.startswith(("+", "|")) for line in lines)
    assert all(line.endswith(("+", "|")) for line in lines)
