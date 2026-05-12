from core.input_parser import format_target_summary, parse_target_input


def test_format_target_summary_single_ip_is_one_host():
    assert format_target_summary(parse_target_input("127.0.0.1")) == "127.0.0.1 (1 host)"


def test_format_target_summary_uses_usable_ipv4_hosts_for_subnets():
    assert format_target_summary(["192.168.1.0/24"]) == "192.168.1.0/24 (254 hosts)"
