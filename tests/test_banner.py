from config.settings import ASCII_BANNER
from config.settings import Settings
from core.banner_grabber import BannerGrabber


def test_ascii_banner_border_lines_align():
    lines = [line for line in ASCII_BANNER.format(version="2.0.0").splitlines() if line]

    assert len({len(line) for line in lines}) == 1
    assert all(line.startswith(("+", "|")) for line in lines)
    assert all(line.endswith(("+", "|")) for line in lines)


class _FakeSocket:
    def __init__(self, response):
        self.response = response

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        self.address = address

    def send(self, data):
        self.sent = data

    def sendall(self, data):
        self.sent = data

    def recv(self, size):
        return self.response

    def close(self):
        pass


def test_unknown_port_tries_http_fallback_for_silent_service(monkeypatch):
    responses = [
        b"",
        (
            b"HTTP/1.0 200 OK\r\n"
            b"Server: WordPress/5.8.0\r\n"
            b"Content-Length: 0\r\n\r\n"
        ),
    ]

    def fake_socket(*args, **kwargs):
        return _FakeSocket(responses.pop(0))

    monkeypatch.setattr("core.banner_grabber.socket.socket", fake_socket)
    grabber = BannerGrabber(
        settings=Settings(banner_timeout=1),
        enable_http_fingerprinting=False,
    )

    result = grabber.grab_banner("127.0.0.1", 18080, service_hint="unknown")

    assert result.parsed_name == "wordpress"
    assert result.parsed_version == "5.8.0"
    assert responses == []
