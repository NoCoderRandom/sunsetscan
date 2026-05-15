import sunsetscan


class FakeModuleManager:
    def __init__(self, installed=False):
        self.installed = installed

    def is_installed(self, module_name):
        return self.installed


class FakeHardwareEOLDatabase:
    def __init__(self, available):
        self._available = available

    def available(self):
        return self._available


def test_hardware_eol_readiness_accepts_bundled_database(monkeypatch):
    monkeypatch.setattr(
        sunsetscan,
        "HardwareEOLDatabase",
        lambda: FakeHardwareEOLDatabase(available=True),
    )

    assert sunsetscan._default_module_ready("hardware-eol-home", FakeModuleManager()) is True


def test_missing_non_hardware_default_module_is_not_ready():
    assert sunsetscan._default_module_ready("mac-oui", FakeModuleManager()) is False


def test_installed_default_module_is_ready():
    assert sunsetscan._default_module_ready("mac-oui", FakeModuleManager(installed=True)) is True
