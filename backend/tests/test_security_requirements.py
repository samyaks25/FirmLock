"""Extra security requirement tests."""
import os
import importlib

import pytest


def test_jwt_secret_missing_in_production_raises(monkeypatch):
    monkeypatch.setenv("FIRMLOCK_ENV", "production")
    monkeypatch.delenv("FIRMLOCK_JWT_SECRET", raising=False)
    from app.core import config
    with pytest.raises(ValueError, match="FIRMLOCK_JWT_SECRET must be set"):
        importlib.reload(config)


def test_jwt_secret_short_in_production_raises(monkeypatch):
    monkeypatch.setenv("FIRMLOCK_ENV", "production")
    monkeypatch.setenv("FIRMLOCK_JWT_SECRET", "short")
    from app.core import config
    with pytest.raises(ValueError, match="at least 32 characters"):
        importlib.reload(config)


def test_untrusted_client_cannot_spoof_x_forwarded_for():
    from app.api.rate_limit import _get_client_ip
    from unittest.mock import MagicMock
    os.environ.pop("FIRMLOCK_TRUSTED_PROXIES", None)
    request = MagicMock()
    request.client.host = "203.0.113.5"
    request.headers.get = lambda k: "1.2.3.4" if k == "X-Forwarded-For" else None
    assert _get_client_ip(request) == "203.0.113.5"


def test_trusted_proxy_honors_x_forwarded_for(monkeypatch):
    monkeypatch.setenv("FIRMLOCK_TRUSTED_PROXIES", "127.0.0.1")
    from app.api.rate_limit import _get_client_ip
    from unittest.mock import MagicMock
    request = MagicMock()
    request.client.host = "127.0.0.1"
    request.headers.get = lambda k: "1.2.3.4" if k == "X-Forwarded-For" else None
    assert _get_client_ip(request) == "1.2.3.4"


def test_wildcard_host_rejects_lookalike_domains():
    from app.core.trusted_host import TrustedHostMiddleware
    mw = TrustedHostMiddleware.__new__(TrustedHostMiddleware)
    mw.allowed_hosts = {"*.example.com"}
    mw.www_redirect = False
    assert not mw._is_allowed_host("evil-example.com")
    assert not mw._is_allowed_host("example.com.evil.com")
    assert not mw._is_allowed_host("notexample.com")
    assert mw._is_allowed_host("sub.example.com")
