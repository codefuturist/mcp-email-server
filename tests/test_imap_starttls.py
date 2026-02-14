"""Tests for IMAP STARTTLS support and ConnectionSecurity enum."""

from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_email_server.config import ConnectionSecurity, EmailServer, EmailSettings


class TestConnectionSecurity:
    """Tests for the ConnectionSecurity enum and EmailServer model."""

    def test_default_security_is_tls(self):
        server = EmailServer(user_name="u", password="p", host="h", port=993)
        assert server.security == ConnectionSecurity.TLS

    def test_explicit_security_tls(self):
        server = EmailServer(user_name="u", password="p", host="h", port=993, security="tls")
        assert server.security == ConnectionSecurity.TLS

    def test_explicit_security_starttls(self):
        server = EmailServer(user_name="u", password="p", host="h", port=143, security="starttls")
        assert server.security == ConnectionSecurity.STARTTLS

    def test_explicit_security_none(self):
        server = EmailServer(user_name="u", password="p", host="h", port=143, security="none")
        assert server.security == ConnectionSecurity.NONE

    def test_legacy_use_ssl_true(self):
        server = EmailServer(user_name="u", password="p", host="h", port=993, use_ssl=True)
        assert server.security == ConnectionSecurity.TLS

    def test_legacy_use_ssl_false_start_ssl_true(self):
        server = EmailServer(user_name="u", password="p", host="h", port=143, use_ssl=False, start_ssl=True)
        assert server.security == ConnectionSecurity.STARTTLS

    def test_legacy_use_ssl_false_start_ssl_false(self):
        server = EmailServer(user_name="u", password="p", host="h", port=143, use_ssl=False, start_ssl=False)
        assert server.security == ConnectionSecurity.NONE

    def test_legacy_use_ssl_false_only(self):
        """use_ssl=False alone should default to TLS (secure by default)."""
        server = EmailServer(user_name="u", password="p", host="h", port=993, use_ssl=False)
        assert server.security == ConnectionSecurity.TLS

    def test_legacy_start_ssl_false_only(self):
        """start_ssl=False alone should default to TLS (secure by default)."""
        server = EmailServer(user_name="u", password="p", host="h", port=993, start_ssl=False)
        assert server.security == ConnectionSecurity.TLS

    def test_legacy_start_ssl_true_only(self):
        server = EmailServer(user_name="u", password="p", host="h", port=143, start_ssl=True)
        # use_ssl defaults to None (not set), start_ssl=True → STARTTLS
        assert server.security == ConnectionSecurity.STARTTLS

    def test_invalid_use_ssl_and_start_ssl_both_true(self):
        with pytest.raises(ValueError, match="cannot both be true"):
            EmailServer(user_name="u", password="p", host="h", port=993, use_ssl=True, start_ssl=True)

    def test_security_enum_values(self):
        assert ConnectionSecurity.TLS.value == "tls"
        assert ConnectionSecurity.STARTTLS.value == "starttls"
        assert ConnectionSecurity.NONE.value == "none"

    def test_verify_ssl_default_true(self):
        server = EmailServer(user_name="u", password="p", host="h", port=993)
        assert server.verify_ssl is True

    def test_verify_ssl_false(self):
        server = EmailServer(user_name="u", password="p", host="h", port=993, verify_ssl=False)
        assert server.verify_ssl is False

    def test_masked_preserves_security(self):
        server = EmailServer(user_name="u", password="secret", host="h", port=143, security="starttls")
        masked = server.masked()
        assert masked.security == ConnectionSecurity.STARTTLS
        assert masked.password == "*" * 8


class TestEmailSettingsInit:
    """Tests for EmailSettings.init() with new security parameters."""

    def test_init_with_security_params(self):
        settings = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@example.com",
            user_name="test",
            password="pass",
            imap_host="imap.example.com",
            smtp_host="smtp.example.com",
            imap_port=143,
            imap_security=ConnectionSecurity.STARTTLS,
            smtp_port=587,
            smtp_security=ConnectionSecurity.STARTTLS,
        )
        assert settings.incoming.security == ConnectionSecurity.STARTTLS
        assert settings.outgoing.security == ConnectionSecurity.STARTTLS

    def test_init_with_legacy_params(self):
        settings = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@example.com",
            user_name="test",
            password="pass",
            imap_host="imap.example.com",
            smtp_host="smtp.example.com",
            imap_ssl=False,
            smtp_ssl=False,
            smtp_start_ssl=True,
        )
        # imap_ssl=False alone → defaults to TLS (secure by default, start_ssl not set)
        assert settings.incoming.security == ConnectionSecurity.TLS
        # smtp_ssl=False + smtp_start_ssl=True → STARTTLS
        assert settings.outgoing.security == ConnectionSecurity.STARTTLS

    def test_init_default_is_tls(self):
        settings = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@example.com",
            user_name="test",
            password="pass",
            imap_host="imap.example.com",
            smtp_host="smtp.example.com",
        )
        assert settings.incoming.security == ConnectionSecurity.TLS
        assert settings.outgoing.security == ConnectionSecurity.TLS

    def test_init_with_verify_ssl(self):
        settings = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@example.com",
            user_name="test",
            password="pass",
            imap_host="localhost",
            smtp_host="localhost",
            imap_verify_ssl=False,
            smtp_verify_ssl=False,
        )
        assert settings.incoming.verify_ssl is False
        assert settings.outgoing.verify_ssl is False


class TestEmailSettingsFromEnv:
    """Tests for EmailSettings.from_env() with new security env vars."""

    def test_from_env_with_security_vars(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_SECURITY", "starttls")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_SECURITY", "starttls")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_PORT", "143")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_PORT", "587")

        settings = EmailSettings.from_env()
        assert settings is not None
        assert settings.incoming.security == ConnectionSecurity.STARTTLS
        assert settings.outgoing.security == ConnectionSecurity.STARTTLS

    def test_from_env_with_legacy_ssl_vars(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_SSL", "false")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_SSL", "false")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_START_SSL", "true")

        settings = EmailSettings.from_env()
        assert settings is not None
        # IMAP_SSL=false alone → defaults to TLS (secure by default, no start_ssl set)
        assert settings.incoming.security == ConnectionSecurity.TLS
        assert settings.outgoing.security == ConnectionSecurity.STARTTLS

    def test_from_env_security_takes_precedence_over_legacy(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "smtp.example.com")
        # New env var takes precedence
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_SECURITY", "starttls")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_SSL", "true")  # Should be ignored

        settings = EmailSettings.from_env()
        assert settings is not None
        assert settings.incoming.security == ConnectionSecurity.STARTTLS

    def test_from_env_with_imap_verify_ssl(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "localhost")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "localhost")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_VERIFY_SSL", "false")

        settings = EmailSettings.from_env()
        assert settings is not None
        assert settings.incoming.verify_ssl is False

    def test_from_env_invalid_security_value_uses_default(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_SECURITY", "invalid_value")

        settings = EmailSettings.from_env()
        assert settings is not None
        assert settings.incoming.security == ConnectionSecurity.TLS  # Falls back to default

    def test_from_env_invalid_smtp_security_uses_default(self, monkeypatch):
        monkeypatch.setenv("MCP_EMAIL_SERVER_EMAIL_ADDRESS", "test@example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_PASSWORD", "pass")
        monkeypatch.setenv("MCP_EMAIL_SERVER_IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("MCP_EMAIL_SERVER_SMTP_SECURITY", "invalid_value")

        settings = EmailSettings.from_env()
        assert settings is not None
        assert settings.outgoing.security == ConnectionSecurity.TLS  # Falls back to default


class TestImapConnection:
    """Tests for IMAP connection creation with different security modes."""

    @pytest.mark.asyncio
    async def test_create_imap_connection_tls(self):
        server = EmailServer(user_name="u", password="p", host="localhost", port=993, security="tls")

        with patch("mcp_email_server.emails.classic.aioimaplib") as mock_aioimaplib:
            mock_imap = AsyncMock()
            mock_imap._client_task = asyncio.Future()
            mock_imap._client_task.set_result(None)
            mock_imap.wait_hello_from_server = AsyncMock()
            mock_aioimaplib.IMAP4_SSL.return_value = mock_imap

            from mcp_email_server.emails.classic import _create_imap_connection

            result = await _create_imap_connection(server)

            mock_aioimaplib.IMAP4_SSL.assert_called_once()
            assert result is mock_imap

    @pytest.mark.asyncio
    async def test_create_imap_connection_none(self):
        server = EmailServer(user_name="u", password="p", host="localhost", port=143, security="none")

        with patch("mcp_email_server.emails.classic.aioimaplib") as mock_aioimaplib:
            mock_imap = AsyncMock()
            mock_imap._client_task = asyncio.Future()
            mock_imap._client_task.set_result(None)
            mock_imap.wait_hello_from_server = AsyncMock()
            mock_aioimaplib.IMAP4.return_value = mock_imap

            from mcp_email_server.emails.classic import _create_imap_connection

            result = await _create_imap_connection(server)

            mock_aioimaplib.IMAP4.assert_called_once_with("localhost", 143)
            assert result is mock_imap

    @pytest.mark.asyncio
    async def test_create_imap_connection_starttls(self):
        server = EmailServer(user_name="u", password="p", host="localhost", port=143, security="starttls")

        with (
            patch("mcp_email_server.emails.classic.aioimaplib") as mock_aioimaplib,
            patch("mcp_email_server.emails.classic._imap_starttls") as mock_starttls,
        ):
            mock_imap = AsyncMock()
            mock_imap._client_task = asyncio.Future()
            mock_imap._client_task.set_result(None)
            mock_imap.wait_hello_from_server = AsyncMock()
            mock_aioimaplib.IMAP4.return_value = mock_imap

            from mcp_email_server.emails.classic import _create_imap_connection

            result = await _create_imap_connection(server)

            mock_aioimaplib.IMAP4.assert_called_once_with("localhost", 143)
            mock_starttls.assert_called_once()
            assert result is mock_imap


class TestImapStarttls:
    """Tests for the _imap_starttls function."""

    @pytest.mark.asyncio
    async def test_starttls_succeeds(self):
        from mcp_email_server.emails.classic import _imap_starttls

        mock_imap = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.capabilities = {"STARTTLS", "IMAP4rev1"}
        mock_protocol.new_tag.return_value = "A001"
        mock_protocol.loop = asyncio.get_event_loop()
        mock_protocol.transport = MagicMock()

        # Mock execute to return OK
        mock_response = MagicMock()
        mock_response.result = "OK"
        mock_protocol.execute = AsyncMock(return_value=mock_response)
        mock_protocol.capability = AsyncMock()

        mock_imap.protocol = mock_protocol

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        mock_tls_transport = MagicMock()

        with patch("asyncio.get_running_loop") as mock_loop:
            mock_loop.return_value.start_tls = AsyncMock(return_value=mock_tls_transport)

            await _imap_starttls(mock_imap, ssl_ctx, "localhost")

            # Verify STARTTLS command was sent
            mock_protocol.execute.assert_called_once()
            cmd = mock_protocol.execute.call_args[0][0]
            assert cmd.name == "STARTTLS"

            # Verify transport was upgraded
            mock_loop.return_value.start_tls.assert_called_once()

            # Verify capabilities were re-fetched
            mock_protocol.capability.assert_called_once()

            # Verify transport was replaced
            assert mock_imap.protocol.transport is mock_tls_transport

    @pytest.mark.asyncio
    async def test_starttls_no_capability_raises(self):
        from mcp_email_server.emails.classic import _imap_starttls

        mock_imap = MagicMock()
        mock_imap.protocol.capabilities = {"IMAP4rev1"}  # No STARTTLS

        ssl_ctx = ssl.create_default_context()

        with pytest.raises(OSError, match="does not advertise STARTTLS"):
            await _imap_starttls(mock_imap, ssl_ctx, "localhost")

    @pytest.mark.asyncio
    async def test_starttls_command_fails_raises(self):
        from mcp_email_server.emails.classic import _imap_starttls

        mock_imap = MagicMock()
        mock_protocol = MagicMock()
        mock_protocol.capabilities = {"STARTTLS", "IMAP4rev1"}
        mock_protocol.new_tag.return_value = "A001"
        mock_protocol.loop = asyncio.get_event_loop()

        mock_response = MagicMock()
        mock_response.result = "NO"
        mock_protocol.execute = AsyncMock(return_value=mock_response)
        mock_imap.protocol = mock_protocol

        ssl_ctx = ssl.create_default_context()

        with pytest.raises(OSError, match="STARTTLS command failed"):
            await _imap_starttls(mock_imap, ssl_ctx, "localhost")


class TestEmailClientSecurity:
    """Tests for EmailClient with different security modes."""

    def test_client_tls_smtp_settings(self):
        from mcp_email_server.emails.classic import EmailClient

        server = EmailServer(user_name="u", password="p", host="h", port=993, security="tls")
        client = EmailClient(server)
        assert client.smtp_use_tls is True
        assert client.smtp_start_tls is False

    def test_client_starttls_smtp_settings(self):
        from mcp_email_server.emails.classic import EmailClient

        server = EmailServer(user_name="u", password="p", host="h", port=587, security="starttls")
        client = EmailClient(server)
        assert client.smtp_use_tls is False
        assert client.smtp_start_tls is True

    def test_client_none_smtp_settings(self):
        from mcp_email_server.emails.classic import EmailClient

        server = EmailServer(user_name="u", password="p", host="h", port=25, security="none")
        client = EmailClient(server)
        assert client.smtp_use_tls is False
        assert client.smtp_start_tls is False

    def test_client_legacy_compat_smtp_settings(self):
        from mcp_email_server.emails.classic import EmailClient

        server = EmailServer(user_name="u", password="p", host="h", port=587, use_ssl=False, start_ssl=True)
        client = EmailClient(server)
        assert client.smtp_use_tls is False
        assert client.smtp_start_tls is True


class TestImapSslContext:
    """Tests for IMAP SSL context creation."""

    def test_create_imap_ssl_context_verified(self):
        from mcp_email_server.emails.classic import _create_imap_ssl_context

        ctx = _create_imap_ssl_context(verify_ssl=True)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_create_imap_ssl_context_unverified(self):
        from mcp_email_server.emails.classic import _create_imap_ssl_context

        ctx = _create_imap_ssl_context(verify_ssl=False)
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False


class TestTomlBackwardCompat:
    """Tests for backward compatibility with existing TOML configs."""

    def test_security_takes_precedence_over_legacy(self):
        """When both `security` and legacy fields are set, `security` wins."""
        server = EmailServer(user_name="u", password="p", host="h", port=993, security="starttls", use_ssl=True)
        assert server.security == ConnectionSecurity.STARTTLS

    def test_legacy_toml_format_incoming(self):
        """Simulate loading a config with old use_ssl/start_ssl fields."""
        server = EmailServer.model_validate({
            "user_name": "user",
            "password": "pass",
            "host": "127.0.0.1",
            "port": 1143,
            "use_ssl": False,
            "start_ssl": True,
        })
        assert server.security == ConnectionSecurity.STARTTLS

    def test_new_toml_format(self):
        """Simulate loading a config with new security field."""
        server = EmailServer.model_validate({
            "user_name": "user",
            "password": "pass",
            "host": "127.0.0.1",
            "port": 1143,
            "security": "starttls",
            "verify_ssl": False,
        })
        assert server.security == ConnectionSecurity.STARTTLS
        assert server.verify_ssl is False

    def test_legacy_format_without_explicit_start_ssl(self):
        """Old configs without start_ssl should default to TLS."""
        server = EmailServer.model_validate({
            "user_name": "user",
            "password": "pass",
            "host": "imap.gmail.com",
            "port": 993,
            "use_ssl": True,
        })
        assert server.security == ConnectionSecurity.TLS


class TestParseSecurityEnv:
    """Tests for _parse_security_env helper function."""

    def test_none_returns_default(self):
        from mcp_email_server.config import _parse_security_env

        assert _parse_security_env(None) is None
        assert _parse_security_env(None, ConnectionSecurity.TLS) == ConnectionSecurity.TLS

    def test_valid_values(self):
        from mcp_email_server.config import _parse_security_env

        assert _parse_security_env("tls") == ConnectionSecurity.TLS
        assert _parse_security_env("STARTTLS") == ConnectionSecurity.STARTTLS
        assert _parse_security_env("None") == ConnectionSecurity.NONE

    def test_invalid_value_returns_default(self):
        from mcp_email_server.config import _parse_security_env

        assert _parse_security_env("invalid") is None
        assert _parse_security_env("invalid", ConnectionSecurity.TLS) == ConnectionSecurity.TLS

    def test_invalid_value_logs_warning(self):
        from mcp_email_server.config import _parse_security_env

        with patch("mcp_email_server.config.logger") as mock_logger:
            _parse_security_env("bogus", ConnectionSecurity.TLS)
            mock_logger.warning.assert_called_once()
            assert "bogus" in mock_logger.warning.call_args[0][0]


class TestValidatorEdgeCases:
    """Tests for model validator edge cases."""

    def test_validator_with_non_dict_data(self):
        """Validator should pass through non-dict data unchanged."""
        # When Pydantic passes a model instance (not a dict), the validator should return it as-is
        server = EmailServer(user_name="u", password="p", host="h", port=993)
        # Re-validate the same instance (triggers non-dict path)
        copy = EmailServer.model_validate(server)
        assert copy.security == ConnectionSecurity.TLS


class TestConnectionTest:
    """Tests for test_imap_connection and test_smtp_connection helpers."""

    @pytest.mark.asyncio
    async def test_imap_connection_success(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="imap.example.com", port=993)
        mock_imap = AsyncMock()
        mock_imap.login = AsyncMock(return_value=MagicMock(result="OK"))
        mock_imap.logout = AsyncMock()

        with patch("mcp_email_server.emails.classic._create_imap_connection", return_value=mock_imap):
            result = await test_imap_connection(server)
            assert "✅" in result
            assert "imap.example.com:993" in result

    @pytest.mark.asyncio
    async def test_imap_connection_auth_failure(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)
        mock_imap = AsyncMock()
        mock_imap.login = AsyncMock(return_value=MagicMock(result="NO"))
        mock_imap.logout = AsyncMock()

        with patch("mcp_email_server.emails.classic._create_imap_connection", return_value=mock_imap):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "authentication failed" in result.lower()

    @pytest.mark.asyncio
    async def test_imap_connection_refused(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=ConnectionRefusedError(),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "Connection refused" in result

    @pytest.mark.asyncio
    async def test_imap_connection_ssl_error(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=ssl.SSLCertVerificationError(),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "SSL certificate" in result

    @pytest.mark.asyncio
    async def test_imap_connection_timeout(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=asyncio.TimeoutError(),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "timed out" in result.lower()

    @pytest.mark.asyncio
    async def test_imap_connection_starttls_not_supported(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=143, security="starttls")

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=OSError("IMAP server does not advertise STARTTLS capability"),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "STARTTLS" in result

    @pytest.mark.asyncio
    async def test_smtp_connection_success(self):
        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="smtp.example.com", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock()
        mock_smtp.login = AsyncMock()
        mock_smtp.quit = AsyncMock()

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "✅" in result
            assert "smtp.example.com:465" in result

    @pytest.mark.asyncio
    async def test_smtp_connection_auth_failure(self):
        import aiosmtplib

        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="h", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock()
        mock_smtp.login = AsyncMock(side_effect=aiosmtplib.SMTPAuthenticationError(535, "Authentication failed"))
        mock_smtp.quit = AsyncMock()

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "❌" in result
            assert "authentication failed" in result.lower()

    @pytest.mark.asyncio
    async def test_smtp_connection_refused(self):
        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="h", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock(side_effect=ConnectionRefusedError())

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "❌" in result
            assert "Connection refused" in result

    @pytest.mark.asyncio
    async def test_imap_connection_generic_os_error(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=OSError("Network unreachable"),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "Network unreachable" in result
            assert "STARTTLS" not in result

    @pytest.mark.asyncio
    async def test_imap_connection_generic_exception(self):
        from mcp_email_server.emails.classic import test_imap_connection

        server = EmailServer(user_name="u", password="p", host="h", port=993)

        with patch(
            "mcp_email_server.emails.classic._create_imap_connection",
            side_effect=RuntimeError("unexpected"),
        ):
            result = await test_imap_connection(server)
            assert "❌" in result
            assert "unexpected" in result

    @pytest.mark.asyncio
    async def test_smtp_connection_ssl_error(self):
        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="h", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock(side_effect=ssl.SSLCertVerificationError())

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "❌" in result
            assert "SSL certificate" in result

    @pytest.mark.asyncio
    async def test_smtp_connection_timeout(self):
        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="h", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock(side_effect=asyncio.TimeoutError())

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "❌" in result
            assert "timed out" in result.lower()

    @pytest.mark.asyncio
    async def test_smtp_connection_generic_exception(self):
        from mcp_email_server.emails.classic import test_smtp_connection

        server = EmailServer(user_name="u", password="p", host="h", port=465)
        mock_smtp = AsyncMock()
        mock_smtp.connect = AsyncMock(side_effect=RuntimeError("unexpected"))

        with patch("mcp_email_server.emails.classic.aiosmtplib.SMTP", return_value=mock_smtp):
            result = await test_smtp_connection(server)
            assert "❌" in result
            assert "unexpected" in result


class TestForceCloseImap:
    """Tests for _force_close_imap defensive cleanup helper."""

    def test_closes_transport(self):
        from mcp_email_server.emails.classic import _force_close_imap

        mock_imap = MagicMock()
        mock_imap.protocol.transport.close = MagicMock()
        mock_imap._client_task.done.return_value = True

        _force_close_imap(mock_imap)
        mock_imap.protocol.transport.close.assert_called_once()

    def test_cancels_pending_client_task(self):
        from mcp_email_server.emails.classic import _force_close_imap

        mock_imap = MagicMock()
        mock_imap._client_task.done.return_value = False

        _force_close_imap(mock_imap)
        mock_imap._client_task.cancel.assert_called_once()

    def test_skips_cancel_when_task_done(self):
        from mcp_email_server.emails.classic import _force_close_imap

        mock_imap = MagicMock()
        mock_imap._client_task.done.return_value = True

        _force_close_imap(mock_imap)
        mock_imap._client_task.cancel.assert_not_called()

    def test_handles_missing_protocol(self):
        """Should not raise when imap has no protocol attribute."""
        from mcp_email_server.emails.classic import _force_close_imap

        mock_imap = MagicMock(spec=[])  # no attributes
        mock_imap._client_task = MagicMock()
        mock_imap._client_task.done.return_value = True
        _force_close_imap(mock_imap)  # should not raise

    def test_handles_none_transport(self):
        """Should not raise when transport is None."""
        from mcp_email_server.emails.classic import _force_close_imap

        mock_imap = MagicMock()
        mock_imap.protocol.transport = None
        mock_imap._client_task.done.return_value = True
        _force_close_imap(mock_imap)  # should not raise


class TestUpdateEmail:
    """Tests for Settings.update_email method."""

    def test_update_email_replaces_existing(self):
        from mcp_email_server.config import Settings

        settings = Settings(emails=[], providers=[])
        original = EmailSettings.init(
            account_name="test",
            full_name="Old",
            email_address="old@test.com",
            user_name="u",
            password="p",
            imap_host="h",
            smtp_host="h",
        )
        settings.add_email(original)
        assert settings.emails[0].full_name == "Old"

        updated = EmailSettings.init(
            account_name="test",
            full_name="New",
            email_address="new@test.com",
            user_name="u",
            password="p",
            imap_host="h",
            smtp_host="h",
        )
        settings.update_email(updated)
        assert len(settings.emails) == 1
        assert settings.emails[0].full_name == "New"
        assert settings.emails[0].email_address == "new@test.com"


class TestInitLegacyPaths:
    """Tests for EmailSettings.init() legacy ssl/start_ssl paths."""

    def test_init_with_legacy_smtp_ssl(self):
        """init() with smtp_ssl should pass use_ssl to outgoing server."""
        cfg = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@test.com",
            user_name="u",
            password="p",
            imap_host="imap.test.com",
            smtp_host="smtp.test.com",
            smtp_ssl=True,
        )
        assert cfg.outgoing.security == ConnectionSecurity.TLS

    def test_init_with_legacy_smtp_start_ssl(self):
        """init() with smtp_start_ssl should pass start_ssl to outgoing server."""
        cfg = EmailSettings.init(
            account_name="test",
            full_name="Test",
            email_address="test@test.com",
            user_name="u",
            password="p",
            imap_host="imap.test.com",
            smtp_host="smtp.test.com",
            smtp_start_ssl=True,
        )
        assert cfg.outgoing.security == ConnectionSecurity.STARTTLS
