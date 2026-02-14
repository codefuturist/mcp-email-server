"""Integration tests for SMTP with different security settings.

Tests exercise EmailClient.send_email() in multiple security modes:
- ConnectionSecurity.NONE     (plaintext — covered in test_smtp_live.py)
- ConnectionSecurity.TLS      (Implicit TLS via self-signed cert)
- ConnectionSecurity.STARTTLS (upgrade to TLS via STARTTLS command)
- Connection test diagnostics with wrong security settings

Run: make test-integration
"""

from __future__ import annotations

import pytest

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import test_smtp_connection as check_smtp_connection

from .conftest import TEST_PASSWORD, TEST_USER

pytestmark = pytest.mark.integration


class TestSmtpImplicitTLS:
    """SMTP operations over Implicit TLS (ConnectionSecurity.TLS)."""

    async def test_connection_success(self, smtp_tls_email_server):
        """Verify TLS connection + login succeeds."""
        result = await check_smtp_connection(smtp_tls_email_server, timeout=5)
        assert result.startswith("✅")
        assert "tls" in result

    async def test_send_basic_email(self, smtp_tls_client, smtpserver_tls):
        """Verify sending works over Implicit TLS."""
        await smtp_tls_client.send_email(
            recipients=["to@localhost"],
            subject="TLS Send Test",
            body="Sent over Implicit TLS!",
        )

        assert len(smtpserver_tls.outbox) == 1
        msg = smtpserver_tls.outbox[0]
        assert msg["Subject"] == "TLS Send Test"

    async def test_send_html_email(self, smtp_tls_client, smtpserver_tls):
        """Verify HTML emails work over TLS."""
        await smtp_tls_client.send_email(
            recipients=["to@localhost"],
            subject="TLS HTML",
            body="<h1>TLS</h1>",
            html=True,
        )

        assert len(smtpserver_tls.outbox) == 1
        assert smtpserver_tls.outbox[0].get_content_type() == "text/html"

    async def test_send_with_attachment(self, smtp_tls_client, smtpserver_tls, tmp_path):
        """Verify attachments work over TLS."""
        attachment = tmp_path / "secure.txt"
        attachment.write_text("secure attachment")

        await smtp_tls_client.send_email(
            recipients=["to@localhost"],
            subject="TLS Attachment",
            body="See attached",
            attachments=[str(attachment)],
        )

        assert len(smtpserver_tls.outbox) == 1
        assert smtpserver_tls.outbox[0].is_multipart()


class TestSmtpStartTLS:
    """SMTP operations with STARTTLS upgrade."""

    async def test_connection_success(self, smtp_starttls_email_server):
        """Verify STARTTLS connection + login succeeds."""
        result = await check_smtp_connection(smtp_starttls_email_server, timeout=5)
        assert result.startswith("✅")
        assert "starttls" in result

    async def test_send_basic_email(self, smtp_starttls_client, smtpserver_starttls):
        """Verify sending works with STARTTLS upgrade."""
        await smtp_starttls_client.send_email(
            recipients=["to@localhost"],
            subject="STARTTLS Send Test",
            body="Sent with STARTTLS upgrade!",
        )

        assert len(smtpserver_starttls.outbox) == 1
        msg = smtpserver_starttls.outbox[0]
        assert msg["Subject"] == "STARTTLS Send Test"

    async def test_send_with_cc_bcc(self, smtp_starttls_client, smtpserver_starttls):
        """Verify CC/BCC work with STARTTLS."""
        await smtp_starttls_client.send_email(
            recipients=["to@localhost"],
            subject="STARTTLS CC/BCC",
            body="CC and BCC over STARTTLS",
            cc=["cc@localhost"],
            bcc=["bcc@localhost"],
        )

        assert len(smtpserver_starttls.outbox) == 1
        msg = smtpserver_starttls.outbox[0]
        assert msg["Cc"] == "cc@localhost"
        assert msg.get("Bcc") is None


class TestSmtpSecurityMismatch:
    """Test that wrong security settings produce clear error messages."""

    async def test_tls_on_plaintext_server(self, smtpserver):
        """TLS client against plaintext SMTP server should fail clearly."""
        host, port = smtpserver.addr
        server = EmailServer(
            host=host,
            port=port,
            user_name=TEST_USER,
            password=TEST_PASSWORD,
            security=ConnectionSecurity.TLS,
            verify_ssl=False,
        )
        result = await check_smtp_connection(server, timeout=3)
        assert result.startswith("❌")

    async def test_plaintext_on_tls_server(self, smtpserver_tls):
        """Plaintext client against TLS SMTP server should fail."""
        host, port = smtpserver_tls.addr
        server = EmailServer(
            host=host,
            port=port,
            user_name=TEST_USER,
            password=TEST_PASSWORD,
            security=ConnectionSecurity.NONE,
            verify_ssl=False,
        )
        result = await check_smtp_connection(server, timeout=3)
        assert result.startswith("❌")

    async def test_verify_ssl_true_rejects_self_signed(self, smtpserver_tls):
        """verify_ssl=True should reject our self-signed certificate."""
        host, port = smtpserver_tls.addr
        server = EmailServer(
            host=host,
            port=port,
            user_name=TEST_USER,
            password=TEST_PASSWORD,
            security=ConnectionSecurity.TLS,
            verify_ssl=True,
        )
        result = await check_smtp_connection(server, timeout=3)
        assert result.startswith("❌")
        assert "SSL" in result or "certificate" in result.lower()
