"""Fixtures for integration tests against real protocol servers.

Tier 1: Pure Python — no Docker required.
- MockImapServer from aioimaplib (ships with runtime dependency)
- pytest-localserver SMTP server (dev dependency group: integration)
"""

from __future__ import annotations

import asyncio
import socket
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest
from aioimaplib.imap_testing_server import Mail, MockImapServer
from aiosmtpd.smtp import AuthResult
from pytest_localserver.smtp import Handler, Server

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import EmailClient

TEST_USER = "testuser@localhost"
TEST_PASSWORD = "testpass"  # noqa: S105

# MockImapServer stores mailbox names verbatim.  The production code
# quotes mailbox names for RFC 3501 compatibility (_quote_mailbox wraps
# them in double-quotes, e.g. '"INBOX"').  We must inject mail into
# the *quoted* mailbox so it is visible to the production EmailClient.
QUOTED_INBOX = '"INBOX"'


def _accept_any(server, session, envelope, mechanism, auth_data):
    """Authenticator that accepts any credentials (for testing)."""
    return AuthResult(success=True)


class AuthSmtpServer(Server):
    """SMTP server that accepts AUTH LOGIN/PLAIN with any credentials."""

    def __init__(self, host="localhost", port=0):
        # Skip the parent __init__ and call Controller directly
        from aiosmtpd.controller import Controller

        Controller.__init__(
            self,
            Handler(),
            hostname=host,
            port=port,
            authenticator=_accept_any,
            auth_require_tls=False,
        )


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
async def imap_server_and_port():
    """Start a MockImapServer on a random port for each test.

    The server shares the test's event loop (required by aioimaplib).
    Yields (server, port) so tests can inject mail and create clients.
    """
    port = _free_port()
    loop = asyncio.get_running_loop()
    server = MockImapServer(loop=loop)
    real_server = await server.run_server(host="127.0.0.1", port=port)

    yield server, port

    server.reset()
    real_server.close()
    await real_server.wait_closed()


@pytest.fixture()
def imap_email_server(imap_server_and_port) -> EmailServer:
    """Create an EmailServer config pointing at the MockImapServer."""
    _, port = imap_server_and_port
    return EmailServer(
        host="127.0.0.1",
        port=port,
        user_name=TEST_USER,
        password=TEST_PASSWORD,
        security=ConnectionSecurity.NONE,
        verify_ssl=False,
    )


@pytest.fixture()
def imap_client(imap_email_server) -> EmailClient:
    """Create an EmailClient wired to the MockImapServer."""
    return EmailClient(imap_email_server, sender=TEST_USER)


@pytest.fixture()
def smtpserver(request):
    """SMTP server fixture that supports AUTH (unlike pytest-localserver default)."""
    server = AuthSmtpServer()
    server.start()
    request.addfinalizer(server.stop)
    return server


@pytest.fixture()
def smtp_email_server(smtpserver) -> EmailServer:
    """Create an EmailServer config pointing at our auth-enabled SMTP server."""
    host, port = smtpserver.addr
    return EmailServer(
        host=host,
        port=port,
        user_name=TEST_USER,
        password=TEST_PASSWORD,
        security=ConnectionSecurity.NONE,
        verify_ssl=False,
    )


@pytest.fixture()
def smtp_client(smtp_email_server) -> EmailClient:
    """Create an EmailClient wired to the pytest-localserver SMTP server."""
    return EmailClient(smtp_email_server, sender=TEST_USER)


def make_test_mail(
    to: str = TEST_USER,
    subject: str = "Test Subject",
    body: str = "Hello, World!",
    mail_from: str = "sender@localhost",
    **kwargs,
) -> Mail:
    """Create a Mail object for injection into MockImapServer."""
    return Mail.create(
        to=[to],
        mail_from=mail_from,
        subject=subject,
        content=body,
        **kwargs,
    )


def make_multipart_mail(
    to: str = TEST_USER,
    subject: str = "Test with Attachment",
    body: str = "See attached.",
    mail_from: str = "sender@localhost",
    attachment_name: str = "test.txt",
    attachment_content: bytes = b"attachment content",
) -> Mail:
    """Create a multipart Mail with an attachment for MockImapServer injection."""
    msg = MIMEMultipart()
    msg["To"] = to
    msg["From"] = mail_from
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    part = MIMEApplication(attachment_content, Name=attachment_name)
    part["Content-Disposition"] = f'attachment; filename="{attachment_name}"'
    msg.attach(part)

    return Mail(msg)
