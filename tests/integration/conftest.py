"""Fixtures for integration tests against real protocol servers.

Tier 1: Pure Python — no Docker required.
- MockImapServer from aioimaplib (ships with runtime dependency)
- pytest-localserver SMTP server (dev dependency group: integration)

Provides fixtures for all three ConnectionSecurity modes:
- NONE:     plaintext IMAP + SMTP (default fixtures)
- TLS:      Implicit TLS IMAP + SMTP via self-signed certs
- STARTTLS: tested at Docker tier (MockImapServer lacks STARTTLS support)
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import socket
import ssl
import tempfile
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import pytest
from aioimaplib.imap_testing_server import Mail, MockImapServer
from aiosmtpd.smtp import AuthResult
from pytest_localserver.smtp import Handler, Server

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import EmailClient

# ---------------------------------------------------------------------------
# Workaround: aioimaplib#128 — dangling asyncio tasks after IMAP connections
# aioimaplib's _client_task does not support asyncio cancellation and can
# linger after imap.logout(), preventing clean event-loop shutdown.
# This autouse fixture cancels all dangling tasks after each test.
# See: https://github.com/iroco-co/aioimaplib/issues/128
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def _cleanup_dangling_imap_tasks():
    """Cancel lingering aioimaplib tasks after each test to prevent hangs.

    Workaround for https://github.com/iroco-co/aioimaplib/issues/128
    aioimaplib's _client_task spawns asyncio tasks (create_connection, etc.)
    that do not support cancellation and linger after imap.logout().
    """
    tasks_before = set(asyncio.all_tasks())
    yield
    await asyncio.sleep(0.05)
    for task in asyncio.all_tasks() - tasks_before:
        if task.done() or task == asyncio.current_task():
            continue
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


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

    def __init__(self, host="localhost", port=0, ssl_context=None):
        from aiosmtpd.controller import Controller

        kwargs = {
            "authenticator": _accept_any,
            "auth_require_tls": False,
        }
        if ssl_context is not None:
            kwargs["tls_context"] = ssl_context
        Controller.__init__(
            self,
            Handler(),
            hostname=host,
            port=port,
            **kwargs,
        )


class AuthSmtpServerTLS(Server):
    """SMTP server that speaks Implicit TLS (wraps socket in TLS immediately)."""

    def __init__(self, host="localhost", port=0, ssl_context=None):
        from aiosmtpd.controller import Controller

        Controller.__init__(
            self,
            Handler(),
            hostname=host,
            port=port,
            authenticator=_accept_any,
            auth_require_tls=False,
            ssl_context=ssl_context,
        )


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _generate_self_signed_cert():
    """Generate a self-signed certificate and key for testing TLS.

    Returns (certfile_path, keyfile_path) as temporary files.
    Uses the cryptography library which ships with most Python environments.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])

    cert = (
        x509
        .CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    certfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)  # noqa: SIM115
    certfile.write(cert.public_bytes(serialization.Encoding.PEM))
    certfile.close()

    keyfile = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)  # noqa: SIM115
    keyfile.write(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
        )
    )
    keyfile.close()

    return certfile.name, keyfile.name


@pytest.fixture(scope="session")
def self_signed_cert():
    """Session-scoped self-signed TLS certificate for testing.

    Yields (certfile, keyfile, server_ssl_context, client_ssl_context).
    """
    import os

    certfile, keyfile = _generate_self_signed_cert()

    # Server-side context
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certfile, keyfile)

    # Client-side context (trusts the self-signed cert)
    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_ctx.load_verify_locations(certfile)

    yield certfile, keyfile, server_ctx, client_ctx

    os.unlink(certfile)
    os.unlink(keyfile)


# ---------------------------------------------------------------------------
# Plaintext (NONE) fixtures — default
# ---------------------------------------------------------------------------


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
    # wait_closed() can hang if aioimaplib left dangling connections (aioimaplib#128)
    with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
        await asyncio.wait_for(real_server.wait_closed(), timeout=1.0)


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


# ---------------------------------------------------------------------------
# Implicit TLS fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def imap_tls_server_and_port(self_signed_cert):
    """Start a MockImapServer with Implicit TLS on a random port."""
    _, _, server_ctx, _ = self_signed_cert
    port = _free_port()
    loop = asyncio.get_running_loop()
    server = MockImapServer(loop=loop)
    real_server = await server.run_server(host="127.0.0.1", port=port, ssl_context=server_ctx)

    yield server, port

    server.reset()
    real_server.close()
    # wait_closed() can hang if aioimaplib left dangling connections (aioimaplib#128)
    with contextlib.suppress(TimeoutError, asyncio.TimeoutError):
        await asyncio.wait_for(real_server.wait_closed(), timeout=1.0)


@pytest.fixture()
def imap_tls_email_server(imap_tls_server_and_port) -> EmailServer:
    """EmailServer config for Implicit TLS IMAP (verify_ssl=False for self-signed)."""
    _, port = imap_tls_server_and_port
    return EmailServer(
        host="127.0.0.1",
        port=port,
        user_name=TEST_USER,
        password=TEST_PASSWORD,
        security=ConnectionSecurity.TLS,
        verify_ssl=False,
    )


@pytest.fixture()
def imap_tls_client(imap_tls_email_server) -> EmailClient:
    """EmailClient wired to MockImapServer over Implicit TLS."""
    return EmailClient(imap_tls_email_server, sender=TEST_USER)


@pytest.fixture()
def smtpserver_tls(request, self_signed_cert):
    """SMTP server with Implicit TLS (wraps socket in TLS on connect)."""
    _, _, server_ctx, _ = self_signed_cert
    server = AuthSmtpServerTLS(ssl_context=server_ctx)
    server.start()
    request.addfinalizer(server.stop)
    return server


@pytest.fixture()
def smtp_tls_email_server(smtpserver_tls) -> EmailServer:
    """EmailServer config for Implicit TLS SMTP."""
    host, port = smtpserver_tls.addr
    return EmailServer(
        host=host,
        port=port,
        user_name=TEST_USER,
        password=TEST_PASSWORD,
        security=ConnectionSecurity.TLS,
        verify_ssl=False,
    )


@pytest.fixture()
def smtp_tls_client(smtp_tls_email_server) -> EmailClient:
    """EmailClient wired to SMTP over Implicit TLS."""
    return EmailClient(smtp_tls_email_server, sender=TEST_USER)


# ---------------------------------------------------------------------------
# STARTTLS SMTP fixture (MockImapServer lacks STARTTLS protocol support)
# ---------------------------------------------------------------------------


@pytest.fixture()
def smtpserver_starttls(request, self_signed_cert):
    """SMTP server that supports STARTTLS upgrade."""
    _, _, server_ctx, _ = self_signed_cert
    server = AuthSmtpServer(ssl_context=server_ctx)
    server.start()
    request.addfinalizer(server.stop)
    return server


@pytest.fixture()
def smtp_starttls_email_server(smtpserver_starttls) -> EmailServer:
    """EmailServer config for SMTP STARTTLS."""
    host, port = smtpserver_starttls.addr
    return EmailServer(
        host=host,
        port=port,
        user_name=TEST_USER,
        password=TEST_PASSWORD,
        security=ConnectionSecurity.STARTTLS,
        verify_ssl=False,
    )


@pytest.fixture()
def smtp_starttls_client(smtp_starttls_email_server) -> EmailClient:
    """EmailClient wired to SMTP with STARTTLS upgrade."""
    return EmailClient(smtp_starttls_email_server, sender=TEST_USER)


# ---------------------------------------------------------------------------
# Mail helpers
# ---------------------------------------------------------------------------


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
