"""Fixtures for Docker-based integration tests (Tier 2).

GreenMail provides a real SMTP+IMAP server for full send→read roundtrip tests.
Tests auto-skip if Docker is not available.
"""

from __future__ import annotations

import shutil
import socket

import pytest

from mcp_email_server.config import ConnectionSecurity, EmailServer
from mcp_email_server.emails.classic import EmailClient

# GreenMail accepts any credentials when auth is disabled
GREENMAIL_USER = "testuser@localhost"
GREENMAIL_PASSWORD = "testpass"  # noqa: S105

GREENMAIL_SMTP_PORT = 3025
GREENMAIL_IMAP_PORT = 3143


def pytest_collection_modifyitems(config, items):
    """Auto-skip all docker tests if Docker is not available."""
    if not shutil.which("docker"):
        skip = pytest.mark.skip(reason="Docker not available")
        for item in items:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def docker_compose_file():
    """Point pytest-docker to our docker-compose.yml."""
    import pathlib

    return str(pathlib.Path(__file__).parent / "docker-compose.yml")


@pytest.fixture(scope="session")
def docker_setup():
    """Override default 'up --build --wait' to avoid healthcheck requirement."""
    return ["up --build -d"]


def _greenmail_is_ready() -> bool:
    """Check if GreenMail SMTP and IMAP services are actually ready.

    A simple socket connection is insufficient — GreenMail may accept TCP
    connections before the SMTP/IMAP handlers are initialized.
    """
    import smtplib

    try:
        # Test SMTP with a real EHLO handshake
        with smtplib.SMTP("127.0.0.1", GREENMAIL_SMTP_PORT, timeout=3) as smtp:
            smtp.ehlo()
        # Test IMAP socket
        with socket.create_connection(("127.0.0.1", GREENMAIL_IMAP_PORT), timeout=3):
            pass
        return True
    except Exception:
        return False


@pytest.fixture(scope="session")
def greenmail(docker_services):
    """Wait for GreenMail to be healthy and return connection details."""
    docker_services.wait_until_responsive(
        timeout=60.0,
        pause=1.0,
        check=_greenmail_is_ready,
    )
    return {
        "smtp_host": "127.0.0.1",
        "smtp_port": GREENMAIL_SMTP_PORT,
        "imap_host": "127.0.0.1",
        "imap_port": GREENMAIL_IMAP_PORT,
        "user": GREENMAIL_USER,
        "password": GREENMAIL_PASSWORD,
    }


@pytest.fixture()
def greenmail_smtp_server(greenmail) -> EmailServer:
    """EmailServer config for GreenMail SMTP."""
    return EmailServer(
        host=greenmail["smtp_host"],
        port=greenmail["smtp_port"],
        user_name=greenmail["user"],
        password=greenmail["password"],
        security=ConnectionSecurity.NONE,
        verify_ssl=False,
    )


@pytest.fixture()
def greenmail_imap_server(greenmail) -> EmailServer:
    """EmailServer config for GreenMail IMAP."""
    return EmailServer(
        host=greenmail["imap_host"],
        port=greenmail["imap_port"],
        user_name=greenmail["user"],
        password=greenmail["password"],
        security=ConnectionSecurity.NONE,
        verify_ssl=False,
    )


@pytest.fixture()
def greenmail_smtp_client(greenmail_smtp_server) -> EmailClient:
    """EmailClient wired to GreenMail SMTP."""
    return EmailClient(greenmail_smtp_server, sender=GREENMAIL_USER)


@pytest.fixture()
def greenmail_imap_client(greenmail_imap_server) -> EmailClient:
    """EmailClient wired to GreenMail IMAP."""
    return EmailClient(greenmail_imap_server, sender=GREENMAIL_USER)
