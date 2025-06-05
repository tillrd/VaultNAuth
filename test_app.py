"""Tests for VaultNAuth certificate generation."""
from app import generate_pfx_if_missing

TEST_PFX_PASSWORD = b"password"

def test_generate_pfx_creates_files(tmp_path):
    """Test that generate_pfx_if_missing creates all expected certificate files."""
    certs_dir = tmp_path / "certificates"
    certs_dir.mkdir()
    pfx_path = certs_dir / "sample.pfx"

    generate_pfx_if_missing(str(pfx_path), TEST_PFX_PASSWORD)

    assert pfx_path.exists()
    assert (certs_dir / "sample.crt").exists()
    assert (certs_dir / "sample.cer").exists()
    assert (certs_dir / "sample_public_cert.pem").exists()
    assert (certs_dir / "sample_private_key.pem").exists()
