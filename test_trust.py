"""Phase 1: trust store beyond bare pubkey-hex TOFU.

TOFU on its own answers one question ("have I seen this key?") and
nothing else. These tests cover the additions: structured records,
migration from the old flat file, verification that survives reconnects,
and the two substitution cases plain TOFU cannot see.
"""
import json

import pytest

from memnode import config
from memnode.peers import PeerManager, TrustStore, pairing_uri, render_qr_ascii
from memnode.security import NodeIdentity, short_authentication_string

KEY_A = "aa" * 32
KEY_B = "bb" * 32


def _store(tmp_path) -> TrustStore:
    return TrustStore(path=tmp_path / "trusted_devices.json")


# -- storage format ---------------------------------------------------------

def test_trust_and_reload(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "laptop", addr="192.0.2.5:8080")
    assert s.is_trusted(KEY_A)

    reloaded = _store(tmp_path)
    assert reloaded.is_trusted(KEY_A)
    entry = reloaded.get(KEY_A)
    assert entry["name"] == "laptop"
    assert entry["method"] == "tofu"
    assert entry["verified"] is False
    assert "192.0.2.5:8080" in entry["addresses"]
    assert entry["first_seen"] > 0


def test_v1_flat_file_is_migrated(tmp_path):
    path = tmp_path / "trusted_devices.json"
    path.write_text(json.dumps({KEY_A: "old-laptop"}))

    s = TrustStore(path=path)
    assert s.is_trusted(KEY_A)
    assert s.get(KEY_A)["name"] == "old-laptop"
    assert s.get(KEY_A)["verified"] is False

    on_disk = json.loads(path.read_text())
    assert on_disk["version"] == config.TRUST_STORE_VERSION
    assert KEY_A in on_disk["peers"]


def test_corrupt_file_does_not_crash(tmp_path):
    path = tmp_path / "trusted_devices.json"
    path.write_text("{not json at all")
    s = TrustStore(path=path)
    assert s.all() == {}


# -- verification -----------------------------------------------------------

def test_verification_is_sticky_across_reconnects(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "phone")
    assert s.mark_verified(KEY_A, method="qr") is True
    assert s.is_verified(KEY_A)

    # A later plain-TOFU refresh must not silently downgrade a peer that
    # was confirmed out of band.
    s.trust(KEY_A, "phone", verified=False, method="tofu")
    assert s.is_verified(KEY_A)
    assert s.get(KEY_A)["method"] == "qr"


def test_mark_verified_on_unknown_key_is_false(tmp_path):
    assert _store(tmp_path).mark_verified(KEY_B) is False


def test_revoke(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "laptop")
    assert s.revoke(KEY_A) is True
    assert s.is_trusted(KEY_A) is False
    assert s.revoke(KEY_A) is False


# -- substitution detection -------------------------------------------------

def test_flags_a_familiar_name_on_a_new_identity(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "work-laptop")
    warnings = s.identity_conflicts(KEY_B, "work-laptop")
    assert warnings and "already pinned to a different identity" in warnings[0]


def test_flags_a_known_identity_that_renamed_itself(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "work-laptop")
    warnings = s.identity_conflicts(KEY_A, "totally-different")
    assert warnings and "previously called itself" in warnings[0]


def test_no_warning_for_a_clean_first_contact(tmp_path):
    s = _store(tmp_path)
    s.trust(KEY_A, "work-laptop")
    assert s.identity_conflicts(KEY_B, "phone") == []


# -- out-of-band helpers ----------------------------------------------------

def test_pairing_uri_contains_key_and_code():
    uri = pairing_uri(KEY_A, "123456", "my node")
    assert uri.startswith("memcloud://pair?pk=" + KEY_A)
    assert "sas=123456" in uri
    assert "my%20node" in uri


def test_qr_rendering_degrades_gracefully():
    """Missing optional dependency must return None, never raise: a
    display helper is not allowed to break pairing."""
    out = render_qr_ascii(pairing_uri(KEY_A, "123456"))
    assert out is None or isinstance(out, str)


def test_sas_differs_for_different_transcripts():
    assert short_authentication_string(b"\x01" * 32) != short_authentication_string(b"\x02" * 32)


# -- consent flow -----------------------------------------------------------

@pytest.mark.asyncio
async def test_consent_callback_receives_the_sas(tmp_path):
    seen = {}

    def consent(pubkey, name, addr, sas):
        seen.update(pubkey=pubkey, name=name, addr=addr, sas=sas)
        return True

    pm = PeerManager(NodeIdentity.generate(), "node", 1024, consent_callback=consent)
    pm.trust_store = _store(tmp_path)

    assert await pm._check_consent(KEY_A, "peer", "192.0.2.1:8080", "654321") is True
    assert seen["sas"] == "654321"
    assert pm.trust_store.is_trusted(KEY_A)


@pytest.mark.asyncio
async def test_legacy_three_argument_consent_callback_still_works(tmp_path):
    """Callbacks written against the pre-Phase-1 signature must not break."""
    calls = []

    def legacy_consent(pubkey, name, addr):
        calls.append((pubkey, name, addr))
        return True

    pm = PeerManager(NodeIdentity.generate(), "node", 1024, consent_callback=legacy_consent)
    pm.trust_store = _store(tmp_path)

    assert await pm._check_consent(KEY_A, "peer", "192.0.2.1:8080", "654321") is True
    assert calls == [(KEY_A, "peer", "192.0.2.1:8080")]


@pytest.mark.asyncio
async def test_denied_consent_is_not_recorded(tmp_path):
    pm = PeerManager(NodeIdentity.generate(), "node", 1024,
                     consent_callback=lambda *_a: False)
    pm.trust_store = _store(tmp_path)
    assert await pm._check_consent(KEY_A, "peer", "addr", "111111") is False
    assert pm.trust_store.is_trusted(KEY_A) is False


@pytest.mark.asyncio
async def test_known_peer_skips_the_prompt(tmp_path):
    prompts = []

    def consent(*args):
        prompts.append(args)
        return True

    pm = PeerManager(NodeIdentity.generate(), "node", 1024, consent_callback=consent)
    pm.trust_store = _store(tmp_path)

    await pm._check_consent(KEY_A, "peer", "addr", "111111")
    await pm._check_consent(KEY_A, "peer", "addr", "222222")
    assert len(prompts) == 1, "an already-trusted peer must not re-prompt"


@pytest.mark.asyncio
async def test_require_verification_reprompts_an_unverified_peer(tmp_path):
    prompts = []

    def consent(*args):
        prompts.append(args)
        return True

    pm = PeerManager(NodeIdentity.generate(), "node", 1024, consent_callback=consent,
                     require_sas_verification=True)
    pm.trust_store = _store(tmp_path)
    pm.trust_store.trust(KEY_A, "peer")          # TOFU-only record

    await pm._check_consent(KEY_A, "peer", "addr", "111111")
    assert len(prompts) == 1
    assert pm.trust_store.is_verified(KEY_A) is True

    await pm._check_consent(KEY_A, "peer", "addr", "111111")
    assert len(prompts) == 1, "once verified, no further prompt"
