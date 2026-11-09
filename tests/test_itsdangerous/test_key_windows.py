import hashlib
from datetime import datetime
from datetime import timezone

import pytest
from freezegun import freeze_time

from itsdangerous.exc import BadData
from itsdangerous.exc import BadSignature
from itsdangerous.exc import BadTimeSignature
from itsdangerous.exc import KeyWindowViolation
from itsdangerous.exc import NoSigningKeyError
from itsdangerous.exc import SignatureExpired
from itsdangerous.timed import KeyWindow
from itsdangerous.timed import TimedSerializer
from itsdangerous.timed import TimestampSigner
from itsdangerous.url_safe import URLSafeTimedSerializer

T0 = 1_700_000_000

KEYS = ["old-secret", "new-secret"]
OLD_WINDOW = {
    "not_before": T0 - 1000,
    "sign_until": T0 + 1000,
    "verify_until": T0 + 2000,
}
NEW_WINDOW = {
    "not_before": T0 + 500,
    "sign_until": T0 + 3000,
    "verify_until": T0 + 4000,
}
WINDOWS = [OLD_WINDOW, NEW_WINDOW]


def at(ts):
    return freeze_time(datetime.fromtimestamp(ts, tz=timezone.utc))


def make_signer(**kwargs):
    return TimestampSigner(KEYS, key_windows=WINDOWS, **kwargs)


def signed_by(token, secret_key):
    return TimestampSigner(secret_key).validate(token)


class TestKeyWindowLifecycle:
    def test_full_rotation_lifecycle(self):
        # Phase 1: only the old key may sign.
        with at(T0):
            old_token = make_signer().sign(b"value")

        assert signed_by(old_token, "old-secret")
        assert not signed_by(old_token, "new-secret")

        # Phase 2: overlap, the newest eligible key signs.
        with at(T0 + 750):
            signer = make_signer()
            overlap_token = signer.sign(b"value")
            assert signer.unsign(old_token) == b"value"

        assert signed_by(overlap_token, "new-secret")
        assert not signed_by(overlap_token, "old-secret")

        # Phase 3: the old key stopped signing but still verifies.
        with at(T0 + 1500):
            signer = make_signer()
            new_token = signer.sign(b"value")
            assert signer.unsign(old_token) == b"value"

        assert signed_by(new_token, "new-secret")

        # Phase 4: the old key is fully retired, old links are rejected.
        with at(T0 + 2500):
            signer = make_signer()

            with pytest.raises(KeyWindowViolation):
                signer.unsign(old_token)

            assert signer.unsign(new_token) == b"value"

        # Phase 5: every key is retired, signing and verifying fail.
        with at(T0 + 4500):
            signer = make_signer()

            with pytest.raises(NoSigningKeyError):
                signer.sign(b"value")

            with pytest.raises(KeyWindowViolation):
                signer.unsign(new_token)

    def test_exception_hierarchy(self):
        assert issubclass(KeyWindowViolation, BadTimeSignature)
        assert issubclass(KeyWindowViolation, BadSignature)
        assert issubclass(NoSigningKeyError, BadData)

        with at(T0 + 4500):
            with pytest.raises(BadData):
                make_signer().sign(b"value")

    def test_window_rejection_caught_as_bad_signature(self):
        with at(T0):
            token = make_signer().sign(b"value")

        with at(T0 + 2500):
            signer = make_signer()

            with pytest.raises(BadTimeSignature):
                signer.unsign(token)

            assert not signer.validate(token)

    def test_plain_mismatch_still_bad_time_signature(self):
        with at(T0):
            token = make_signer().sign(b"value")

        token = token.replace(b"value", b"other", 1)

        with at(T0):
            with pytest.raises(BadTimeSignature) as exc_info:
                make_signer().unsign(token)

            assert not isinstance(exc_info.value, KeyWindowViolation)
            assert "does not match" in str(exc_info.value)


class TestKeyWindowBoundaries:
    @pytest.fixture()
    def signer(self):
        return TimestampSigner(
            "key",
            key_windows=[
                {"not_before": T0, "sign_until": T0 + 10, "verify_until": T0 + 20}
            ],
        )

    def test_sign_window_edges(self, signer):
        with at(T0 - 1):
            with pytest.raises(NoSigningKeyError):
                signer.sign(b"value")

        with at(T0):
            assert signer.unsign(signer.sign(b"value")) == b"value"

        with at(T0 + 9):
            assert signer.unsign(signer.sign(b"value")) == b"value"

        with at(T0 + 10):
            with pytest.raises(NoSigningKeyError):
                signer.sign(b"value")

    def test_verify_until_is_exclusive(self, signer):
        with at(T0):
            token = signer.sign(b"value")

        with at(T0 + 19):
            assert signer.unsign(token) == b"value"

        with at(T0 + 20):
            with pytest.raises(KeyWindowViolation):
                signer.unsign(token)

    def test_token_timestamp_must_be_inside_signing_window(self, signer):
        # A legacy token signed exactly at sign_until is rejected.
        with at(T0 + 10):
            legacy = TimestampSigner("key").sign(b"value")

        with at(T0 + 10):
            with pytest.raises(KeyWindowViolation):
                signer.unsign(legacy)

        # A legacy token signed before not_before is rejected.
        with at(T0 - 1):
            legacy = TimestampSigner("key").sign(b"value")

        with at(T0):
            with pytest.raises(KeyWindowViolation):
                signer.unsign(legacy)

    def test_legacy_token_format_still_verifies(self, signer):
        # Tokens signed before key_windows was configured keep working
        # while the key's window allows it.
        with at(T0 + 5):
            legacy = TimestampSigner("key").sign(b"value")

        with at(T0 + 15):
            assert signer.unsign(legacy) == b"value"

        with at(T0 + 20):
            with pytest.raises(KeyWindowViolation):
                signer.unsign(legacy)


class TestKeyWindowMaxAge:
    @pytest.fixture()
    def signer(self):
        return TimestampSigner(
            "key",
            key_windows=[
                {"not_before": T0, "sign_until": T0 + 10, "verify_until": T0 + 20}
            ],
        )

    def test_max_age_still_applies(self, signer):
        with at(T0):
            token = signer.sign(b"value")

        with at(T0 + 15):
            with pytest.raises(SignatureExpired):
                signer.unsign(token, max_age=10)

            assert signer.unsign(token, max_age=100) == b"value"

    def test_window_rejects_when_max_age_would_pass(self, signer):
        with at(T0):
            token = signer.sign(b"value")

        with at(T0 + 25):
            with pytest.raises(KeyWindowViolation):
                signer.unsign(token, max_age=1000)

    def test_future_timestamp_rejected(self, signer):
        with at(T0 + 5):
            token = signer.sign(b"value")

        with at(T0):
            with pytest.raises(SignatureExpired):
                signer.unsign(token, max_age=10)


class TestKeyWindowValidation:
    def test_length_mismatch(self):
        with pytest.raises(ValueError, match="correspond by position"):
            TimestampSigner(["a", "b"], key_windows=[(0, 10, 20)])

    def test_duplicate_secret_keys(self):
        with pytest.raises(ValueError, match="duplicate"):
            TimestampSigner(["a", "a"], key_windows=[(0, 10, 20), (0, 10, 20)])

    @pytest.mark.parametrize(
        "window",
        [
            {"not_before": 10, "sign_until": 10, "verify_until": 20},
            {"not_before": 11, "sign_until": 10, "verify_until": 20},
            {"not_before": 0, "sign_until": 30, "verify_until": 20},
            {"not_before": 0.5, "sign_until": 10, "verify_until": 20},
            {"not_before": 0, "sign_until": "10", "verify_until": 20},
            {"not_before": True, "sign_until": 10, "verify_until": 20},
            {"not_before": 0, "sign_until": 10},
            (0, 10),
            "not-a-window",
        ],
    )
    def test_invalid_windows_rejected(self, window):
        with pytest.raises(ValueError):
            TimestampSigner("key", key_windows=[window])

    def test_valid_forms_accepted(self):
        signer = TimestampSigner(
            "key",
            key_windows=[KeyWindow(not_before=0, sign_until=10, verify_until=10)],
        )
        assert signer.key_windows == [KeyWindow(0, 10, 10)]

        signer = TimestampSigner("key", key_windows=[(0, 10, 20)])
        assert signer.key_windows == [KeyWindow(0, 10, 20)]

    def test_config_is_copied(self):
        windows = [{"not_before": T0, "sign_until": T0 + 10, "verify_until": T0 + 20}]
        signer = TimestampSigner("key", key_windows=windows)
        windows[0]["sign_until"] = T0 + 1000
        windows.append({"not_before": 0, "sign_until": 1, "verify_until": 2})

        with at(T0 + 50):
            with pytest.raises(NoSigningKeyError):
                signer.sign(b"value")

    def test_serializer_validates_at_construction(self):
        with pytest.raises(ValueError):
            TimedSerializer(["a", "b"], key_windows=[(0, 10, 20)])


class TestTimedSerializerKeyWindows:
    def make_serializer(self, **kwargs):
        return TimedSerializer(KEYS, key_windows=WINDOWS, **kwargs)

    def test_dumps_loads_across_rotation(self):
        with at(T0):
            old_token = self.make_serializer().dumps({"k": "v"})

        with at(T0 + 1500):
            serializer = self.make_serializer()
            assert serializer.loads(old_token) == {"k": "v"}
            new_token = serializer.dumps({"k": "v"})

        with at(T0 + 2500):
            serializer = self.make_serializer()

            with pytest.raises(KeyWindowViolation):
                serializer.loads(old_token)

            assert serializer.loads(new_token) == {"k": "v"}

    def test_dumps_without_signing_key(self):
        with at(T0 + 4500):
            with pytest.raises(NoSigningKeyError):
                self.make_serializer().dumps({"k": "v"})

    def test_max_age_combines_with_windows(self):
        with at(T0 + 1500):
            token = self.make_serializer().dumps("value")

        with at(T0 + 1505):
            assert self.make_serializer().loads(token, max_age=10) == "value"

            with pytest.raises(SignatureExpired):
                self.make_serializer().loads(token, max_age=4)

    def test_url_safe_timed_serializer(self):
        serializer = URLSafeTimedSerializer(KEYS, key_windows=WINDOWS)

        with at(T0 + 1500):
            token = serializer.dumps("value")
            assert serializer.loads(token) == "value"

        with at(T0 + 3500):
            assert serializer.loads(token) == "value"

        with at(T0 + 4500):
            with pytest.raises(KeyWindowViolation):
                serializer.loads(token)

    def test_fallback_signers_enforce_same_windows(self):
        serializer = self.make_serializer(
            fallback_signers=[{"digest_method": hashlib.sha512}]
        )
        legacy = TimedSerializer(
            KEYS,
            key_windows=WINDOWS,
            signer_kwargs={"digest_method": hashlib.sha512},
        )

        # Old-format (sha512) token signed by the old key verifies while
        # the old key's window allows it.
        with at(T0):
            token = legacy.dumps("value")

        with at(T0 + 1500):
            assert serializer.loads(token) == "value"

        # Once the old key is retired, the fallback digest cannot
        # re-accept it.
        with at(T0 + 2500):
            with pytest.raises(KeyWindowViolation):
                serializer.loads(token)

    def test_fallback_retired_key_default_digest(self):
        serializer = self.make_serializer(
            fallback_signers=[{"digest_method": hashlib.sha512}]
        )

        with at(T0):
            token = serializer.dumps("value")

        with at(T0 + 2500):
            with pytest.raises(KeyWindowViolation):
                serializer.loads(token)

    def test_fallback_accepts_old_digest_within_window(self):
        serializer = self.make_serializer(
            fallback_signers=[{"digest_method": hashlib.sha512}]
        )
        legacy = TimedSerializer(
            KEYS,
            key_windows=WINDOWS,
            signer_kwargs={"digest_method": hashlib.sha512},
        )

        with at(T0 + 1500):
            token = legacy.dumps("value")

        with at(T0 + 3500):
            assert serializer.loads(token) == "value"

    def test_no_windows_behavior_unchanged(self):
        serializer = TimedSerializer(KEYS)

        with at(T0):
            token = serializer.dumps("value")

        with at(T0 + 10_000):
            assert serializer.loads(token) == "value"
