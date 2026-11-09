from __future__ import annotations

import collections.abc as cabc
import time
import typing as t
from datetime import datetime
from datetime import timezone

from .encoding import base64_decode
from .encoding import base64_encode
from .encoding import bytes_to_int
from .encoding import int_to_bytes
from .encoding import want_bytes
from .exc import BadSignature
from .exc import BadTimeSignature
from .exc import KeyWindowViolation
from .exc import NoSigningKeyError
from .exc import SignatureExpired
from .serializer import _TSerialized
from .serializer import Serializer
from .signer import Signer


class KeyWindow(t.NamedTuple):
    """Rotation window for one secret key, used with the
    ``key_windows`` argument of :class:`TimestampSigner` and
    :class:`TimedSerializer`. All values are integer UTC seconds.

    The key may sign while ``not_before <= now < sign_until``. A token
    verifies only if its authenticated signing time ``ts`` satisfies
    ``not_before <= ts < sign_until`` and the current time is strictly
    less than ``verify_until``.

    .. versionadded:: 2.3
    """

    #: The key may not sign, and its tokens do not verify, before this time.
    not_before: int
    #: The key stops signing at this time (exclusive). Tokens carry a
    #: signing time strictly earlier than this.
    sign_until: int
    #: The key stops verifying at this time (exclusive). Must be greater
    #: than or equal to ``sign_until``.
    verify_until: int


#: Accepted forms for one ``key_windows`` item: a :class:`KeyWindow`, a
#: mapping with ``not_before`` / ``sign_until`` / ``verify_until`` keys, or
#: a sequence of those three integers in order.
_KeyWindowConfig = KeyWindow | cabc.Mapping[str, int] | cabc.Sequence[int]


def _coerce_key_window(item: _KeyWindowConfig, index: int) -> KeyWindow:
    if isinstance(item, KeyWindow):
        window = item
    elif isinstance(item, cabc.Mapping):
        try:
            window = KeyWindow(
                not_before=item["not_before"],
                sign_until=item["sign_until"],
                verify_until=item["verify_until"],
            )
        except KeyError as e:
            raise ValueError(f"key_windows[{index}] is missing the {e} field") from None
    elif isinstance(item, cabc.Sequence) and not isinstance(item, (str, bytes)):
        values = list(item)

        if len(values) != 3:
            raise ValueError(
                f"key_windows[{index}] must have exactly 3 values:"
                " not_before, sign_until, verify_until"
            )

        window = KeyWindow(*values)
    else:
        raise ValueError(
            f"key_windows[{index}] must be a KeyWindow, a mapping with"
            " 'not_before', 'sign_until', and 'verify_until' keys, or a"
            " sequence of those 3 integers"
        )

    for name, value in window._asdict().items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"key_windows[{index}].{name} must be an integer number of"
                " UTC seconds"
            )

    if not window.not_before < window.sign_until <= window.verify_until:
        raise ValueError(
            f"key_windows[{index}] must satisfy"
            " not_before < sign_until <= verify_until"
        )

    return window


def _make_key_windows(
    secret_keys: list[bytes],
    key_windows: cabc.Iterable[_KeyWindowConfig] | None,
) -> list[KeyWindow] | None:
    """Validate and copy the ``key_windows`` configuration, returning a
    new list aligned by position with ``secret_keys``, or ``None`` if
    windows are not configured.
    """
    if key_windows is None:
        return None

    items = list(key_windows)

    if len(items) != len(secret_keys):
        raise ValueError(
            f"key_windows has {len(items)} entries but"
            f" {len(secret_keys)} secret keys are configured; they must"
            " correspond by position"
        )

    if len(set(secret_keys)) != len(secret_keys):
        raise ValueError("key_windows cannot be used with duplicate secret keys")

    return [_coerce_key_window(item, index) for index, item in enumerate(items)]


class TimestampSigner(Signer):
    """Works like the regular :class:`.Signer` but also records the time
    of the signing and can be used to expire signatures. The
    :meth:`unsign` method can raise :exc:`.SignatureExpired` if the
    unsigning failed because the signature is expired.

    :param key_windows: Optional per-key rotation windows, corresponding
        to ``secret_key`` by position. Each item is a :class:`KeyWindow`
        (or a mapping or 3-sequence of ``not_before``, ``sign_until``,
        ``verify_until``, integer UTC seconds). Signing uses the last key
        whose window is currently open; a token only verifies if the key
        that signed it was allowed to sign at the token's authenticated
        timestamp and has not passed its ``verify_until``. If not given,
        signing and verification behave as before.

    .. versionchanged:: 2.3
        Added the ``key_windows`` parameter.
    """

    def get_timestamp(self) -> int:
        """Returns the current timestamp. The function must return an
        integer.
        """
        return int(time.time())

    def timestamp_to_datetime(self, ts: int) -> datetime:
        """Convert the timestamp from :meth:`get_timestamp` into an
        aware :class`datetime.datetime` in UTC.

        .. versionchanged:: 2.0
            The timestamp is returned as a timezone-aware ``datetime``
            in UTC rather than a naive ``datetime`` assumed to be UTC.
        """
        return datetime.fromtimestamp(ts, tz=timezone.utc)

    def __init__(
        self,
        secret_key: str | bytes | cabc.Iterable[str] | cabc.Iterable[bytes],
        salt: str | bytes | None = b"itsdangerous.Signer",
        sep: str | bytes = b".",
        key_derivation: str | None = None,
        digest_method: t.Any | None = None,
        algorithm: t.Any | None = None,
        key_windows: cabc.Iterable[_KeyWindowConfig] | None = None,
    ):
        super().__init__(
            secret_key,
            salt=salt,
            sep=sep,
            key_derivation=key_derivation,
            digest_method=digest_method,
            algorithm=algorithm,
        )

        #: The validated per-key rotation windows, aligned with
        #: :attr:`secret_keys`, or ``None`` if not configured.
        self.key_windows: list[KeyWindow] | None = _make_key_windows(
            self.secret_keys, key_windows
        )

    def _get_signing_key_index(self, now: int) -> int:
        """Return the index of the last key allowed to sign at ``now``,
        or raise :exc:`.NoSigningKeyError` if no key window is open.
        """
        key_windows = t.cast("list[KeyWindow]", self.key_windows)

        for index in range(len(self.secret_keys) - 1, -1, -1):
            window = key_windows[index]

            if window.not_before <= now < window.sign_until:
                return index

        raise NoSigningKeyError(
            f"No secret key is allowed to sign at {now}; check the"
            " key_windows configuration"
        )

    def _find_matching_key_index(self, value: bytes, sig: bytes) -> int | None:
        """Return the index of the key whose signature matches, trying
        the newest key first, or ``None`` if no key matches.
        """
        try:
            sig = base64_decode(sig)
        except Exception:
            return None

        for index in range(len(self.secret_keys) - 1, -1, -1):
            key = self.derive_key(self.secret_keys[index])

            if self.algorithm.verify_signature(key, value, sig):
                return index

        return None

    def sign(self, value: str | bytes) -> bytes:
        """Signs the given string and also attaches time information."""
        value = want_bytes(value)
        now = self.get_timestamp()
        timestamp = base64_encode(int_to_bytes(now))
        sep = want_bytes(self.sep)
        value = value + sep + timestamp

        if self.key_windows is None:
            sig = self.get_signature(value)
        else:
            index = self._get_signing_key_index(now)
            key = self.derive_key(self.secret_keys[index])
            sig = base64_encode(self.algorithm.get_signature(key, value))

        return value + sep + sig

    # Ignore overlapping signatures check, return_timestamp is the only
    # parameter that affects the return type.

    @t.overload
    def unsign(  # pyright: ignore
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[False] = False,
    ) -> bytes: ...

    @t.overload
    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: t.Literal[True] = True,
    ) -> tuple[bytes, datetime]: ...

    def unsign(
        self,
        signed_value: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
    ) -> tuple[bytes, datetime] | bytes:
        """Works like the regular :meth:`.Signer.unsign` but can also
        validate the time. See the base docstring of the class for
        the general behavior. If ``return_timestamp`` is ``True`` the
        timestamp of the signature will be returned as an aware
        :class:`datetime.datetime` object in UTC.

        .. versionchanged:: 2.0
            The timestamp is returned as a timezone-aware ``datetime``
            in UTC rather than a naive ``datetime`` assumed to be UTC.
        """
        sep = want_bytes(self.sep)
        matched_window: KeyWindow | None = None

        if self.key_windows is None:
            try:
                result = super().unsign(signed_value)
                sig_error = None
            except BadSignature as e:
                sig_error = e
                result = e.payload or b""
        else:
            signed_value = want_bytes(signed_value)

            if sep not in signed_value:
                raise BadSignature(f"No {sep!r} found in value")

            result, sig = signed_value.rsplit(sep, 1)
            key_index = self._find_matching_key_index(result, sig)

            if key_index is None:
                sig_error = BadSignature(
                    f"Signature {sig!r} does not match", payload=result
                )
            else:
                sig_error = None
                matched_window = self.key_windows[key_index]

        # If there is no timestamp in the result there is something
        # seriously wrong. In case there was a signature error, we raise
        # that one directly, otherwise we have a weird situation in
        # which we shouldn't have come except someone uses a time-based
        # serializer on non-timestamp data, so catch that.
        if sep not in result:
            if sig_error:
                raise sig_error

            raise BadTimeSignature("timestamp missing", payload=result)

        value, ts_bytes = result.rsplit(sep, 1)
        ts_int: int | None = None
        ts_dt: datetime | None = None

        try:
            ts_int = bytes_to_int(base64_decode(ts_bytes))
        except Exception:
            pass

        # Signature is *not* okay. Raise a proper error now that we have
        # split the value and the timestamp.
        if sig_error is not None:
            if ts_int is not None:
                try:
                    ts_dt = self.timestamp_to_datetime(ts_int)
                except (ValueError, OSError, OverflowError) as exc:
                    # Windows raises OSError
                    # 32-bit raises OverflowError
                    raise BadTimeSignature(
                        "Malformed timestamp", payload=value
                    ) from exc

            raise BadTimeSignature(str(sig_error), payload=value, date_signed=ts_dt)

        # Signature was okay but the timestamp is actually not there or
        # malformed. Should not happen, but we handle it anyway.
        if ts_int is None:
            raise BadTimeSignature("Malformed timestamp", payload=value)

        # The signature matched a specific key. The token's authenticated
        # signing time must be within that key's signing window, and the
        # key must not have passed its verify_until time.
        if matched_window is not None:
            try:
                date_signed: datetime | None = self.timestamp_to_datetime(ts_int)
            except (ValueError, OSError, OverflowError):
                date_signed = None

            if not matched_window.not_before <= ts_int < matched_window.sign_until:
                raise KeyWindowViolation(
                    f"Signature timestamp {ts_int} is outside the signing"
                    f" window [{matched_window.not_before},"
                    f" {matched_window.sign_until}) of the matching key",
                    payload=value,
                    date_signed=date_signed,
                )

            now = self.get_timestamp()

            if now >= matched_window.verify_until:
                raise KeyWindowViolation(
                    f"The matching key stopped verifying at"
                    f" {matched_window.verify_until}, it is now {now}",
                    payload=value,
                    date_signed=date_signed,
                )

        # Check timestamp is not older than max_age
        if max_age is not None:
            age = self.get_timestamp() - ts_int

            if age > max_age:
                raise SignatureExpired(
                    f"Signature age {age} > {max_age} seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

            if age < 0:
                raise SignatureExpired(
                    f"Signature age {age} < 0 seconds",
                    payload=value,
                    date_signed=self.timestamp_to_datetime(ts_int),
                )

        if return_timestamp:
            return value, self.timestamp_to_datetime(ts_int)

        return value

    def validate(self, signed_value: str | bytes, max_age: int | None = None) -> bool:
        """Only validates the given signed value. Returns ``True`` if
        the signature exists and is valid."""
        try:
            self.unsign(signed_value, max_age=max_age)
            return True
        except BadSignature:
            return False


class TimedSerializer(Serializer[_TSerialized]):
    """Uses :class:`TimestampSigner` instead of the default
    :class:`.Signer`.

    :param key_windows: Optional per-key rotation windows, corresponding
        to ``secret_key`` by position. See :class:`TimestampSigner` for
        the exact semantics. The same windows are enforced by the default
        signer and every fallback signer, so trying an old digest method
        cannot re-accept a retired key.

    .. versionchanged:: 2.3
        Added the ``key_windows`` parameter.
    """

    default_signer: type[TimestampSigner] = TimestampSigner  # pyright: ignore

    def __init__(
        self,
        *args: t.Any,
        key_windows: cabc.Iterable[_KeyWindowConfig] | None = None,
        **kwargs: t.Any,
    ):
        super().__init__(*args, **kwargs)

        #: The validated per-key rotation windows, aligned with
        #: :attr:`secret_keys`, or ``None`` if not configured.
        self.key_windows: list[KeyWindow] | None = _make_key_windows(
            self.secret_keys, key_windows
        )

    def make_signer(self, salt: str | bytes | None = None) -> TimestampSigner:
        if salt is None:
            salt = self.salt

        kwargs: dict[str, t.Any] = dict(self.signer_kwargs)

        if self.key_windows is not None:
            kwargs["key_windows"] = self.key_windows

        return t.cast(
            "TimestampSigner", self.signer(self.secret_keys, salt=salt, **kwargs)
        )

    def iter_unsigners(
        self, salt: str | bytes | None = None
    ) -> cabc.Iterator[TimestampSigner]:
        if salt is None:
            salt = self.salt

        yield self.make_signer(salt)

        for fallback in self.fallback_signers:
            if isinstance(fallback, dict):
                kwargs = fallback
                fallback = self.signer
            elif isinstance(fallback, tuple):
                fallback, kwargs = fallback
            else:
                kwargs = self.signer_kwargs

            for index, secret_key in enumerate(self.secret_keys):
                fallback_kwargs = dict(kwargs)

                if self.key_windows is not None:
                    fallback_kwargs["key_windows"] = [self.key_windows[index]]

                yield t.cast(
                    "TimestampSigner",
                    fallback(secret_key, salt=salt, **fallback_kwargs),
                )

    # TODO: Signature is incompatible because parameters were added
    #  before salt.

    def loads(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        return_timestamp: bool = False,
        salt: str | bytes | None = None,
    ) -> t.Any:
        """Reverse of :meth:`dumps`, raises :exc:`.BadSignature` if the
        signature validation fails. If a ``max_age`` is provided it will
        ensure the signature is not older than that time in seconds. In
        case the signature is outdated, :exc:`.SignatureExpired` is
        raised. All arguments are forwarded to the signer's
        :meth:`~TimestampSigner.unsign` method.
        """
        s = want_bytes(s)
        last_exception = None

        for signer in self.iter_unsigners(salt):
            try:
                base64d, timestamp = signer.unsign(
                    s, max_age=max_age, return_timestamp=True
                )
                payload = self.load_payload(base64d)

                if return_timestamp:
                    return payload, timestamp

                return payload
            except (SignatureExpired, KeyWindowViolation):
                # The signature was unsigned successfully but was
                # expired or rejected by the key's rotation window. Do
                # not try the next signer.
                raise
            except BadSignature as err:
                last_exception = err

        raise t.cast(BadSignature, last_exception)

    def loads_unsafe(  # type: ignore[override]
        self,
        s: str | bytes,
        max_age: int | None = None,
        salt: str | bytes | None = None,
    ) -> tuple[bool, t.Any]:
        return self._loads_unsafe_impl(s, salt, load_kwargs={"max_age": max_age})
