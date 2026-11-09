.. module:: itsdangerous.timed

Signing With Timestamps
=======================

If you want to expire signatures you can use the
:class:`TimestampSigner` class which adds timestamp information and
signs it. On unsigning you can validate that the timestamp is not older
than a given age.

.. code-block:: python

    from itsdangerous import TimestampSigner
    s = TimestampSigner('secret-key')
    string = s.sign('foo')

.. code-block:: python

    s.unsign(string, max_age=5)
    Traceback (most recent call last):
      ...
    itsdangerous.exc.SignatureExpired: Signature age 15 > 5 seconds

Key Rotation Windows
--------------------

When rotating keys, a plain ``secret_keys`` list cannot express *when*
each key stops signing or stops verifying. Passing ``key_windows``
aligns a :class:`KeyWindow` with each entry in ``secret_keys`` by
position. All values are integer UTC seconds and must satisfy
``not_before < sign_until <= verify_until``.

-   Signing uses the last key with ``not_before <= now < sign_until``,
    and raises :exc:`~itsdangerous.exc.NoSigningKeyError` if no key is
    eligible.
-   A token only verifies if the key that signed it was allowed to sign
    at the token's authenticated timestamp, and ``now < verify_until``.
    Otherwise :exc:`~itsdangerous.exc.KeyWindowViolation` (a subclass of
    :exc:`~itsdangerous.exc.BadTimeSignature`) is raised.
-   ``max_age`` keeps working independently of the windows.

The token format is unchanged: no key id is embedded, and tokens signed
before the windows were configured verify as long as their timestamp
falls inside the key's window. To migrate, keep your existing key list
and add one window per key:

.. code-block:: python

    from datetime import datetime, timezone
    from itsdangerous import TimedSerializer

    def utc(y, m, d):
        return int(datetime(y, m, d, tzinfo=timezone.utc).timestamp())

    # The existing key list, oldest to newest. Only edit this list and
    # the matching windows below when rotating.
    secret_keys = ["old-secret-key", "new-secret-key"]

    key_windows = [
        # old key: no longer signs, keeps verifying existing links
        # until 2027-02-01, then is rejected entirely.
        {"not_before": utc(2026, 1, 1), "sign_until": utc(2026, 12, 1),
         "verify_until": utc(2027, 2, 1)},
        # new key: signs from 2026-11-01 onwards.
        {"not_before": utc(2026, 11, 1), "sign_until": utc(2027, 6, 1),
         "verify_until": utc(2027, 8, 1)},
    ]

    serializer = TimedSerializer(secret_keys, key_windows=key_windows)

Once a key's ``verify_until`` has passed, remove both the key and its
window from the lists. ``URLSafeTimedSerializer`` and any
``fallback_signers`` enforce the same windows.

.. autoclass:: KeyWindow
    :members:

.. autoclass:: TimestampSigner
    :members:

.. autoclass:: TimedSerializer
    :members:
