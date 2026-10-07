# This fork

sail's fork of [0x676e67/quinn-btls](https://github.com/0x676e67/quinn-btls),
the BoringSSL (btls) crypto provider for quinn. The `sail` branch tracks
upstream `main`, and sail pins revisions of it.

Upstream is merged into `sail`, never rebased onto it, and the branch is
never force-pushed: a pinned revision has to stay reachable.

## Patches

- **Exporter context**: `SSL_export_keying_material` was told to use the
  context only when it was empty, so every export ran with an empty one.
  TUIC's authentication token is an export with the password as context
  and never matched other implementations. QUIC is TLS 1.3 only, where no
  context and an empty one are the same, so the context is always used.
- **ECH retry configs**: `SSL_get0_ech_retry_configs` was called on every
  fatal handshake error, which BoringSSL allows only after
  `SSL_R_ECH_REJECTED`. Debug builds aborted on any failed handshake. The
  configs are now read only once ECH was rejected.
- **SNI and fallible calls**: RFC 6066 forbids IP literals in SNI; SNI is
  now set only for DNS names, and an IP server name is still verified
  against the certificate's IP SANs. Fallible BoringSSL calls return
  errors instead of panicking.
- **Session ticket in 1-RTT**: BoringSSL writes the server's
  NewSessionTicket before quinn has the 1-RTT keys. It was filed under the
  Handshake space and lost with those keys, so clients never resumed and
  0-RTT never happened against a quinn-btls server. Application data now
  waits for the 1-RTT keys.
- **ECH config list**: `ClientConfig::set_ech_config_list` sets the
  ECHConfigList each session offers ECH with (`SSL_set1_ech_config_list`
  on each SSL, before the ClientHello); a list BoringSSL cannot parse is an
  error when it is set. `ClientConfig` is `Clone`, sharing the context and
  the session cache, so that a client can offer a list per connection, as
  one looked up in DNS. `HandshakeData::ech_accepted` says whether the
  handshake was the encrypted ClientHello's, on both sides.
- **lru 0.18**: past RUSTSEC-2026-0253 (`LruCache::pop` not panic-safe).
  The session cache's keys are `Bytes`, whose drop cannot panic, so the
  flaw was not reachable; the advisory is closed all the same.

## When it could go away

Five are bug fixes and one, the ECH config list, a feature rather than
anything sail-specific: once upstream has equivalents of them, sail can
depend on upstream directly. None are there today.
