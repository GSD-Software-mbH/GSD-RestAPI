import 'dart:async';

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/models/gsd_http_metric.dart';
import 'package:meta/meta.dart';

/// Ereignisse des Runtimes an die App, als synchrone Broadcast-Streams.
///
/// `sync: true`: Ein Ereignis kommt beim Listener an, während der Runtime es
/// meldet, also im Session-Setter bzw. vor dem Werfen der Exception. Wirft ein
/// Listener, geht der Fehler an die Zone, nicht in den Runtime. Ohne Listener
/// geht ein Ereignis verloren.
///
/// Nach [close] verwirft jede Meldung still (Guard statt `add` nach `close`).
@internal
class RuntimeEvents {
  /// [twoFactorTokenProvider] liefert das 2FA-Token, wenn eine laufende
  /// Sitzung einen 341 bekommt; ohne Provider gilt das Token als leer.
  RuntimeEvents({Future<String> Function()? twoFactorTokenProvider})
    : _twoFactorTokenProvider = twoFactorTokenProvider;

  final Future<String> Function()? _twoFactorTokenProvider;

  final _sessionIdChanges = StreamController<String>.broadcast(sync: true);
  final _licenseErrors = StreamController<GsdLicenseException>.broadcast(
    sync: true,
  );
  final _invalidCredentials =
      StreamController<GsdInvalidCredentialsException>.broadcast(sync: true);
  final _logs = StreamController<String>.broadcast(sync: true);
  final _httpMetrics = StreamController<GsdHttpMetric>.broadcast(
    sync: true,
  );

  final Set<Completer<String>> _pendingTwoFactorRequests = {};
  bool _closed = false;

  /// Jede neue Session-ID; `''` nach Logout oder Fehler, auch doppelt.
  Stream<String> get sessionIdChanges => _sessionIdChanges.stream;

  /// Lizenzfehler (`internalStatus` 306/101).
  Stream<GsdLicenseException> get licenseErrors => _licenseErrors.stream;

  /// Falsche Zugangsdaten (`internalStatus` 302).
  Stream<GsdInvalidCredentialsException> get invalidCredentials =>
      _invalidCredentials.stream;

  /// Log-Zeilen; Header-Werte und Bodies sind redigiert.
  Stream<String> get logs => _logs.stream;

  /// Eine Metrik je abgeschlossenem HTTP-Request.
  Stream<GsdHttpMetric> get httpMetrics => _httpMetrics.stream;

  /// Meldet eine neue Session-ID.
  void sessionIdChanged(String sessionId) => _add(_sessionIdChanges, sessionId);

  /// Meldet einen Lizenzfehler.
  void licenseError(GsdLicenseException error) => _add(_licenseErrors, error);

  /// Meldet falsche Zugangsdaten.
  void invalidCredentialsError(GsdInvalidCredentialsException error) =>
      _add(_invalidCredentials, error);

  /// Meldet eine Log-Zeile.
  void log(String message) => _add(_logs, message);

  /// Meldet eine HTTP-Metrik.
  void httpMetric(GsdHttpMetric metric) => _add(_httpMetrics, metric);

  /// Fragt den Provider nach einem 2FA-Token.
  ///
  /// Ohne Provider oder nach [close] ist das Token `''`. Wirft der Provider,
  /// gilt das ebenfalls als `''`, dazu kommt ein Log-Ereignis. [close]
  /// schließt eine noch offene Anfrage mit `''` ab.
  Future<String> requestTwoFactorToken() {
    final provider = _twoFactorTokenProvider;
    if (provider == null || _closed) {
      return Future<String>.value('');
    }

    final pending = Completer<String>();
    _pendingTwoFactorRequests.add(pending);
    unawaited(_askProvider(provider, pending));
    return pending.future;
  }

  Future<void> _askProvider(
    Future<String> Function() provider,
    Completer<String> pending,
  ) async {
    var token = '';
    try {
      token = await provider();
    } on Object catch (error) {
      log('2FA-Token-Provider fehlgeschlagen: $error');
    }

    _pendingTwoFactorRequests.remove(pending);
    if (!pending.isCompleted) {
      pending.complete(token);
    }
  }

  /// Schließt offene 2FA-Anfragen mit `''` ab.
  void cancelTwoFactorRequests() {
    for (final pending in _pendingTwoFactorRequests) {
      if (!pending.isCompleted) {
        pending.complete('');
      }
    }
    _pendingTwoFactorRequests.clear();
  }

  /// Schließt offene 2FA-Anfragen und die Streams. Danach geht kein Ereignis
  /// mehr hinaus. Idempotent.
  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    cancelTwoFactorRequests();

    await Future.wait([
      _sessionIdChanges.close(),
      _licenseErrors.close(),
      _invalidCredentials.close(),
      _logs.close(),
      _httpMetrics.close(),
    ]);
  }

  void _add<T>(StreamController<T> controller, T event) {
    if (_closed) {
      return;
    }
    controller.add(event);
  }
}
