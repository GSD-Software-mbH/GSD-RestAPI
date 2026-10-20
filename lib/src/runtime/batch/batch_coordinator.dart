import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/api_types.dart';

import '../headers/header_provider.dart';
import '../policies/request_priority.dart';
import '../runtime_configuration.dart';
import '../response/response_decryptor.dart';
import '../response/recoverable_session_status.dart';
import '../session/session_state.dart';
import '../transport/http_transport.dart';
import '../transport_response.dart';
import '../uri/uri_builder.dart';

/// Puffert Requests, die `ApiRuntime` als multi-fähig UND aktuell nicht
/// direkt zu sendend eingestuft hat, und flusht sie gebündelt als EINEN
/// `POST v1/multi`-Request; jeder Aufrufer erhält seine eigene, aus der
/// Multi-Antwort demultiplexte [TransportResponse].
///
/// Reproduziert den Legacy-Vertrag von
/// `RestApiDOCUframeManager._performPriorityBufferedRequest`/
/// `_flushPriorityRequestBuffer`/`_processPriorityMultiRequest`/
/// `_processMultiRequestResponse` funktional nach, aber OHNE dessen drei
/// per Task-1-Charakterisierung nachgewiesene Bugs:
///
/// - Kein `_shouldNeverBuffer`-String-Matching (das `/v1/xSync` nie traf,
///   weil reale Pfade `/v1/xSync/...` lauten): "nie puffern" wird zentral
///   über `MultiRequestEligibility` (Version/Pfad) sowie über einen
///   No-Buffer-Zone-Scope entschieden und NICHT von diesem Koordinator - er
///   sieht als ungeeignet oder als No-Buffer-Scope erkannte Requests nie.
/// - Kein High-Priority-Buffer, der beim Flush nur
///   `requestsToProcess.first` erneut sendet und weitere Requests verliert:
///   `high` wird bereits von `ApiRuntime` VOR dem Puffern abgefangen und von
///   [enqueue] zusätzlich defensiv abgelehnt. `normal` und `low` besitzen
///   voneinander unabhängige Buffer und Flush-Timer.
/// - Der Demux vergleicht die tatsächliche Ergebnis-LISTEN-Länge (nicht
///   die Envelope-Map-Länge) gegen die Anzahl gepufferter Requests; fehlen
///   Ergebnisse, werden die übrigen Requests über den Einzel-Fallback
///   abgeschlossen statt dauerhaft offen zu bleiben.
///
/// Der Koordinator kennt bewusst weder `ApiRequest` noch `ResponsePolicy`:
/// Ein/Ausgabe sind reine Transport-Primitive (Methode, URI, Header,
/// Body -> [TransportResponse]), damit die demultiplexte Antwort
/// anschließend denselben Dekodier- und Session-Retry-Pfad wie jeder
/// andere Request durchläuft.
@internal
class BatchCoordinator {
  /// Runtime-Konfiguration; liefert `maxBufferSize`,
  /// `bufferFlushDelayMs` sowie Alias/Basis-URI für die Pfad-Kürzung im
  /// Multi-Request-Body.
  final RuntimeConfiguration configuration;

  final Map<ApiRequestPriority, List<_BufferedItem>> _buffers = {
    ApiRequestPriority.normal: <_BufferedItem>[],
    ApiRequestPriority.low: <_BufferedItem>[],
  };

  final Map<ApiRequestPriority, Timer?> _flushTimers = {
    ApiRequestPriority.normal: null,
    ApiRequestPriority.low: null,
  };

  bool _disposed = false;

  HttpTransport? _transport;
  UriBuilder? _uriBuilder;
  SessionState? _sessionState;

  BatchCoordinator({required this.configuration});

  int get _maxBufferSize => configuration.maxBufferSize;

  Duration get _flushDelay =>
      Duration(milliseconds: configuration.bufferFlushDelayMs);

  /// Verbindet den Koordinator mit dem Transport, URI-Builder und
  /// `SessionState` des angebundenen `ApiRuntime`. Wird von der
  /// `ApiRuntime`-Factory genau einmal aufgerufen - analog zu
  /// `SessionCoordinator.attachRuntime`.
  ///
  /// Bewusst KEIN eigener Transport/Client: Der Koordinator sendet über
  /// denselben Transport wie alle anderen Requests des Runtimes, damit
  /// Client-Lifecycle und `dispose()` an einer Stelle bleiben.
  ///
  /// Der `SessionState` wird bei JEDEM Senden frisch gelesen (siehe
  /// [_currentSessionId]), NICHT beim Enqueue zwischengespeichert: Ein
  /// Session-Refresh während des `bufferFlushDelayMs`-Fensters darf weder den
  /// `v1/multi`-POST noch einen Einzel-Fallback-Resend mit einer veralteten
  /// `sessionid` verlassen.
  void attachTransport({
    required HttpTransport transport,
    required UriBuilder uriBuilder,
    required SessionState sessionState,
  }) {
    if (_transport != null && !identical(_transport, transport)) {
      throw StateError(
        'BatchCoordinator ist bereits an einen anderen Transport gebunden.',
      );
    }
    _transport = transport;
    _uriBuilder = uriBuilder;
    _sessionState = sessionState;
  }

  HttpTransport get _requireTransport {
    final transport = _transport;
    if (transport == null) {
      throw StateError(
        'BatchCoordinator ist nicht an einen ApiRuntime gebunden; den '
        'Koordinator über die ApiRuntime-Factory anbinden.',
      );
    }
    return transport;
  }

  UriBuilder get _requireUriBuilder {
    final uriBuilder = _uriBuilder;
    if (uriBuilder == null) {
      throw StateError(
        'BatchCoordinator ist nicht an einen ApiRuntime gebunden; den '
        'Koordinator über die ApiRuntime-Factory anbinden.',
      );
    }
    return uriBuilder;
  }

  /// Aktuelle Session-ID zum SENDEZEITPUNKT (nicht zum Enqueue-Zeitpunkt);
  /// leer, wenn keine Session vorliegt oder der Koordinator (noch) nicht
  /// angebunden ist. Wird für jeden `v1/multi`-POST und jeden Einzel-Fallback-
  /// Resend frisch gelesen, damit ein Session-Refresh während des
  /// `bufferFlushDelayMs`-Fensters keine veraltete `sessionid` verschickt.
  String get _currentSessionId => _sessionState?.sessionId ?? '';

  /// Reiht einen Request in den Buffer ein und liefert ein Future, das mit
  /// der (ggf. demultiplexten) [TransportResponse] dieses EINEN Requests
  /// abgeschlossen wird.
  ///
  /// [needsSession] - ob der Request `AuthenticationPolicy.session`/
  /// `sessionNoRefresh` verwendet (siehe `ApiRuntime._dispatch`). Steuert, ob
  /// [_resolvedHeaders] die zum Enqueue-Zeitpunkt erfassten Header beim
  /// SENDEN um die AKTUELLE Session-ID ergänzt.
  ///
  /// Flush-Auslöser:
  /// - Erreicht der Buffer `maxBufferSize`, wird sofort geflusht.
  /// - Andernfalls startet der ERSTE Request eines zuvor leeren Buffers
  ///   einen Timer über `bufferFlushDelayMs`; weitere Requests vor Ablauf
  ///   verlängern das Fenster NICHT (anders als der Legacy-Manager, der
  ///   den Timer bei JEDEM neuen Request zurücksetzte und den Flush damit
  ///   potenziell unbegrenzt verzögern konnte).
  Future<TransportResponse> enqueue({
    required ApiHttpMethod method,
    required Uri uri,
    required Map<String, String> headers,
    required bool needsSession,
    required ApiRequestPriority priority,
    String? body,
  }) {
    if (_disposed) {
      return Future<TransportResponse>.error(
        StateError('BatchCoordinator wurde bereits mit dispose() freigegeben.'),
      );
    }

    if (priority == ApiRequestPriority.high) {
      throw ArgumentError.value(
        priority,
        'priority',
        'ApiRequestPriority.high darf nicht gepuffert werden.',
      );
    }

    final List<_BufferedItem> buffer = _buffers[priority]!;

    final completer = Completer<TransportResponse>();
    final item = _BufferedItem(
      method: method,
      uri: uri,
      headers: headers,
      needsSession: needsSession,
      body: body,
      completer: completer,
    );

    final bool wasEmpty = buffer.isEmpty;
    buffer.add(item);

    if (buffer.length >= _maxBufferSize) {
      unawaited(_flush(priority));
    } else if (wasEmpty) {
      _flushTimers[priority] = Timer(
        _flushDelay,
        () => unawaited(_flush(priority)),
      );
    }

    return completer.future;
  }

  /// Flusht den aktuellen Buffer-Inhalt (No-Op, wenn leer). Genau EIN
  /// gepufferter Request wird als normale Einzelanfrage gesendet statt als
  /// Multi-Request mit einem Element.
  Future<void> _flush(ApiRequestPriority priority) {
    _flushTimers[priority]?.cancel();
    _flushTimers[priority] = null;

    final List<_BufferedItem> buffer = _buffers[priority]!;

    if (buffer.isEmpty) {
      return Future<void>.value();
    }

    final items = List<_BufferedItem>.of(buffer);
    buffer.clear();

    if (items.length == 1) {
      return _sendSingle(items.first);
    }

    return _sendMulti(items);
  }

  /// Sendet EINEN gepufferten Request direkt über den Transport (kein
  /// Multi-Request-Envelope). Wird sowohl für den Lone-Buffer-Flush als auch
  /// für JEDEN Einzel-Fallback-Resend genutzt; [_resolvedHeaders] sorgt in
  /// beiden Fällen dafür, dass eine `sessionid` nie veraltet verschickt wird.
  Future<void> _sendSingle(_BufferedItem item) async {
    try {
      final TransportResponse response = await _requireTransport.send(
        method: item.method,
        uri: item.uri,
        headers: _resolvedHeaders(item),
        body: item.body,
      );
      if (!item.completer.isCompleted) {
        item.completer.complete(response);
      }
    } catch (error, stackTrace) {
      if (!item.completer.isCompleted) {
        item.completer.completeError(error, stackTrace);
      }
    }
  }

  /// Liefert die beim SENDEN tatsächlich zu verwendenden Header eines
  /// gepufferten Items.
  ///
  /// Braucht das Item KEINE Session (`needsSession == false`, z.B.
  /// `AuthenticationPolicy.none`), bleiben die zum Enqueue-Zeitpunkt vom
  /// `HeaderProvider` erzeugten Header unverändert. Braucht es eine Session
  /// UND liegt aktuell eine nicht-leere Session-ID vor, wird `sessionid` auf
  /// den AKTUELLEN Wert überschrieben - analog zum Legacy
  /// `_retryAsSingleRequest` (`requestHeader['sessionid'] = _config.sessionId;`
  /// in `lib/legacy/restapidocuframemanager.dart`), das genau deshalb vor jedem
  /// Einzel-Resend die frischeste Session-ID einsetzte. `appkey` und
  /// `Content-type` bleiben unangetastet (wie zum Enqueue-Zeitpunkt erfasst).
  Map<String, String> _resolvedHeaders(_BufferedItem item) {
    if (!item.needsSession) {
      return item.headers;
    }

    final String sessionId = _currentSessionId;
    if (sessionId.isEmpty) {
      return item.headers;
    }

    return Map<String, String>.of(item.headers)..['sessionid'] = sessionId;
  }

  /// Baut die Header des äußeren `POST v1/multi` explizit (statt sie von
  /// `items.first.headers` zu kopieren): Der Multi-Endpunkt ist von Natur aus
  /// session-authentifiziert (wie der Legacy-`_getHeader()`-Standard) - ein
  /// `items.first` mit `AuthenticationPolicy.none` darf die `sessionid` für
  /// die gesamte Bündel-Anfrage nicht unterdrücken. Die Session-ID wird
  /// AKTUELL (Sendezeitpunkt, nicht Enqueue-Zeitpunkt) gelesen, damit ein
  /// Refresh während des `bufferFlushDelayMs`-Fensters nicht zu einer
  /// veralteten `sessionid` führt.
  Map<String, String> _buildMultiHeaders() {
    final Map<String, String> headers = {
      'appkey': configuration.appKey,
      _contentTypeHeaderName: HeaderProvider.defaultContentType,
    };

    final String sessionId = _currentSessionId;
    if (sessionId.isNotEmpty) {
      headers['sessionid'] = sessionId;
    }

    return headers;
  }

  /// Sendet mehrere gepufferte Requests als EINEN `POST v1/multi` und
  /// demultiplext die Antwort. Äußere Sessionfehler werden unabhängig vom
  /// HTTP-Status an alle Items durchgereicht, damit der Runtime dieselbe
  /// Single-Flight-Recovery wie bei Teilfehlern ausführt. Bei sonstigen
  /// Transport-Fehlern, einem Nicht-200-Status oder einem unparsbaren Envelope
  /// werden ALLE `items` über den Einzel-Fallback abgeschlossen. Liefert der
  /// Server weniger Ergebnisse als Requests gesendet wurden (oder ist ein
  /// Ergebnis-Eintrag fehlerhaft), werden die übrigen `items` ebenfalls über
  /// den Einzel-Fallback abgeschlossen statt dauerhaft offen zu bleiben (Fix
  /// des Legacy-Bugs, der die Envelope-Map- statt die Ergebnis-Listenlänge
  /// verglich).
  Future<void> _sendMulti(List<_BufferedItem> items) async {
    final Map<String, String> multiHeaders = _buildMultiHeaders();
    final String multiBody = jsonEncode(
      items.map(_toMultiItemJson).toList(growable: false),
    );

    final TransportResponse response;
    try {
      // `_requireUriBuilder.build(...)` bewusst INNERHALB des try/catch: Wäre
      // der Koordinator (defensiv, heute unerreichbar) nicht angebunden,
      // würde der StateError sonst den un-awaited `_flush()`-Aufruf
      // verlassen und alle gepufferten Completer unbegrenzt offen lassen,
      // statt über den Einzel-Fallback abzuschließen.
      final Uri multiUri = _requireUriBuilder.build(
        version: ApiVersion.v1,
        path: '/multi',
      );
      response = await _requireTransport.send(
        method: ApiHttpMethod.post,
        uri: multiUri,
        headers: multiHeaders,
        body: multiBody,
      );
    } catch (_) {
      await _fallbackToIndividual(items);
      return;
    }

    final TransportResponse normalizedResponse;
    try {
      normalizedResponse = await const ResponseDecryptor().decryptIfNeeded(
        response,
      );
    } catch (_) {
      await _fallbackToIndividual(items);
      return;
    }

    dynamic decoded;
    List<dynamic>? results;
    try {
      decoded = jsonDecode(normalizedResponse.body);
      if (decoded is Map<String, dynamic> && decoded['data'] is List) {
        results = decoded['data'] as List<dynamic>;
      }
    } catch (_) {
      results = null;
    }

    if (_isOuterSessionErrorEnvelope(decoded)) {
      _completeAllWithResponse(items, normalizedResponse);
      return;
    }

    if (response.statusCode != 200) {
      await _fallbackToIndividual(items);
      return;
    }

    if (results == null) {
      await _fallbackToIndividual(items);
      return;
    }

    final int completeUpTo = results.length < items.length
        ? results.length
        : items.length;
    var completedCount = 0;
    for (var index = 0; index < completeUpTo; index++) {
      try {
        final entry = results[index] as Map<String, dynamic>;
        final int httpStatus = entry['httpStatus'] as int;
        final String encodedResult = jsonEncode(entry['result']);
        if (!items[index].completer.isCompleted) {
          items[index].completer.complete(
            TransportResponse(
              statusCode: httpStatus,
              headers: const {'content-type': 'application/json'},
              bodyBytes: Uint8List.fromList(utf8.encode(encodedResult)),
              body: encodedResult,
            ),
          );
        }
        completedCount++;
      } catch (_) {
        // Fehlerhafter Eintrag: ab hier (inklusive dieses Items) über den
        // Einzel-Fallback abschließen statt die Demux-Schleife abzubrechen.
        break;
      }
    }

    if (completedCount < items.length) {
      await _fallbackToIndividual(items.sublist(completedCount));
    }
  }

  Future<void> _fallbackToIndividual(List<_BufferedItem> items) {
    return Future.wait(items.map(_sendSingle));
  }

  /// Erkennt ausschließlich die Session-Fehler, bei denen der Server den
  /// Fehler am äußeren `v1/multi`-Envelope statt pro `data`-Eintrag meldet.
  /// Die eigentliche Exception- und Recovery-Logik bleibt im `ApiRuntime`:
  /// Jeder Item-Completer erhält dieselbe Transportantwort, alle daraus
  /// entstehenden Sessionfehler teilen anschließend den Single-Flight-
  /// Refresh des `SessionCoordinator`.
  bool _isOuterSessionErrorEnvelope(dynamic decoded) {
    return recoverableSessionStatusFromEnvelope(decoded) != null;
  }

  void _completeAllWithResponse(
    List<_BufferedItem> items,
    TransportResponse response,
  ) {
    for (final item in items) {
      if (!item.completer.isCompleted) {
        item.completer.complete(response);
      }
    }
  }

  Map<String, dynamic> _toMultiItemJson(_BufferedItem item) {
    final Map<String, dynamic> json = {
      'method': item.method.name.toUpperCase(),
      'path': _relativePath(item.uri),
    };

    if (item.body != null) {
      json['data'] = jsonDecode(item.body!);
    }

    return json;
  }

  /// Kürzt die vollständige Request-URI auf den Anteil ab `/v1/...` bzw.
  /// `/v2/...` (ohne Basis-Pfad und Alias), wie es der Multi-Request-Body
  /// erwartet.
  String _relativePath(Uri uri) {
    final String aliasSegment = configuration.alias.isEmpty
        ? ''
        : '/${configuration.alias}';
    final String prefix = '${configuration.baseUri.path}$aliasSegment';

    String path = uri.path;
    if (prefix.isNotEmpty && path.startsWith(prefix)) {
      path = path.substring(prefix.length);
    }

    if (uri.hasQuery) {
      path = '$path?${uri.query}';
    }

    return path;
  }

  /// Gibt den Koordinator frei: Idempotent, bricht den Flush-Timer ab und
  /// schließt alle noch gepufferten Requests mit einem Fehler ab (statt sie
  /// zu flushen), damit kein Aufrufer nach `dispose()` unbegrenzt wartet.
  Future<void> dispose() async {
    if (_disposed) {
      return;
    }
    _disposed = true;

    for (final timer in _flushTimers.values) {
      timer?.cancel();
    }
    for (final priority in _flushTimers.keys) {
      _flushTimers[priority] = null;
    }

    final items = <_BufferedItem>[];
    for (final buffer in _buffers.values) {
      items.addAll(buffer);
      buffer.clear();
    }

    for (final item in items) {
      if (!item.completer.isCompleted) {
        item.completer.completeError(
          StateError(
            'ApiRuntime wurde mit dispose() freigegeben, bevor der '
            'gepufferte Request gesendet wurde.',
          ),
        );
      }
    }
  }
}

const String _contentTypeHeaderName = 'Content-type';

/// Ein gepufferter Request: Transport-Primitive plus der [Completer], den
/// [BatchCoordinator.enqueue] seinem Aufrufer zurückgegeben hat.
class _BufferedItem {
  final ApiHttpMethod method;
  final Uri uri;
  final Map<String, String> headers;

  /// Ob dieser Request `AuthenticationPolicy.session`/`sessionNoRefresh`
  /// verwendet (siehe `ApiRuntime._dispatch`). Steuert, ob
  /// [BatchCoordinator._resolvedHeaders] die Session-ID beim Senden auf den
  /// aktuellen Wert überschreibt.
  final bool needsSession;

  final String? body;
  final Completer<TransportResponse> completer;

  _BufferedItem({
    required this.method,
    required this.uri,
    required this.headers,
    required this.needsSession,
    required this.body,
    required this.completer,
  });
}
