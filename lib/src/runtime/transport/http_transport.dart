import 'dart:async' show TimeoutException;

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/http/http_client_factory.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

/// Führt einzelne HTTP-Requests aus und wendet den Response-Timeout an.
///
/// Der Transport besitzt bewusst keine weitere Logik: keine Retries, kein
/// Session-Handling, kein Buffering - das übernehmen die Koordinatoren des
/// `ApiRuntime`. Transport-Fehler (Timeout, Netzwerk) werden als Exceptions
/// propagiert; HTTP-Fehlerstatus sind reguläre [TransportResponse]s.
@internal
class HttpTransport {
  /// Erstellt einen Transport mit injiziertem [client] (z.B. `MockClient`
  /// in Tests).
  ///
  /// [ownsClient] - ob [close] den Client schließt; standardmäßig gehört sein
  /// Lifecycle dem Aufrufer.
  ///
  /// [allowInsecureHttp] - ob `http://`-URIs erlaubt sind; sonst wirft jeder
  /// Request darauf eine [GsdSecurityException], bevor er den Client erreicht.
  HttpTransport({
    required http.Client client,
    required this.responseTimeout,
    bool ownsClient = false,
    bool allowInsecureHttp = false,
  }) : _client = _HttpsOnlyClient(client, allowInsecureHttp: allowInsecureHttp),
       _ownsClient = ownsClient;

  /// Erstellt einen Transport mit einem eigenen, plattformspezifischen
  /// Client aus der vorhandenen Client-Factory (`lib/httpclient`). Dieser
  /// Client gehört dem Transport und wird von [close] geschlossen.
  HttpTransport.withDefaultClient(RuntimeConfiguration configuration)
    : this(
        client: HttpClientFactory.create(
          configuration.connectionTimeout,
          allowSslError: configuration.allowSslError,
        ),
        responseTimeout: configuration.responseTimeout,
        ownsClient: true,
        allowInsecureHttp: configuration.allowSslError,
      );

  final _HttpsOnlyClient _client;
  final bool _ownsClient;
  bool _closed = false;

  /// Timeout für die vollständige HTTP-Antwort.
  final Duration responseTimeout;

  /// Ob der Client dem Transport gehört (und [close] ihn damit schließt).
  bool get ownsClient => _ownsClient;

  /// HTTP-Client dieses Transports (injiziert oder plattformspezifisch
  /// erzeugt), mit der HTTPS-Prüfung davor.
  ///
  /// Ausschließlich für den `UploadExecutor` (PR 3d) gedacht: Multipart-
  /// Requests (`http.MultipartRequest`) sind gestreamte `http.BaseRequest`s
  /// ohne festen String-Body, [send] unterstützt das bewusst nicht. Der
  /// Multipart-Schritt muss daher denselben Client direkt verwenden - statt
  /// einen zweiten Client zu erzeugen und damit den Client-Lifecycle
  /// ([ownsClient]/[close]) zu duplizieren.
  http.Client get client => _client;

  /// Sendet einen Request und liest die vollständige Antwort ein.
  ///
  /// Wirft [TimeoutException], wenn die Antwort nicht innerhalb von
  /// [responseTimeout] vollständig vorliegt.
  Future<TransportResponse> send({
    required GsdHttpMethod method,
    required Uri uri,
    required Map<String, String> headers,
    String? body,
  }) async {
    final request = http.Request(method.name.toUpperCase(), uri);
    request.headers.addAll(headers);

    if (body != null) {
      request.body = body;
    }

    final response = await _sendAndRead(
      request,
    ).timeout(responseTimeout);

    return TransportResponse(
      statusCode: response.statusCode,
      headers: response.headers,
      bodyBytes: response.bodyBytes,
      body: response.body,
      reasonPhrase: response.reasonPhrase,
    );
  }

  Future<http.Response> _sendAndRead(http.Request request) async {
    final streamedResponse = await _client.send(request);
    return http.Response.fromStream(streamedResponse);
  }

  /// Schließt den Client, wenn er dem Transport gehört ([ownsClient]).
  /// Idempotent.
  void close() {
    if (_closed) {
      return;
    }

    _closed = true;

    if (_ownsClient) {
      _client.close();
    }
  }
}

/// Lässt `http://` nur mit [allowInsecureHttp] durch, für jeden Client.
///
/// Die Prüfung sitzt im Transport statt in der Client-Factory, damit sie
/// auch für einen injizierten Client gilt.
class _HttpsOnlyClient extends http.BaseClient {
  _HttpsOnlyClient(this._inner, {required this.allowInsecureHttp});

  final http.Client _inner;

  /// Ob `http://`-URIs erlaubt sind (`allowSslError` der Konfiguration).
  final bool allowInsecureHttp;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (request.url.scheme == 'http' && !allowInsecureHttp) {
      throw const GsdSecurityException(
        'HTTP connections are not allowed (SSL errors are not allowed).',
      );
    }
    return _inner.send(request);
  }

  @override
  void close() => _inner.close();
}
