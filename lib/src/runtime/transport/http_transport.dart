import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import 'package:gsd_restapi/httpclient/httpclient.dart';
import 'package:gsd_restapi/raw/api_types.dart';

import '../runtime_configuration.dart';
import '../transport_response.dart';

/// Führt einzelne HTTP-Requests aus und wendet den Response-Timeout an.
///
/// Der Transport besitzt bewusst keine weitere Logik: keine Retries, kein
/// Session-Handling, kein Buffering - das übernehmen die Koordinatoren des
/// `ApiRuntime`. Transport-Fehler (Timeout, Netzwerk) werden als Exceptions
/// propagiert; HTTP-Fehlerstatus sind reguläre [TransportResponse]s.
@internal
class HttpTransport {
  final http.Client _client;
  final bool _ownsClient;
  bool _closed = false;

  /// Timeout für die vollständige HTTP-Antwort.
  final Duration responseTimeout;

  /// Erstellt einen Transport mit injiziertem [client] (z.B. `MockClient`
  /// in Tests). Der injizierte Client wird von [close] NICHT geschlossen -
  /// sein Lifecycle gehört dem Aufrufer.
  HttpTransport({required http.Client client, required this.responseTimeout})
    : _client = client,
      _ownsClient = false;

  /// Erstellt einen Transport mit einem eigenen, plattformspezifischen
  /// Client aus der vorhandenen Client-Factory (`lib/httpclient`). Dieser
  /// Client gehört dem Transport und wird von [close] geschlossen.
  HttpTransport.withDefaultClient(RuntimeConfiguration configuration)
    : _client = createClient(
        configuration.connectionTimeout,
        allowSslError: configuration.allowSslError,
      ),
      _ownsClient = true,
      responseTimeout = configuration.responseTimeout;

  /// Ob der Transport seinen Client selbst erzeugt hat (und damit bei
  /// [close] schließen muss).
  bool get ownsClient => _ownsClient;

  /// Roher HTTP-Client dieses Transports (injiziert oder plattformspezifisch
  /// erzeugt).
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
    required ApiHttpMethod method,
    required Uri uri,
    required Map<String, String> headers,
    String? body,
  }) async {
    final request = http.Request(method.name.toUpperCase(), uri);
    request.headers.addAll(headers);

    if (body != null) {
      request.body = body;
    }

    final http.Response response = await _sendAndRead(
      request,
    ).timeout(responseTimeout);

    return TransportResponse(
      statusCode: response.statusCode,
      headers: response.headers,
      bodyBytes: response.bodyBytes,
      body: response.body,
    );
  }

  Future<http.Response> _sendAndRead(http.Request request) async {
    final http.StreamedResponse streamedResponse = await _client.send(request);
    return http.Response.fromStream(streamedResponse);
  }

  /// Schließt den eigenen Client. Idempotent; injizierte Clients werden
  /// nicht geschlossen.
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
