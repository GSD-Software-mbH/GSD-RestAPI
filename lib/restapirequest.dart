part of 'gsd_restapi.dart';

/// Wrapper-Klasse für HTTP-Anfragen an die REST-API
///
/// Diese Klasse kapselt eine HTTP-Response und verwaltet zusätzliche Metadaten
/// über die Anfrage, wie z.B. ob es sich um einen Login-Request handelt.
class RestApiRequest {
  String get requestHash =>
      '$requestUri|${requestHeader.toString()}|${body.toString()}'.toMd5Hash();

  /// Das Future, das die HTTP-Response enthält
  ///
  /// Dieses Future wird aufgelöst, wenn die HTTP-Anfrage abgeschlossen ist.
  late Future<http.Response> Function(http.Client client) execute;

  /// Kennzeichnet, ob es sich um eine Login-Anfrage handelt
  ///
  /// Login-Anfragen werden speziell behandelt, um Duplikate zu vermeiden.
  bool login;
  Map<String, String>? requestHeader;
  Uri requestUri;
  dynamic body;
  HttpMethod method;
  Duration connectionTimeout;
  Duration responseTimeout;
  String function;
  RestApiHttpMetric? metric;

  /// Erstellt eine neue RestApiRequest-Instanz
  ///
  /// [response] - Das Future mit der HTTP-Response
  /// [login] - Optional: Kennzeichnet Login-Anfragen (Standard: false)
  RestApiRequest(
    this.requestUri,
    this.requestHeader,
    this.body,
    this.method,
    this.connectionTimeout,
    this.responseTimeout,
    this.function, {
    this.login = false,
  }) {
    execute = (http.Client client) async {
      metric = RestApiHttpMetric(function, method);

      try {
        final request = http.Request(method.name.toUpperCase(), requestUri);

        if (requestHeader != null) {
          request.headers.addAll(requestHeader!);
        }
        if (body != null) {
          request.body = body;
        }

        // Sende die Anfrage – der connectionTimeout wird hier vom HttpClient berücksichtigt
        final http.StreamedResponse streamedResponse = await client.send(
          request,
        );

        metric?.start();

        // Verarbeite die Antwort mit einem separaten Response Timeout
        final http.Response response = await http.Response.fromStream(
          streamedResponse,
        ).timeout(responseTimeout);

        metric?.responseCode = response.statusCode;
        metric?.responsePayloadSize = response.contentLength;
        metric?.responseContentType = response.headers['content-type'];
        metric?.stop();

        return response;
      } catch (e) {
        rethrow;
      }
    };
  }
}
