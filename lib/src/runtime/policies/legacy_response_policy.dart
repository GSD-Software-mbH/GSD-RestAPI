import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import '../transport_response.dart';
import 'response_policy.dart';
import 'rest_api_response_policy.dart';

/// Generische Konstruktor-Policy für Legacy-kompatible Rückgabetypen, die
/// selbst einen `http.Response` im Konstruktor entgegennehmen (z.B.
/// `RestApiResponse`, `RestApiLoginResponse`, aber auch beliebige weitere
/// Legacy-Antworttypen).
///
/// Übersetzt die Transport-Antwort 1:1 in ein `http.Response` (Statuscode,
/// Header und exakte Body-Bytes bleiben erhalten) und übergibt es
/// UNGEPRÜFT an [construct] - anders als [ValidatedHttpResponsePolicy] findet
/// KEINE Envelope-Validierung statt: ein Statuscode 207 mit beliebigem Body
/// dekodiert klaglos, die Validierung (falls gewünscht) übernimmt [T]s
/// eigener Konstruktor.
@internal
class LegacyResponsePolicy<T> implements ResponsePolicy<T> {
  final T Function(http.Response response) construct;

  const LegacyResponsePolicy(this.construct);

  @override
  T decode(TransportResponse response) => construct(_toHttpResponse(response));
}

/// Validiert das Standard-DOCUframe-Envelope
/// (`{"status": {"internalStatus", "statusMessage"}, "data": ...}`) über
/// dasselbe Exception-Mapping wie [RestApiResponsePolicy] (z.B.
/// `internalStatus '201'` -> `SessionInvalidException`) und liefert bei
/// Erfolg das exakt validierte `http.Response` zurück (Statuscode, Header
/// und Body-Bytes unverändert).
@internal
class ValidatedHttpResponsePolicy implements ResponsePolicy<http.Response> {
  const ValidatedHttpResponsePolicy();

  @override
  http.Response decode(TransportResponse response) {
    return const RestApiResponsePolicy().decode(response).httpResponse;
  }
}

/// Adapter TransportResponse -> http.Response OHNE Envelope-Validierung.
/// Bewusst über die Bytes (nicht `body`/String), damit die
/// Charset-Dekodierung (Content-Type-Header) identisch zum bisherigen Pfad
/// funktioniert.
http.Response _toHttpResponse(TransportResponse response) =>
    http.Response.bytes(
      response.bodyBytes,
      response.statusCode,
      headers: response.headers,
    );
