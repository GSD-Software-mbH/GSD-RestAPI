import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/raw_api_response.dart';

import '../transport_response.dart';
import 'response_policy.dart';

/// Durchreich-Policy für `RawApi`: übersetzt eine [TransportResponse]
/// 1:1 in eine stabile [RawApiResponse].
///
/// Es findet bewusst kein Fehler-Mapping statt: HTTP-Fehlerstatus werden
/// als [RawApiResponse] zurückgegeben, nicht geworfen.
@internal
class RawResponsePolicy implements ResponsePolicy<RawApiResponse> {
  const RawResponsePolicy();

  @override
  RawApiResponse decode(TransportResponse response) {
    return RawApiResponse(
      statusCode: response.statusCode,
      headers: Map<String, String>.unmodifiable(response.headers),
      body: response.body,
      bodyBytes: response.bodyBytes,
    );
  }
}
