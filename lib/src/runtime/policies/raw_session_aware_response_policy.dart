import 'package:gsd_restapi/src/raw/gsd_raw_api_response.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/recoverable_session_status.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Policy für `GsdRawApi`: reicht die [TransportResponse] 1:1 als
/// [GsdRawApiResponse] durch, mit der Session-Recovery-Semantik des normalen
/// Runtimes.
///
/// Ausschließlich die recoverbaren DOCUframe-Statuscodes 201, 204 und 341
/// werden über die Statusauswertung von [ResponseEnvelope] geworfen. Alle
/// anderen Antworten bleiben unverändert raw, einschließlich HTTP-Fehlern und
/// fachlichen DOCUframe-Fehler-Envelopes.
@internal
class RawSessionAwareResponsePolicy
    implements IResponsePolicy<GsdRawApiResponse> {
  const RawSessionAwareResponsePolicy();

  @override
  GsdRawApiResponse decode(
    TransportResponse response, {
    required String operationId,
  }) {
    if (RecoverableSessionStatus.of(response) != null) {
      ResponseEnvelope.decode(response, operationId: operationId);
      throw StateError(
        'Recoverbarer Sessionstatus wurde nicht als Exception abgebildet.',
      );
    }
    return GsdRawApiResponse(
      statusCode: response.statusCode,
      headers: Map<String, String>.unmodifiable(response.headers),
      body: response.body,
      bodyBytes: response.bodyBytes,
    );
  }
}
