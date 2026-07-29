import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/raw_api_response.dart';

import '../response/recoverable_session_status.dart';
import '../transport_response.dart';
import 'raw_response_policy.dart';
import 'response_policy.dart';
import 'rest_api_response_policy.dart';

/// Raw-Durchreichung mit der Session-Recovery-Semantik des normalen Runtimes.
///
/// Ausschließlich die recoverbaren DOCUframe-Statuscodes 201, 204 und 341
/// werden über das kanonische Legacy-Exception-Mapping geworfen. Alle anderen
/// Antworten bleiben unverändert raw, einschließlich HTTP-Fehlern und
/// fachlichen DOCUframe-Fehler-Envelopes.
@internal
class RawSessionAwareResponsePolicy implements ResponsePolicy<RawApiResponse> {
  const RawSessionAwareResponsePolicy();

  @override
  RawApiResponse decode(TransportResponse response) {
    if (recoverableSessionStatus(response) != null) {
      const RestApiResponsePolicy().decode(response);
      throw StateError(
        'Recoverbarer Sessionstatus wurde nicht als Exception abgebildet.',
      );
    }
    return const RawResponsePolicy().decode(response);
  }
}
