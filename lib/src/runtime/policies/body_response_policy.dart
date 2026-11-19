import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Liefert den ganzen dekodierten Body, nachdem der Status ausgewertet ist
/// (siehe [ResponseEnvelope]).
///
/// Für Endpunkte, deren Aufrufer neben `data` auch Schlüssel oben im Body
/// lesen, etwa `objectId` und `object` bei `v3/view/action`.
///
/// Als `const` verwenden: Die Deduplizierung vergleicht Policies per
/// Identität.
@internal
class BodyResponsePolicy implements IResponsePolicy<Map<String, Object?>> {
  const BodyResponsePolicy();

  @override
  Map<String, Object?> decode(
    TransportResponse response, {
    required String operationId,
  }) => ResponseEnvelope.decode(response, operationId: operationId).body;
}
