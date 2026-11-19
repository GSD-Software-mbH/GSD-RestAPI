import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Liefert `data` des Umschlags als [T].
///
/// Wertet zuerst den Status aus (siehe [ResponseEnvelope]); passt `data`
/// nicht zu [T], wirft sie [GsdParseException] mit `path: 'data'`. Für
/// Endpunkte ohne bekannte Antwortform ist [T] `Object?`.
///
/// Als `const` verwenden: Die Deduplizierung vergleicht Policies per
/// Identität.
@internal
class DataResponsePolicy<T> implements IResponsePolicy<T> {
  const DataResponsePolicy();

  @override
  T decode(TransportResponse response, {required String operationId}) {
    final data = ResponseEnvelope.decode(
      response,
      operationId: operationId,
    ).data;
    if (data is T) {
      return data;
    }
    throw GsdParseException(operationId: operationId, path: 'data');
  }
}
