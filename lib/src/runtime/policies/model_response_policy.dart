import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:json_annotation/json_annotation.dart';
import 'package:meta/meta.dart';

/// Baut aus `data` des Umschlags ein Modell [T] über [fromJson].
///
/// Wertet zuerst den Status aus (siehe [ResponseEnvelope]). Ist `data` kein
/// Objekt, wirft sie [GsdParseException] mit `path: 'data'`. Die Modelle
/// entstehen mit `checked: true`; jede [CheckedFromJsonException] aus
/// [fromJson] wird eine [GsdParseException] mit der Stelle als `path`, etwa
/// `data.sessionId`. Der Body steht nie in der Exception.
///
/// Als `const` verwenden, etwa
/// `ModelResponsePolicy<GsdVersionInfo>(GsdVersionInfo.fromJson)`: Die
/// Deduplizierung vergleicht Policies per Identität.
@internal
class ModelResponsePolicy<T> implements IResponsePolicy<T> {
  const ModelResponsePolicy(this.fromJson);

  /// Baut das Modell aus `data`.
  final T Function(Map<String, Object?> json) fromJson;

  @override
  T decode(TransportResponse response, {required String operationId}) {
    final data = ResponseEnvelope.decode(
      response,
      operationId: operationId,
    ).data;
    if (data is! Map<String, Object?>) {
      throw GsdParseException(operationId: operationId, path: 'data');
    }

    try {
      return fromJson(data);
    } on CheckedFromJsonException catch (error) {
      final key = error.key;
      throw GsdParseException(
        operationId: operationId,
        path: key == null ? 'data' : 'data.$key',
      );
    }
  }
}
