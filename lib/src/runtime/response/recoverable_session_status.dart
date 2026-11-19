import 'dart:convert';

import 'package:gsd_restapi/src/runtime/response/response_envelope.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Erkennt die recoverbaren internen DOCUframe-Sessionstatus (201, 204, 341)
/// in einer JSON-Envelope-Antwort.
@internal
abstract final class RecoverableSessionStatus {
  static const Set<String> _statuses = {'201', '204', '341'};

  /// Liefert den recoverbaren internen DOCUframe-Sessionstatus einer
  /// JSON-Envelope-Antwort oder `null`, wenn die Antwort kein entsprechendes
  /// Envelope enthält.
  static String? of(TransportResponse response) {
    final Object? decoded;
    try {
      decoded = jsonDecode(response.body);
    } on FormatException {
      return null;
    }

    return fromEnvelope(decoded);
  }

  /// Variante für Transportgrenzen, die das Envelope bereits dekodiert haben.
  static String? fromEnvelope(Object? decoded) {
    final internalStatus = ResponseEnvelope.internalStatusOf(decoded);
    return _statuses.contains(internalStatus) ? internalStatus : null;
  }
}
