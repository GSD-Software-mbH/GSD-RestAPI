import 'dart:convert';

import 'package:meta/meta.dart';

import '../transport_response.dart';

const Set<int> _recoverableSessionStatuses = {201, 204, 341};

/// Liefert den recoverbaren internen DOCUframe-Sessionstatus einer
/// JSON-Envelope-Antwort oder `null`, wenn die Antwort kein entsprechendes
/// Envelope enthält.
@internal
int? recoverableSessionStatus(TransportResponse response) {
  final dynamic decoded;
  try {
    decoded = jsonDecode(response.body);
  } on FormatException {
    return null;
  }

  return recoverableSessionStatusFromEnvelope(decoded);
}

/// Variante für Transportgrenzen, die das Envelope bereits dekodiert haben.
@internal
int? recoverableSessionStatusFromEnvelope(dynamic decoded) {
  if (decoded is! Map<String, dynamic>) return null;
  final dynamic status = decoded['status'];
  if (status is! Map<String, dynamic>) return null;

  final dynamic rawInternalStatus = status['internalStatus'];
  final int? internalStatus = rawInternalStatus is int
      ? rawInternalStatus
      : int.tryParse(rawInternalStatus?.toString() ?? '');
  return _recoverableSessionStatuses.contains(internalStatus)
      ? internalStatus
      : null;
}
