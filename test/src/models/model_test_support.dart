import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

const _operationId = 'test.model';

/// `data` einer vollen V1-Antwort aus `test/fixtures/v1/models/`.
Map<String, Object?> loadV1ModelFixture(String name) =>
    jsonDecode(File('test/fixtures/v1/models/$name').readAsStringSync())
        as Map<String, Object?>;

/// Baut das Modell aus [data] so, wie ein Endpunkt es tut: über den
/// Umschlag und `ModelResponsePolicy`.
T decodeModel<T>(T Function(Map<String, Object?> json) fromJson, Object? data) {
  final body = jsonEncode({
    'status': {'internalStatus': '0', 'statusMessage': 'OK'},
    'data': data,
  });
  return ModelResponsePolicy<T>(fromJson).decode(
    TransportResponse(
      statusCode: 200,
      headers: const {},
      bodyBytes: Uint8List.fromList(utf8.encode(body)),
      body: body,
    ),
    operationId: _operationId,
  );
}

/// Erwartet eine [GsdParseException] für die Stelle [path].
Matcher throwsParseExceptionAt(String path) => throwsA(
  isA<GsdParseException>()
      .having((e) => e.operationId, 'operationId', _operationId)
      .having((e) => e.path, 'path', path),
);
