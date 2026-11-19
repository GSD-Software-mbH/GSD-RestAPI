@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

void main() {
  group('GsdObjectsByIdRequest', () {
    test('sendet den Body der App byte-gleich', () {
      const request = GsdObjectsByIdRequest(
        classId: 100,
        ids: [200, 201],
        context: 'edit',
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_byid_request.json'),
      );
    });

    test('sendet einen fehlenden Kontext als "null"', () {
      const request = GsdObjectsByIdRequest(classId: 100, ids: [200]);

      expect(request.context, 'null');
      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_byid_null_context_request.json'),
      );
    });

    test('sendet je Klasse einen Eintrag', () {
      const requests = [
        GsdObjectsByIdRequest(classId: 100, ids: [200], context: 'mobile'),
        GsdObjectsByIdRequest(
          classId: 300,
          ids: [400, 401],
          context: 'mobile',
        ),
      ];

      expect(
        jsonEncode([for (final request in requests) request.toJson()]),
        loadV3Fixture('objectdata_byid_two_classes_request.json'),
      );
    });
  });
}
