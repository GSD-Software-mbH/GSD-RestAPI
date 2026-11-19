@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

void main() {
  group('GsdObjectsByQueryRequest', () {
    test('sendet den Body der App byte-gleich', () {
      const request = GsdObjectsByQueryRequest(
        className: 'Dokument',
        query: 'Name=Test',
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_by_query_request.json'),
      );
    });

    test('sendet ohne Abfrage einen leeren String', () {
      const request = GsdObjectsByQueryRequest(className: 'Dokument');

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_by_query_without_query_request.json'),
      );
    });
  });
}
