@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

void main() {
  group('GsdViewLoadRequest', () {
    test('sendet den Body der App byte-gleich, ohne Klasse und Kontext '
        'als leere Strings', () {
      const requests = [
        GsdViewLoadRequest(
          viewName: 'edit',
          className: 'Dokument',
          context: 'mobile',
        ),
        GsdViewLoadRequest(viewName: 'theme'),
      ];

      expect(
        jsonEncode([for (final request in requests) request.toJson()]),
        loadV3Fixture('view_load_request.json'),
      );
    });
  });
}
