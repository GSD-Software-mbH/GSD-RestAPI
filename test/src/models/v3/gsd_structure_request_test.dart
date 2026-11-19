@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

void main() {
  group('GsdStructureRequest', () {
    test('sendet den Body der App byte-gleich', () {
      const request = GsdStructureRequest(
        className: 'Object',
        skipDerivedClasses: false,
        skipMembers: false,
        skipBaseMembers: true,
        skipIndices: false,
        skipValueMapping: false,
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('model_structure_request.json'),
      );
    });
  });
}
