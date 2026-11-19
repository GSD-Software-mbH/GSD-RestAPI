@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

void main() {
  group('GsdObjectsByParentRequest', () {
    test('sendet Kontext, Abfrage, Sortierung und Suche byte-gleich', () {
      const request = GsdObjectsByParentRequest(
        parentOid: 'PARENT-OID',
        member: 'Dokumente',
        context: 'edit',
        idList: true,
        query: 'Status=Offen',
        order: 'Name ASC',
        seFulltext: 'rechnung',
        seFulltextStem: true,
        seTextContent: 'rechnung',
        seTextContentStem: true,
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_by_parent_object_request.json'),
      );
    });

    test('lässt fehlende optionale Felder weg, statt null zu senden', () {
      const request = GsdObjectsByParentRequest(
        parentOid: 'PARENT-OID',
        member: 'Dokumente',
        idList: true,
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_by_parent_object_minimal_request.json'),
      );
    });

    test('sendet alle Suchfelder ohne Kontext byte-gleich', () {
      const request = GsdObjectsByParentRequest(
        parentOid: 'PARENT-OID',
        member: 'Dokumente',
        idList: true,
        seFulltext: 'rechnung',
        seFulltextConcept: 'FTC_ALL',
        seFulltextTypo: true,
        seTextContent: 'inhalt',
        seTextContentConcept: 3,
        seTextContentTypo: true,
        seSortByScore: false,
        seFulltextCombineAnd: true,
        seCreateTimeFrom: 1700000000,
        seCreateTimeTo: '20260101T000000',
      );

      expect(
        jsonEncode([request.toJson()]),
        loadV3Fixture('objectdata_by_parent_object_search_request.json'),
      );
    });
  });
}
