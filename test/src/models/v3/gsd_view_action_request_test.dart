@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../v3/v3_test_support.dart';

/// Eine Payload, wie die App sie baut (`DocuframeFormEnvelope.payload`).
Map<String, Object?> _payload() => {
  '~StoreTime': '20260910T104512+02:00',
  'viewOpenTime': '20260910T104123+02:00',
  'forms': {
    'editnote': {
      'HC12': {
        '~ClassName': 'Notiz',
        'Name': {'old': 'Alt', 'new': 'Neu'},
      },
    },
  },
  'data': {'folder': 'HA3G'},
};

void main() {
  group('GsdViewActionRequest', () {
    final cases = <String, (GsdViewActionRequest, String)>{
      'action zuerst, die Payload daneben auf oberster Ebene': (
        GsdViewActionRequest(
          actionOid: '4TOF',
          tryCount: 0,
          payload: _payload(),
        ),
        'view_action_request.json',
      ),
      'den Versuchszähler einer Wiederholung': (
        GsdViewActionRequest(
          actionOid: '4TOF',
          tryCount: 3,
          payload: _payload(),
        ),
        'view_action_replay_request.json',
      ),
      'gleichnamige Schlüssel der View in data': (
        GsdViewActionRequest(
          actionOid: '4TOF',
          tryCount: 0,
          payload: {
            ..._payload(),
            'data': {
              '~StoreTime': 'vom View',
              'forms': 'vom View',
              'action': 'vom View',
            },
          },
        ),
        'view_action_view_keys_in_data_request.json',
      ),
      'viewOpenTime null, forms leer und data null': (
        const GsdViewActionRequest(
          actionOid: '4TOF',
          tryCount: 1,
          payload: {
            '~StoreTime': '20260910T104512+02:00',
            'viewOpenTime': null,
            'forms': <String, Object?>{},
            'data': null,
          },
        ),
        'view_action_without_form_request.json',
      ),
      'eine leere Payload': (
        const GsdViewActionRequest(actionOid: '4TOF', tryCount: 0, payload: {}),
        'view_action_empty_payload_request.json',
      ),
      'ohne Payload nur action': (
        const GsdViewActionRequest(actionOid: '4TOF', tryCount: 0),
        'view_action_empty_payload_request.json',
      ),
    };

    for (final MapEntry(key: name, value: (request, fixture))
        in cases.entries) {
      test('sendet $name byte-gleich', () {
        expect(jsonEncode(request.toJson()), loadV3Fixture(fixture));
      });
    }

    test('reicht die Payload-Werte unverändert durch', () {
      final payload = _payload();

      final json = GsdViewActionRequest(
        actionOid: '4TOF',
        tryCount: 0,
        payload: payload,
      ).toJson();

      expect(json['forms'], same(payload['forms']));
      expect(json['data'], same(payload['data']));
    });
  });
}
