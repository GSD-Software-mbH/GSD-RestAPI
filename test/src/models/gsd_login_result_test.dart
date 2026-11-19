@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdLoginResult', () {
    test('liest die volle Antwort; null-Einträge in acls fallen weg', () {
      final result = decodeModel(
        GsdLoginResult.fromJson,
        loadV1ModelFixture('login_result.json'),
      );

      expect(result.sessionId, 'S-1');
      expect(result.isMdm2, isTrue);
      expect(result.user, {'~ObjectID': 'U-1', 'Name': 'tester'});
      expect(result.applications, const [
        GsdAclEntry(
          oid: 'ACL-1',
          status: 1,
          userName: 'tester',
          deviceID: 'device-1',
          licenseKey: 'KEY-1',
          licenseLevel: 'full',
          parallelConnections: 2,
          tfaActivated: true,
          tfaConfirmed: false,
          application: 'GSD-DFApp',
          addOns: ['Sync'],
        ),
      ]);
      expect(result.hasApplication('GSD-DFApp'), isTrue);
      expect(result.hasApplication('Andere'), isFalse);
    });

    test('nur sessionId: ohne acls kein MDM2, ohne user null', () {
      final result = decodeModel(GsdLoginResult.fromJson, {'sessionId': 'S'});

      expect(result, const GsdLoginResult(sessionId: 'S'));
      expect(result.user, isNull);
      expect(result.isMdm2, isFalse);
    });

    test('fehlende sessionId wirft mit path', () {
      expect(
        () => decodeModel(GsdLoginResult.fromJson, <String, Object?>{}),
        throwsParseExceptionAt('data.sessionId'),
      );
    });

    test('falscher Typ in einem ACL-Eintrag wirft mit Index und Schlüssel', () {
      final data = loadV1ModelFixture('login_result.json');
      final acl =
          ((data['acls']! as Map<String, Object?>)['~Elements']!
                      as List<Object?>)
                  .first!
              as Map<String, Object?>;
      acl['Status'] = 'aktiv';

      expect(
        () => decodeModel(GsdLoginResult.fromJson, data),
        throwsParseExceptionAt('data.acls.~Elements[0].Status'),
      );
    });

    test('acls ohne ~Elements wirft mit path', () {
      expect(
        () => decodeModel(GsdLoginResult.fromJson, {
          'sessionId': 'S',
          'acls': <String, Object?>{},
        }),
        throwsParseExceptionAt('data.acls'),
      );
    });
  });
}
