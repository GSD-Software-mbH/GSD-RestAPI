@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdTwoFactorSecret', () {
    test('liest die volle Antwort', () {
      expect(
        decodeModel(
          GsdTwoFactorSecret.fromJson,
          loadV1ModelFixture('two_factor_secret.json'),
        ),
        const GsdTwoFactorSecret(
          isActivated: true,
          isConfirmed: true,
          status: GsdTwoFactorStatus.forced,
        ),
      );
    });

    test('ohne Felder gilt „nichts eingerichtet“', () {
      expect(
        decodeModel(GsdTwoFactorSecret.fromJson, <String, Object?>{}),
        const GsdTwoFactorSecret(),
      );
    });

    test('jeder Status wird über seine id gelesen', () {
      for (final status in GsdTwoFactorStatus.values) {
        expect(
          decodeModel(GsdTwoFactorSecret.fromJson, {
            '2faStatus': status.id,
          }).status,
          status,
        );
      }
    });

    test('ein unbekannter Status ergibt na', () {
      expect(
        decodeModel(GsdTwoFactorSecret.fromJson, {'2faStatus': 9}).status,
        GsdTwoFactorStatus.na,
      );
    });

    test('falscher Typ wirft mit path', () {
      expect(
        () => decodeModel(GsdTwoFactorSecret.fromJson, {'isActivated': 'ja'}),
        throwsParseExceptionAt('data.isActivated'),
      );
    });
  });
}
