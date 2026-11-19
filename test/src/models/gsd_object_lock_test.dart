@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdObjectLock', () {
    test('liest die volle Antwort; null-Meldungen fallen weg', () {
      expect(
        decodeModel(
          GsdObjectLock.fromJson,
          loadV1ModelFixture('object_lock.json'),
        ),
        const GsdObjectLock(
          isLocked: true,
          messages: ['Gesperrt von tester', 'seit 10:30'],
        ),
      );
    });

    test('nur isLocked', () {
      expect(
        decodeModel(GsdObjectLock.fromJson, {'isLocked': false}),
        const GsdObjectLock(isLocked: false),
      );
    });

    test('fehlendes isLocked wirft mit path', () {
      expect(
        () => decodeModel(GsdObjectLock.fromJson, <String, Object?>{}),
        throwsParseExceptionAt('data.isLocked'),
      );
    });

    test('falscher Typ in einer Meldung wirft mit Index', () {
      expect(
        () => decodeModel(GsdObjectLock.fromJson, {
          'isLocked': true,
          'messages': ['a', 5],
        }),
        throwsParseExceptionAt('data.messages[1]'),
      );
    });
  });
}
