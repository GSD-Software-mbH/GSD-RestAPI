@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdVersionInfo', () {
    test('liest die volle Antwort', () {
      expect(
        decodeModel(
          GsdVersionInfo.fromJson,
          loadV1ModelFixture('version_info.json'),
        ),
        GsdVersionInfo(
          serviceVersion: '5.6.7',
          structureChangeDate: DateTime.parse('2026-07-20T10:30:00.000Z'),
          modules: const [GsdDocuframeModule('Customizing', '3.2.1')],
        ),
      );
    });

    test('ohne Felder: leere Werte', () {
      expect(
        decodeModel(GsdVersionInfo.fromJson, <String, Object?>{}),
        const GsdVersionInfo(),
      );
    });

    test('ein leeres Datum ergibt null', () {
      expect(
        decodeModel(GsdVersionInfo.fromJson, {
          'structureChangeDate': '',
        }).structureChangeDate,
        isNull,
      );
    });

    test('falscher Typ in einem Modul wirft mit Index und Schlüssel', () {
      expect(
        () => decodeModel(GsdVersionInfo.fromJson, {
          'listOfModules': [
            {'moduleName': 'A'},
            {'moduleName': 'B', 'moduleVersion': 1},
          ],
        }),
        throwsParseExceptionAt('data.listOfModules[1].moduleVersion'),
      );
    });
  });
}
