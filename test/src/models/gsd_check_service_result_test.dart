@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdCheckServiceResult', () {
    test('liest die volle Antwort; webservice.version hat Vorrang', () {
      expect(
        decodeModel(
          GsdCheckServiceResult.fromJson,
          loadV1ModelFixture('check_service_result.json'),
        ),
        const GsdCheckServiceResult(
          applicationName: 'DOCUframe',
          applicationVersion: '2.4.0',
          databases: [
            GsdDocuframeDatabase('database-a', [
              GsdDocuframeModule('Basis', '1.2.3'),
              GsdDocuframeModule('Sync', ''),
            ]),
            GsdDocuframeDatabase('database-b', []),
          ],
        ),
      );
    });

    test('ohne Felder: leere Werte', () {
      expect(
        decodeModel(GsdCheckServiceResult.fromJson, <String, Object?>{}),
        const GsdCheckServiceResult(),
      );
    });

    test('ohne webservice gilt applicationVersion', () {
      expect(
        decodeModel(GsdCheckServiceResult.fromJson, {
          'applicationVersion': '1.0',
        }).applicationVersion,
        '1.0',
      );
    });

    test('falscher Typ in einem Modul wirft mit Datenbank, Index und '
        'Schlüssel', () {
      final data = loadV1ModelFixture('check_service_result.json');
      final modules =
          ((data['webservice']! as Map<String, Object?>)['moduleVersion']!
                  as Map<String, Object?>)['database-a']!
              as List<Object?>;
      (modules[1]! as Map<String, Object?>)['moduleName'] = 5;

      expect(
        () => decodeModel(GsdCheckServiceResult.fromJson, data),
        throwsParseExceptionAt(
          'data.webservice.moduleVersion.database-a[1].moduleName',
        ),
      );
    });
  });
}
