@TestOn('vm')
library;

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import 'model_test_support.dart';

void main() {
  group('GsdSyncObjectsResult', () {
    test('liest die volle Antwort; data bleibt unverändert', () {
      final data = loadV1ModelFixture('sync_objects_result.json');

      final result = decodeModel(GsdSyncObjectsResult.fromJson, data);

      expect(result.allContainers, ['c1', 'c2']);
      // c2 steht in allContainers, fehlt aber in der Antwort.
      expect(result.containers.keys, ['c1']);
      expect(
        result.containers['c1'],
        const GsdSyncContainer(
          containerId: 'c1',
          contentId: 'content-1',
          readOnly: true,
          count: 1,
          revision: 5,
          endMarker: 10,
          nextMarker: 10,
          classes: [
            GsdSyncDataClass(
              className: 'Adresse',
              count: 1,
              header: ['~ObjectID', 'Name'],
              data: [
                ['A-1', 'Muster'],
              ],
            ),
          ],
          deleted: ['A-0'],
        ),
      );
      expect(result.data, data);
    });

    test('ohne Felder: keine Container', () {
      expect(
        decodeModel(GsdSyncObjectsResult.fromJson, <String, Object?>{}),
        const GsdSyncObjectsResult(),
      );
    });

    test('falscher Typ in einer Datenklasse wirft mit Container, Index und '
        'Schlüssel', () {
      final data = loadV1ModelFixture('sync_objects_result.json');
      final classes =
          (data['c1']! as Map<String, Object?>)['classes']! as List<Object?>;
      (classes.first! as Map<String, Object?>)['header'] = 5;

      expect(
        () => decodeModel(GsdSyncObjectsResult.fromJson, data),
        throwsParseExceptionAt('data.c1.classes[0].header'),
      );
    });

    test('der Container rundet über toJson', () {
      final container = decodeModel(
        GsdSyncObjectsResult.fromJson,
        loadV1ModelFixture('sync_objects_result.json'),
      ).containers['c1']!;

      expect(GsdSyncContainer.fromJson(container.toJson()), container);
    });
  });
}
