import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';

import 'v1_test_support.dart';

void main() {
  late V1TestHarness harness;

  setUp(() async {
    harness = await V1TestHarness.start();
  });

  tearDown(() => harness.close());

  test(
    'getSyncClassInfo ruft den versionierten xSync-ClassInfo-Pfad auf',
    () async {
      harness.enqueueSuccess(
        'GET',
        '/dfapp/v1/xSync/ClassInfo/App1',
        data: <String, dynamic>{
          'classes': <String>['Class1'],
        },
      );

      final RestApiResponse response = await harness.api.v1.xSync
          .getSyncClassInfo('App1');

      expect(response.isOk, isTrue);
      harness.expectRequest(
        harness.server.requests.single,
        method: 'GET',
        path: '/dfapp/v1/xSync/ClassInfo/App1',
      );
    },
  );

  test('getSyncObjectsOfClass ohne Parameter sendet keinen Body', () async {
    harness.enqueueSuccess(
      'POST',
      '/dfapp/v1/xSync/dynamic/App1/Class1',
      data: <String, dynamic>{
        'allContainers': <String>['c1'],
        'c1': <String, dynamic>{
          'containerId': 'c1',
          'revision': 5,
          'nextMarker': 10,
          'classes': <Map<String, dynamic>>[],
        },
      },
    );

    final RestApiSyncClassResponse response = await harness.api.v1.xSync
        .getSyncObjectsOfClass('App1', 'Class1');

    expect(response.allContainers, <String>['c1']);
    expect(response.containers['c1']!.revision, 5);
    expect(response.containers['c1']!.nextMarker, 10);
    harness.expectRequest(
      harness.server.requests.single,
      method: 'POST',
      path: '/dfapp/v1/xSync/dynamic/App1/Class1',
    );
  });

  test(
    'getSyncObjectsOfClass sendet maxRecords und nextContainers im Body',
    () async {
      harness.enqueueSuccess(
        'POST',
        '/dfapp/v1/xSync/dynamic/App1/Class1',
        data: <String, dynamic>{'allContainers': <String>[]},
      );

      await harness.api.v1.xSync.getSyncObjectsOfClass(
        'App1',
        'Class1',
        maxRecords: 50,
        nextContainers: <RestApiSyncContainer>[
          RestApiSyncContainer(containerId: 'c1', revision: 3, nextMarker: 7),
        ],
      );

      harness.expectRequest(
        harness.server.requests.single,
        method: 'POST',
        path: '/dfapp/v1/xSync/dynamic/App1/Class1',
        body: '{"maxRecords":50,"c1":{"lastMarker":7,"revision":3}}',
      );
    },
  );
}
