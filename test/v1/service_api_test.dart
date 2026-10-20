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
    'checkService nutzt den unversionierten Pfad und typisierte Abbildung',
    () async {
      harness.enqueueSuccess(
        'GET',
        '/dfapp/_CheckService',
        data: <String, dynamic>{
          'applicationName': 'DOCUframe',
          'applicationVersion': 'fallback-version',
          'webservice': <String, dynamic>{
            'version': '2.4.0',
            'moduleVersion': <String, dynamic>{
              'database-a': <Map<String, dynamic>>[
                <String, dynamic>{
                  'moduleName': 'Basis',
                  'moduleVersion': '1.2.3',
                },
              ],
            },
          },
        },
      );

      final RestApiCheckServiceResponse response = await harness.api.v1.service
          .checkService();

      expect(response.applicationName, 'DOCUframe');
      expect(response.applicationVersion, '2.4.0');
      expect(response.databases.single.name, 'database-a');
      expect(response.databases.single.modules.single.name, 'Basis');
      harness.expectRequest(
        harness.server.requests.single,
        method: 'GET',
        path: '/dfapp/_CheckService',
      );
    },
  );

  test(
    'checkServiceWithUri verwendet die absolute URI exakt und ohne Header',
    () async {
      harness.enqueueSuccess('GET', '/external/_CheckService', data: const {});
      final Uri uri = Uri.parse(
        '${harness.server.baseUrl}/external/_CheckService?probe=exact',
      );

      final RestApiCheckServiceResponse response = await harness.api.v1.service
          .checkServiceWithUri(uri);

      expect(response.isOk, isTrue);
      final request = harness.server.requests.single;
      expect(request.path, '/external/_CheckService');
      expect(request.query, const <String, String>{'probe': 'exact'});
      expect(request.header('appkey'), isNull);
      expect(request.header('sessionid'), isNull);
      expect(request.header('content-type'), isNull);
    },
  );

  test(
    'postLicenseRelease verwendet Body und ausschließlich supplied session',
    () async {
      harness.enqueueSuccess('POST', '/dfapp/v1/license/release');

      final RestApiResponse response = await harness.api.v1.service
          .postLicenseRelease(<String>['App1', 'App2'], 'RELEASE-SESSION');

      expect(response.isOk, isTrue);
      harness.expectRequest(
        harness.server.requests.single,
        method: 'POST',
        path: '/dfapp/v1/license/release',
        body: '{"appNames":["App1","App2"]}',
        sessionId: 'RELEASE-SESSION',
      );
    },
  );

  test(
    'getVersionInfo bewahrt Pfad und bestehenden typisierten Response',
    () async {
      harness.enqueueSuccess(
        'GET',
        '/dfapp/v1/versioninfo',
        data: <String, dynamic>{
          'webserviceVersion': '5.6.7',
          'structureChangeDate': '2026-07-20T10:30:00.000Z',
          'listOfModules': <Map<String, dynamic>>[
            <String, dynamic>{
              'moduleName': 'Customizing',
              'moduleVersion': '3.2.1',
            },
          ],
        },
      );

      final RestApiVersionInfoResponse response = await harness.api.v1.service
          .getVersionInfo();

      expect(response.serviceVersion, '5.6.7');
      expect(
        response.structureChangeDate,
        DateTime.parse('2026-07-20T10:30:00.000Z'),
      );
      expect(response.modules.single.name, 'Customizing');
      harness.expectRequest(
        harness.server.requests.single,
        method: 'GET',
        path: '/dfapp/v1/versioninfo',
      );
    },
  );
}
