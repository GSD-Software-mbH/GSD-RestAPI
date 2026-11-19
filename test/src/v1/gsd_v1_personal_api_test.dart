@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  late V1TestHarness native;

  setUp(() async {
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(TestServer.v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    native.server.fallback = success;
  });

  tearDown(() async {
    await native.close();
  });

  final cases = <(String, Future<void> Function(GsdV1PersonalApi))>[
    (
      'getPersonalUnreadDocuments',
      (api) async {
        await api.getPersonalUnreadDocuments();
      },
    ),
    (
      'getPersonalMyTasks',
      (api) async {
        await api.getPersonalMyTasks();
      },
    ),
    (
      'patchPersonalEmptyRecycleBin',
      (api) async {
        await api.patchPersonalEmptyRecycleBin();
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.personal);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('personal.$name', native.server.requests.single);
    });
  }
}
