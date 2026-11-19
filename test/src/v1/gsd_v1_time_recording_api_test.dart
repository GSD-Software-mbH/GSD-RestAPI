@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  final from = DateTime.utc(2026, 6);
  final to = DateTime.utc(2026, 6, 30);

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

  final cases = <(String, Future<void> Function(GsdV1TimeRecordingApi))>[
    (
      'postPZEClockIn',
      (api) async {
        await api.postPZEClockIn(employeeoid: 'emp-1', key: 'PROJEKT_A');
      },
    ),
    (
      'postPZEClockIn (Defaults, leerer Body {})',
      (api) async {
        await api.postPZEClockIn();
      },
    ),
    (
      'postPZEClockOut',
      (api) async {
        await api.postPZEClockOut(employeeoid: 'emp-1');
      },
    ),
    (
      'postPZEClockOut (Defaults, kein Query)',
      (api) async {
        await api.postPZEClockOut();
      },
    ),
    (
      'getPZEWorkingTimeKeys',
      (api) async {
        await api.getPZEWorkingTimeKeys(serialization: '{"type":"class"}');
      },
    ),
    (
      'getPZEWorkingTimeAccounts',
      (api) async {
        await api.getPZEWorkingTimeAccounts(
          serialization: '{"type":"class"}',
          employeeOid: 'emp-1',
          from: from,
          to: to,
        );
      },
    ),
    (
      'getPZEWorkingTimeAccounts (Defaults)',
      (api) async {
        await api.getPZEWorkingTimeAccounts();
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.timeRecording);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire(
        'time_recording.$name',
        native.server.requests.single,
      );
    });
  }

  test(
    'postPZEClockIn sendet employeeoid/key im Body, clockOut als Query',
    () async {
      await native.api.v1.timeRecording.postPZEClockIn(
        employeeoid: 'e',
        key: 'k',
      );
      expect(
        native.server.requests.single.body,
        '{"employeeoid":"e","key":"k"}',
      );

      native.server.requests.clear();

      await native.api.v1.timeRecording.postPZEClockOut(employeeoid: 'e');
      final out = native.server.requests.single;
      expect(out.query, <String, String>{'employeeoid': 'e'});
      expect(out.body, '');
    },
  );
}
