// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  final DateTime from = DateTime.utc(2026, 6, 1);
  final DateTime to = DateTime.utc(2026, 6, 30);

  late LegacyTestServer legacyServer;
  late RestApiDOCUframeManager legacy;
  late V1TestHarness native;

  setUp(() async {
    HttpOverrides.global = null;
    legacyServer = LegacyTestServer();
    await legacyServer.start();
    legacy = RestApiDOCUframeManager(
      config: buildLegacyConfig(
        legacyServer,
        sessionId: V1TestHarness.sessionId,
      ),
    );
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    legacyServer.fallback = success;
    native.server.fallback = success;
  });

  tearDown(() async {
    legacy.dispose();
    await legacyServer.close();
    await native.close();
  });

  final List<
    (
      String,
      Future<void> Function(RestApiDOCUframeManager),
      Future<void> Function(V1TimeRecordingApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1TimeRecordingApi),
        )
      >[
        (
          'postPZEClockIn',
          (api) async {
            await api.postPZEClockIn(employeeoid: 'emp-1', key: 'PROJEKT_A');
          },
          (api) async {
            await api.postPZEClockIn(employeeoid: 'emp-1', key: 'PROJEKT_A');
          },
        ),
        (
          'postPZEClockIn (Defaults, leerer Body {})',
          (api) async {
            await api.postPZEClockIn();
          },
          (api) async {
            await api.postPZEClockIn();
          },
        ),
        (
          'postPZEClockOut',
          (api) async {
            await api.postPZEClockOut(employeeoid: 'emp-1');
          },
          (api) async {
            await api.postPZEClockOut(employeeoid: 'emp-1');
          },
        ),
        (
          'postPZEClockOut (Defaults, kein Query)',
          (api) async {
            await api.postPZEClockOut();
          },
          (api) async {
            await api.postPZEClockOut();
          },
        ),
        (
          'getPZEWorkingTimeKeys',
          (api) async {
            await api.getPZEWorkingTimeKeys(serialization: '{"type":"class"}');
          },
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
          (api) async {
            await api.getPZEWorkingTimeAccounts();
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.timeRecording);

      expect(legacyServer.requests, hasLength(1));
      expect(native.server.requests, hasLength(1));
      final RecordedRequest legacyRequest = legacyServer.requests.single;
      final RecordedRequest nativeRequest = native.server.requests.single;
      expect(nativeRequest.method, legacyRequest.method);
      expect(nativeRequest.path, legacyRequest.path);
      expect(nativeRequest.query, legacyRequest.query);
      expect(nativeRequest.body, legacyRequest.body);
      expect(
        nativeRequest.header('sessionid'),
        legacyRequest.header('sessionid'),
      );
      expect(nativeRequest.header('appkey'), legacyRequest.header('appkey'));
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
      final RecordedRequest out = native.server.requests.single;
      expect(out.query, <String, String>{'employeeoid': 'e'});
      expect(out.body, '');
    },
  );
}
