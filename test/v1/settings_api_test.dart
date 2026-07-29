// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
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
      Future<void> Function(V1SettingsApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1SettingsApi),
        )
      >[
        (
          'postUserSettings',
          (api) async {
            await api.postUserSettings('dashboard', <String, dynamic>{
              'theme': 'dark',
              'columns': 3,
            });
          },
          (api) async {
            await api.postUserSettings('dashboard', <String, dynamic>{
              'theme': 'dark',
              'columns': 3,
            });
          },
        ),
        (
          'getUserSystemSettings',
          (api) async {
            await api.getUserSystemSettings(eventMacroName: 'myEvent');
          },
          (api) async {
            await api.getUserSystemSettings(eventMacroName: 'myEvent');
          },
        ),
        (
          'getUserSystemSettings (Defaults)',
          (api) async {
            await api.getUserSystemSettings();
          },
          (api) async {
            await api.getUserSystemSettings();
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.settings);

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

  test('postUserSettings hängt den key an den Pfad an', () async {
    await native.api.v1.settings.postUserSettings(
      'dashboard',
      <String, dynamic>{'x': 1},
    );

    expect(
      native.server.requests.single.path,
      '/dfapp/v1/userSetting/dashboard',
    );
  });

  test('getUserSystemSettings liefert den typisierten Response', () async {
    final RestApiUserSystemSettingsResponse response = await native
        .api
        .v1
        .settings
        .getUserSystemSettings();

    expect(response.isOk, isTrue);
  });
}
