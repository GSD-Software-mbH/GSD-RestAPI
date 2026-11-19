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

  final cases = <(String, Future<void> Function(GsdV1SettingsApi))>[
    (
      'postUserSettings',
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
    ),
    (
      'getUserSystemSettings (Defaults)',
      (api) async {
        await api.getUserSystemSettings();
      },
    ),
  ];

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.settings);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire('settings.$name', native.server.requests.single);
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

  test('getUserSystemSettings liefert GsdUserSystemSettings', () async {
    final settings = await native.api.v1.settings.getUserSystemSettings();

    expect(settings, const GsdUserSystemSettings());
  });
}
