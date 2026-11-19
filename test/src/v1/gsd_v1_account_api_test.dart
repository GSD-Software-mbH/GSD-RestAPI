@TestOn('vm')
library;

import 'dart:convert';

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

  test(
    'createDemoAccount entspricht dem beobachteten Legacy-Wire-Vertrag',
    () async {
      await native.api.v1.account.createDemoAccount('secret-pw');

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire(
        'account.createDemoAccount',
        native.server.requests.single,
      );
    },
  );

  test('createDemoAccount nutzt Pfad und deviceId/password-Body', () async {
    await native.api.v1.account.createDemoAccount('secret-pw');

    final request = native.server.requests.single;
    expect(request.method, 'POST');
    expect(request.path, '/dfapp/v1/DF/CreateDemoUser');
    final body = jsonDecode(request.body) as Map<String, dynamic>;
    expect(body.containsKey('deviceId'), isTrue);
    expect(body['password'], 'secret-pw');
  });
}
