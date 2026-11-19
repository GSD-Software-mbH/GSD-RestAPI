import 'dart:async';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:gsd_restapi/src/runtime/runtime_events.dart';
import 'package:test/test.dart';

void main() {
  group('RuntimeEvents', () {
    test('liefert Ereignisse synchron an den Listener', () {
      final events = RuntimeEvents();
      final sessions = <String>[];
      final logs = <String>[];
      final metrics = <GsdHttpMetric>[];
      final licenses = <GsdLicenseException>[];
      final credentials = <GsdInvalidCredentialsException>[];
      events.sessionIdChanges.listen(sessions.add);
      events.logs.listen(logs.add);
      events.httpMetrics.listen(metrics.add);
      events.licenseErrors.listen(licenses.add);
      events.invalidCredentials.listen(credentials.add);

      const metric = GsdHttpMetric(
        path: '/v1/probe',
        method: GsdHttpMethod.get,
      );
      const license = GsdLicenseException(
        internalStatus: '306',
        statusMessage: '',
        message: 'license',
      );
      const wrong = GsdInvalidCredentialsException(
        internalStatus: '302',
        statusMessage: '',
        message: 'wrong',
      );
      events
        ..sessionIdChanged('sess-1')
        ..sessionIdChanged('')
        ..sessionIdChanged('')
        ..log('hallo')
        ..httpMetric(metric)
        ..licenseError(license)
        ..invalidCredentialsError(wrong);

      expect(sessions, <String>['sess-1', '', '']);
      expect(logs, <String>['hallo']);
      expect(metrics, [same(metric)]);
      expect(licenses, [same(license)]);
      expect(credentials, [same(wrong)]);
    });

    test('ohne Listener geht ein Ereignis verloren', () {
      final events = RuntimeEvents()..sessionIdChanged('verloren');
      final sessions = <String>[];
      events.sessionIdChanges.listen(sessions.add);

      events.sessionIdChanged('sess-2');

      expect(sessions, <String>['sess-2']);
    });

    test(
      'nach close() geht kein Ereignis mehr hinaus und nichts wirft',
      () async {
        final events = RuntimeEvents();
        final sessions = <String>[];
        var done = false;
        events.sessionIdChanges.listen(sessions.add, onDone: () => done = true);

        await events.close();
        events
          ..sessionIdChanged('zu-spaet')
          ..log('zu-spaet');
        await events.close();

        expect(sessions, isEmpty);
        expect(done, isTrue);
      },
    );

    test('requestTwoFactorToken ohne Provider liefert ""', () async {
      expect(await RuntimeEvents().requestTwoFactorToken(), isEmpty);
    });

    test('requestTwoFactorToken liefert das Token des Providers', () async {
      final events = RuntimeEvents(twoFactorTokenProvider: () async => '4711');

      expect(await events.requestTwoFactorToken(), '4711');
    });

    test('wirft der Provider, gilt das wie "" und erscheint im Log', () async {
      final events = RuntimeEvents(
        twoFactorTokenProvider: () async => throw StateError('kaputt'),
      );
      final logs = <String>[];
      events.logs.listen(logs.add);

      expect(await events.requestTwoFactorToken(), isEmpty);
      expect(logs.single, allOf(contains('2FA'), contains('kaputt')));
    });

    test('close() schließt eine offene 2FA-Anfrage mit "" ab', () async {
      final prompt = Completer<String>();
      final events = RuntimeEvents(
        twoFactorTokenProvider: () => prompt.future,
      );

      final token = events.requestTwoFactorToken();
      await events.close();
      prompt.complete('zu-spaet');

      expect(await token, isEmpty);
      expect(await events.requestTwoFactorToken(), isEmpty);
    });

    test('cancelTwoFactorRequests() schließt offene Anfragen mit "" ab, '
        'spätere fragen wieder den Provider', () async {
      final prompts = <Completer<String>>[];
      final events = RuntimeEvents(
        twoFactorTokenProvider: () {
          final prompt = Completer<String>();
          prompts.add(prompt);
          return prompt.future;
        },
      );

      final first = events.requestTwoFactorToken();
      events.cancelTwoFactorRequests();
      final second = events.requestTwoFactorToken();
      prompts.last.complete('4711');

      expect(await first, isEmpty);
      expect(await second, '4711');
      expect(prompts, hasLength(2));
    });
  });
}
