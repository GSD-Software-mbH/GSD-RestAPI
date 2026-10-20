// Unit-Tests für HeaderProvider: exakte Legacy-Header-Namen und -Casing,
// AuthenticationPolicy-Verhalten, leere Session-ID, additionalHeaders.

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/src/runtime/headers/header_provider.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/session/session_state.dart';

import 'runtime_test_helpers.dart';

void main() {
  HeaderProvider buildProvider({String sessionId = ''}) {
    return HeaderProvider(
      configuration: buildRuntimeConfiguration(),
      sessionState: SessionState(sessionId),
    );
  }

  group('HeaderProvider', () {
    test(
      'Standard-Header mit exakten Legacy-Namen und Default-Content-Type',
      () {
        final headers = buildProvider().build(
          authentication: AuthenticationPolicy.none,
        );

        expect(
          headers,
          equals({
            'Content-type': 'application/json; charset=utf-8',
            'appkey': 'TEST-APP-KEY',
          }),
        );
      },
    );

    test('Header-Namen verwenden exakt das Legacy-Casing', () {
      final headers = buildProvider(
        sessionId: 'sess-1',
      ).build(authentication: AuthenticationPolicy.session);

      expect(headers.containsKey('Content-type'), isTrue);
      expect(headers.containsKey('content-type'), isFalse);
      expect(headers.containsKey('Content-Type'), isFalse);
      expect(headers.containsKey('appkey'), isTrue);
      expect(headers.containsKey('AppKey'), isFalse);
      expect(headers.containsKey('sessionid'), isTrue);
      expect(headers.containsKey('SessionId'), isFalse);
    });

    test('session-Policy setzt sessionid bei nicht-leerer Session-ID', () {
      final headers = buildProvider(
        sessionId: 'sess-abc',
      ).build(authentication: AuthenticationPolicy.session);

      expect(headers['sessionid'], equals('sess-abc'));
    });

    test('session-Policy lässt sessionid bei leerer Session-ID weg', () {
      final headers = buildProvider(
        sessionId: '',
      ).build(authentication: AuthenticationPolicy.session);

      expect(headers.containsKey('sessionid'), isFalse);
    });

    test(
      'none-Policy setzt kein sessionid, auch wenn eine Session existiert',
      () {
        final headers = buildProvider(
          sessionId: 'sess-abc',
        ).build(authentication: AuthenticationPolicy.none);

        expect(headers.containsKey('sessionid'), isFalse);
      },
    );

    test(
      'sessionid wird bei jedem build frisch aus dem SessionState gelesen',
      () {
        final sessionState = SessionState('old');
        final provider = HeaderProvider(
          configuration: buildRuntimeConfiguration(),
          sessionState: sessionState,
        );

        sessionState.sessionId = 'new';
        final headers = provider.build(
          authentication: AuthenticationPolicy.session,
        );

        expect(headers['sessionid'], equals('new'));
      },
    );

    test('eigener Content-Type überschreibt den Default', () {
      final headers = buildProvider().build(
        authentication: AuthenticationPolicy.none,
        contentType: 'application/xml',
      );

      expect(headers['Content-type'], equals('application/xml'));
    });

    test('leerer Content-Type unterdrückt den Content-type-Header', () {
      final headers = buildProvider().build(
        authentication: AuthenticationPolicy.none,
        contentType: '',
      );

      expect(headers.containsKey('Content-type'), isFalse);
      expect(headers['appkey'], equals('TEST-APP-KEY'));
    });

    test('additionalHeaders gewinnen bei Namensgleichheit', () {
      final headers = buildProvider(sessionId: 'sess-abc').build(
        authentication: AuthenticationPolicy.session,
        additionalHeaders: {
          'Content-type': 'text/plain',
          'sessionid': 'override-session',
          'x-custom': 'yes',
        },
      );

      expect(headers['Content-type'], equals('text/plain'));
      expect(headers['sessionid'], equals('override-session'));
      expect(headers['x-custom'], equals('yes'));
      expect(headers['appkey'], equals('TEST-APP-KEY'));
    });
  });
}
