import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('RestApiDOCUframeCallbacks Tests', () {
    late RestApiDOCUframeCallbacks callbacks;

    setUp(() {
      callbacks = RestApiDOCUframeCallbacks();
    });

    tearDown(() {
      callbacks.clearAllCallbacks();
    });

    group('Konstruktor Tests', () {
      test('Sollte leere DOCUframe-Callbacks erstellen', () {
        // Arrange & Act
        callbacks = RestApiDOCUframeCallbacks();

        // Assert
        // Basis-Callbacks
        expect(callbacks.onLogMessage, isNull);
        expect(callbacks.onHttpMetricRecorded, isNull);

        // DOCUframe-spezifische Callbacks
        expect(callbacks.onMissing2FAToken, isNull);
        expect(callbacks.onLicenseWrong, isNull);
        expect(callbacks.onSessionIdChanged, isNull);
        expect(callbacks.onUserAndPassWrong, isNull);
      });

      test('Sollte DOCUframe-Callbacks mit allen Parametern erstellen', () {
        // Arrange
        Future<void> logFunction(String message) async {}
        Future<void> metricFunction(RestApiHttpMetric metric) async {}
        Future<String> tokenFunction() async => 'test-token';
        Future<void> licenseFunction(LicenseException e) async {}
        Future<void> sessionFunction(String sessionId) async {}
        Future<void> authFunction(UserAndPassWrongException e) async {}

        // Act
        callbacks = RestApiDOCUframeCallbacks(
          onLogMessage: logFunction,
          onHttpMetricRecorded: metricFunction,
          onMissing2FAToken: tokenFunction,
          onLicenseWrong: licenseFunction,
          onSessionIdChanged: sessionFunction,
          onUserAndPassWrong: authFunction,
        );

        // Assert
        expect(callbacks.onLogMessage, equals(logFunction));
        expect(callbacks.onHttpMetricRecorded, equals(metricFunction));
        expect(callbacks.onMissing2FAToken, equals(tokenFunction));
        expect(callbacks.onLicenseWrong, equals(licenseFunction));
        expect(callbacks.onSessionIdChanged, equals(sessionFunction));
        expect(callbacks.onUserAndPassWrong, equals(authFunction));
      });
    });

    group('DOCUframe Event Trigger Tests', () {
      test(
        'Sollte Session-ID-Changed-Event ohne Callback nicht fehlschlagen',
        () async {
          // Arrange & Act & Assert
          expect(
            () async =>
                await callbacks.triggerSessionIdChangedEvent('test-session'),
            returnsNormally,
          );
        },
      );

      test('Sollte Session-ID-Changed-Event mit Callback aufrufen', () async {
        // Arrange
        String? receivedSessionId;
        callbacks.onSessionIdChanged = (String sessionId) async {
          receivedSessionId = sessionId;
        };

        // Act
        await callbacks.triggerSessionIdChangedEvent('new-session-123');

        // Assert
        expect(receivedSessionId, equals('new-session-123'));
      });

      test(
        'Sollte License-Wrong-Event ohne Callback nicht fehlschlagen',
        () async {
          // Arrange
          LicenseException testException = LicenseException(
            'Test license error',
          );

          // Act & Assert
          expect(
            () async => await callbacks.triggerLicenseWrongEvent(testException),
            returnsNormally,
          );
        },
      );

      test('Sollte License-Wrong-Event mit Callback aufrufen', () async {
        // Arrange
        LicenseException? receivedException;
        callbacks.onLicenseWrong = (LicenseException e) async {
          receivedException = e;
        };

        LicenseException testException = LicenseException('License expired');

        // Act
        await callbacks.triggerLicenseWrongEvent(testException);

        // Assert
        expect(receivedException, equals(testException));
        expect(receivedException?.message, equals('License expired'));
      });

      test(
        'Sollte User-And-Pass-Wrong-Event ohne Callback nicht fehlschlagen',
        () async {
          // Arrange
          UserAndPassWrongException testException = UserAndPassWrongException(
            'Invalid credentials',
          );

          // Act & Assert
          expect(
            () async =>
                await callbacks.triggerUserAndPassWrongEvent(testException),
            returnsNormally,
          );
        },
      );

      test('Sollte User-And-Pass-Wrong-Event mit Callback aufrufen', () async {
        // Arrange
        UserAndPassWrongException? receivedException;
        callbacks.onUserAndPassWrong = (UserAndPassWrongException e) async {
          receivedException = e;
        };

        UserAndPassWrongException testException = UserAndPassWrongException(
          'Wrong password',
        );

        // Act
        await callbacks.triggerUserAndPassWrongEvent(testException);

        // Assert
        expect(receivedException, equals(testException));
        expect(receivedException?.message, equals('Wrong password'));
      });

      test(
        'Sollte Missing-2FA-Token-Event ohne Callback leeren String zurückgeben',
        () async {
          // Arrange & Act
          String result = await callbacks.triggerMissing2FATokenEvent();

          // Assert
          expect(result, equals(''));
        },
      );

      test(
        'Sollte Missing-2FA-Token-Event mit Callback Token zurückgeben',
        () async {
          // Arrange
          callbacks.onMissing2FAToken = () async => '123456';

          // Act
          String result = await callbacks.triggerMissing2FATokenEvent();

          // Assert
          expect(result, equals('123456'));
        },
      );

      test(
        'Sollte Missing-2FA-Token-Event mit leerem Callback leeren String zurückgeben',
        () async {
          // Arrange
          callbacks.onMissing2FAToken = () async => '';

          // Act
          String result = await callbacks.triggerMissing2FATokenEvent();

          // Assert
          expect(result, equals(''));
        },
      );
    });

    group('Vererbung Tests', () {
      test('Sollte Basis-Callbacks erben und verwenden können', () async {
        // Arrange
        String? logMessage;
        RestApiHttpMetric? receivedMetric;

        callbacks.onLogMessage = (String message) async {
          logMessage = message;
        };

        callbacks.onHttpMetricRecorded = (RestApiHttpMetric metric) async {
          receivedMetric = metric;
        };

        RestApiHttpMetric testMetric = RestApiHttpMetric(
          'test-path',
          HttpMethod.get,
        );

        // Act
        await callbacks.triggerLogEvent('Test inheritance');
        await callbacks.triggerHttpMetricRecordedEvent(testMetric);

        // Assert
        expect(logMessage, equals('Test inheritance'));
        expect(receivedMetric, equals(testMetric));
      });
    });

    group('Callback Management Tests', () {
      test('Sollte DOCUframe-Callbacks nach der Erstellung setzen können', () {
        // Arrange
        Future<String> newTokenFunction() async => 'new-token';

        // Act
        callbacks.onMissing2FAToken = newTokenFunction;

        // Assert
        expect(callbacks.onMissing2FAToken, equals(newTokenFunction));
      });

      test('Sollte alle Callbacks mit clearAllCallbacks löschen', () {
        // Arrange
        Future<void> logFunction(String message) async {}
        Future<void> metricFunction(RestApiHttpMetric metric) async {}
        Future<String> tokenFunction() async => 'token';
        Future<void> licenseFunction(LicenseException e) async {}
        Future<void> sessionFunction(String sessionId) async {}
        Future<void> authFunction(UserAndPassWrongException e) async {}

        callbacks.onLogMessage = logFunction;
        callbacks.onHttpMetricRecorded = metricFunction;
        callbacks.onMissing2FAToken = tokenFunction;
        callbacks.onLicenseWrong = licenseFunction;
        callbacks.onSessionIdChanged = sessionFunction;
        callbacks.onUserAndPassWrong = authFunction;

        // Verify callbacks are set
        expect(callbacks.onLogMessage, isNotNull);
        expect(callbacks.onHttpMetricRecorded, isNotNull);
        expect(callbacks.onMissing2FAToken, isNotNull);
        expect(callbacks.onLicenseWrong, isNotNull);
        expect(callbacks.onSessionIdChanged, isNotNull);
        expect(callbacks.onUserAndPassWrong, isNotNull);

        // Act
        callbacks.clearAllCallbacks();

        // Assert
        expect(callbacks.onLogMessage, isNull);
        expect(callbacks.onHttpMetricRecorded, isNull);
        expect(callbacks.onMissing2FAToken, isNull);
        expect(callbacks.onLicenseWrong, isNull);
        expect(callbacks.onSessionIdChanged, isNull);
        expect(callbacks.onUserAndPassWrong, isNull);
      });
    });

    group('Complex Workflow Tests', () {
      test(
        'Sollte kompletten Login-Workflow mit Callbacks simulieren',
        () async {
          // Arrange
          List<String> eventLog = [];

          callbacks.onLogMessage = (String message) async {
            eventLog.add('LOG: $message');
          };

          callbacks.onSessionIdChanged = (String sessionId) async {
            eventLog.add('SESSION: $sessionId');
          };

          callbacks.onUserAndPassWrong = (UserAndPassWrongException e) async {
            eventLog.add('AUTH_ERROR: ${e.message}');
          };

          callbacks.onMissing2FAToken = () async {
            eventLog.add('2FA_REQUEST');
            return '654321';
          };

          // Act - Simuliere Login-Workflow
          await callbacks.triggerLogEvent('Login attempt started');
          await callbacks.triggerUserAndPassWrongEvent(
            UserAndPassWrongException('First attempt failed'),
          );
          await callbacks.triggerLogEvent('Requesting 2FA token');
          String token = await callbacks.triggerMissing2FATokenEvent();
          await callbacks.triggerLogEvent('2FA token received: $token');
          await callbacks.triggerSessionIdChangedEvent('session-abc-123');
          await callbacks.triggerLogEvent('Login completed');

          // Assert
          expect(eventLog.length, equals(7));
          expect(eventLog[0], equals('LOG: Login attempt started'));
          expect(eventLog[1], equals('AUTH_ERROR: First attempt failed'));
          expect(eventLog[2], equals('LOG: Requesting 2FA token'));
          expect(eventLog[3], equals('2FA_REQUEST'));
          expect(eventLog[4], equals('LOG: 2FA token received: 654321'));
          expect(eventLog[5], equals('SESSION: session-abc-123'));
          expect(eventLog[6], equals('LOG: Login completed'));
        },
      );

      test('Sollte License-Error-Workflow simulieren', () async {
        // Arrange
        List<String> errorLog = [];

        callbacks.onLicenseWrong = (LicenseException e) async {
          errorLog.add('License Error: ${e.message}');
        };

        callbacks.onSessionIdChanged = (String sessionId) async {
          errorLog.add('Session cleared: $sessionId');
        };

        // Act
        await callbacks.triggerLicenseWrongEvent(
          LicenseException('License has expired'),
        );
        await callbacks.triggerSessionIdChangedEvent(
          '',
        ); // Session wird geleert

        // Assert
        expect(errorLog.length, equals(2));
        expect(errorLog[0], equals('License Error: License has expired'));
        expect(errorLog[1], equals('Session cleared: '));
      });
    });

    group('Multiple Event Tests', () {
      test('Sollte mehrere gleichzeitige Events verarbeiten', () async {
        // Arrange
        int sessionChangeCount = 0;
        int licenseErrorCount = 0;

        callbacks.onSessionIdChanged = (String sessionId) async {
          sessionChangeCount++;
        };

        callbacks.onLicenseWrong = (LicenseException e) async {
          licenseErrorCount++;
        };

        // Act
        List<Future<void>> futures = [
          callbacks.triggerSessionIdChangedEvent('session1'),
          callbacks.triggerSessionIdChangedEvent('session2'),
          callbacks.triggerLicenseWrongEvent(LicenseException('error1')),
          callbacks.triggerLicenseWrongEvent(LicenseException('error2')),
          callbacks.triggerSessionIdChangedEvent('session3'),
        ];

        await Future.wait(futures);

        // Assert
        expect(sessionChangeCount, equals(3));
        expect(licenseErrorCount, equals(2));
      });
    });
  });
}
