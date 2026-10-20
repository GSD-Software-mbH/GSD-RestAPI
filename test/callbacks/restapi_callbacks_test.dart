import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

void main() {
  group('RestApiCallbacks Tests', () {
    late RestApiCallbacks callbacks;

    setUp(() {
      callbacks = RestApiCallbacks();
    });

    tearDown(() {
      callbacks.clearAllCallbacks();
    });

    group('Konstruktor Tests', () {
      test('Sollte leere Callbacks erstellen', () {
        // Arrange & Act
        callbacks = RestApiCallbacks();

        // Assert
        expect(callbacks.onLogMessage, isNull);
        expect(callbacks.onHttpMetricRecorded, isNull);
      });

      test('Sollte Callbacks mit Parametern erstellen', () {
        // Arrange
        Future<void> logFunction(String message) async {
          // Test log function
        }

        Future<void> metricFunction(RestApiHttpMetric metric) async {
          // Test metric function
        }

        // Act
        callbacks = RestApiCallbacks(
          onLogMessage: logFunction,
          onHttpMetricRecorded: metricFunction,
        );

        // Assert
        expect(callbacks.onLogMessage, equals(logFunction));
        expect(callbacks.onHttpMetricRecorded, equals(metricFunction));
      });
    });

    group('Event Trigger Tests', () {
      test('Sollte Log-Event ohne Callback nicht fehlschlagen', () async {
        // Arrange & Act & Assert
        expect(
          () async => await callbacks.triggerLogEvent('Test message'),
          returnsNormally,
        );
      });

      test('Sollte Log-Event mit Callback aufrufen', () async {
        // Arrange
        String receivedMessage = '';
        callbacks.onLogMessage = (String message) async {
          receivedMessage = message;
        };

        // Act
        await callbacks.triggerLogEvent('Test log message');

        // Assert
        expect(receivedMessage, equals('Test log message'));
      });

      test(
        'Sollte HTTP-Metric-Event ohne Callback nicht fehlschlagen',
        () async {
          // Arrange
          RestApiHttpMetric testMetric = RestApiHttpMetric(
            'test',
            HttpMethod.get,
          );

          // Act & Assert
          expect(
            () async =>
                await callbacks.triggerHttpMetricRecordedEvent(testMetric),
            returnsNormally,
          );
        },
      );

      test('Sollte HTTP-Metric-Event mit Callback aufrufen', () async {
        // Arrange
        RestApiHttpMetric? receivedMetric;
        callbacks.onHttpMetricRecorded = (RestApiHttpMetric metric) async {
          receivedMetric = metric;
        };

        RestApiHttpMetric testMetric = RestApiHttpMetric(
          'test-function',
          HttpMethod.post,
        );

        // Act
        await callbacks.triggerHttpMetricRecordedEvent(testMetric);

        // Assert
        expect(receivedMetric, equals(testMetric));
        expect(receivedMetric?.path, equals('test-function'));
        expect(receivedMetric?.method, equals(HttpMethod.post));
      });
    });

    group('Callback Management Tests', () {
      test('Sollte Callbacks nach der Erstellung setzen können', () {
        // Arrange
        Future<void> newLogFunction(String message) async {
          // New log function
        }

        // Act
        callbacks.onLogMessage = newLogFunction;

        // Assert
        expect(callbacks.onLogMessage, equals(newLogFunction));
      });

      test('Sollte Callbacks überschreiben können', () {
        // Arrange
        Future<void> firstFunction(String message) async {
          // First function
        }

        Future<void> secondFunction(String message) async {
          // Second function
        }

        callbacks.onLogMessage = firstFunction;

        // Act
        callbacks.onLogMessage = secondFunction;

        // Assert
        expect(callbacks.onLogMessage, equals(secondFunction));
      });

      test('Sollte Callbacks auf null setzen können', () {
        // Arrange
        Future<void> testFunction(String message) async {
          // Test function
        }

        callbacks.onLogMessage = testFunction;
        expect(callbacks.onLogMessage, isNotNull);

        // Act
        callbacks.onLogMessage = null;

        // Assert
        expect(callbacks.onLogMessage, isNull);
      });

      test('Sollte alle Callbacks mit clearAllCallbacks löschen', () {
        // Arrange
        Future<void> logFunction(String message) async {}
        Future<void> metricFunction(RestApiHttpMetric metric) async {}

        callbacks.onLogMessage = logFunction;
        callbacks.onHttpMetricRecorded = metricFunction;

        expect(callbacks.onLogMessage, isNotNull);
        expect(callbacks.onHttpMetricRecorded, isNotNull);

        // Act
        callbacks.clearAllCallbacks();

        // Assert
        expect(callbacks.onLogMessage, isNull);
        expect(callbacks.onHttpMetricRecorded, isNull);
      });
    });

    group('Multiple Callbacks Tests', () {
      test('Sollte mehrere Log-Events nacheinander verarbeiten', () async {
        // Arrange
        List<String> receivedMessages = [];
        callbacks.onLogMessage = (String message) async {
          receivedMessages.add(message);
        };

        // Act
        await callbacks.triggerLogEvent('Message 1');
        await callbacks.triggerLogEvent('Message 2');
        await callbacks.triggerLogEvent('Message 3');

        // Assert
        expect(receivedMessages.length, equals(3));
        expect(
          receivedMessages,
          equals(['Message 1', 'Message 2', 'Message 3']),
        );
      });

      test(
        'Sollte verschiedene Event-Typen gleichzeitig verarbeiten',
        () async {
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
            'test',
            HttpMethod.get,
          );

          // Act
          await callbacks.triggerLogEvent('Test log');
          await callbacks.triggerHttpMetricRecordedEvent(testMetric);

          // Assert
          expect(logMessage, equals('Test log'));
          expect(receivedMetric, equals(testMetric));
        },
      );
    });

    group('Performance Tests', () {
      test('Sollte viele Events schnell verarbeiten können', () async {
        // Arrange
        int eventCount = 0;
        callbacks.onLogMessage = (String message) async {
          eventCount++;
        };

        // Act
        Stopwatch stopwatch = Stopwatch()..start();
        for (int i = 0; i < 1000; i++) {
          await callbacks.triggerLogEvent('Message $i');
        }
        stopwatch.stop();

        // Assert
        expect(eventCount, equals(1000));
        expect(
          stopwatch.elapsedMilliseconds,
          lessThan(1000),
        ); // Sollte unter 1 Sekunde sein
      });
    });
  });
}
