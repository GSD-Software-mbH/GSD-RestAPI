import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

void main() {
  group('Config Integration Tests', () {
    late GsdApiConfig config;

    setUp(() {
      config = GsdApiConfig(
        appKey: 'INTEGRATION-TEST-KEY',
        userName: 'integration-user',
        appNames: ['IntegrationTestApp'],
        serverUrl: 'https://localhost:8080',
        alias: 'integration-test',
        perPageCount: 25,
        bufferFlushDelayMs: 50,
        maxBufferSize: 5,
        multiRequest: true,
      );
    });

    group('Device Integration Tests', () {
      test('Sollte Device-Konfiguration korrekt verwenden', () {
        // Arrange
        final testDevice = GsdDocuframeDevice(
          'integration-device-123',
          device: 'Integration Test Device',
          systemVersion: 'Test OS 1.0',
          deviceType: GsdDocuframeDeviceType.web,
          fireBaseToken: 'integration-firebase-token',
        );

        config = GsdApiConfig(
          appKey: 'DEVICE-TEST-KEY',
          userName: 'device-user',
          appNames: ['DeviceApp'],
          serverUrl: 'https://localhost:8080',
          alias: 'device-test',
          device: testDevice,
        );

        // Act
        final deviceJson = config.device!.toJson();

        // Assert
        expect(config.device, equals(testDevice));
        expect(deviceJson['deviceId'], equals('integration-device-123'));
        expect(deviceJson['device'], equals('Integration Test Device'));
        expect(deviceJson['systemVersion'], equals('Test OS 1.0'));
        expect(
          deviceJson['deviceType'].toString(),
          equals(GsdDocuframeDeviceType.web.id.toString()),
        );
      });
    });
  });
}
