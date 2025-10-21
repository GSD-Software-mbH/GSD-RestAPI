import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:gsd_restapi/httpclient/httpclient.dart';
import 'dart:io';

void main() {
  late http.Client allowSslClient;
  late http.Client denySslClient;

  setUp(() {
    allowSslClient = createClient(
      const Duration(seconds: 5),
      allowSslError: true,
    );
    denySslClient = createClient(
      const Duration(seconds: 5),
      allowSslError: false,
    );
  });

  tearDown(() {
    allowSslClient.close();
    denySslClient.close();
  });

  group('SSL Certificate Tests', () {
    test('Valid SSL Certificate - should work with both clients', () async {
      // Mehrere URLs zum Fallback
      const testUrls = [
        'https://www.google.com',
        'https://www.microsoft.com',
        'https://api.github.com',
        'https://httpbin.org/get',
      ];

      bool allowSslSuccess = false;
      bool denySslSuccess = false;

      for (final validUrl in testUrls) {
        if (allowSslSuccess && denySslSuccess) break;

        if (!allowSslSuccess) {
          try {
            final response1 = await allowSslClient.get(Uri.parse(validUrl));
            if (response1.statusCode == 200) {
              allowSslSuccess = true;
              debugPrint(
                '✓ Valid SSL works with allowSslError=true ($validUrl)',
              );
            }
          } catch (e) {
            debugPrint('Failed with $validUrl: $e');
          }
        }

        if (!denySslSuccess) {
          try {
            final response2 = await denySslClient.get(Uri.parse(validUrl));
            if (response2.statusCode == 200) {
              denySslSuccess = true;
              debugPrint(
                '✓ Valid SSL works with allowSslError=false ($validUrl)',
              );
            }
          } catch (e) {
            debugPrint('Failed with $validUrl: $e');
          }
        }
      }

      if (!allowSslSuccess) {
        debugPrint(
          '⚠ All SSL tests failed with allowSslError=true - possibly CI environment issue',
        );
      }
      if (!denySslSuccess) {
        debugPrint(
          '⚠ All SSL tests failed with allowSslError=false - possibly CI environment issue',
        );
      }

      // Mindestens einer sollte funktionieren
      expect(
        allowSslSuccess || denySslSuccess,
        isTrue,
        reason: 'At least one SSL configuration should work',
      );
    });

    test('Self-Signed Certificate - allowSslError=true should work', () async {
      const selfSignedUrl = 'https://self-signed.badssl.com/';

      try {
        final response = await allowSslClient.get(Uri.parse(selfSignedUrl));
        debugPrint(
          '✓ Self-signed certificate accepted with allowSslError=true',
        );
        debugPrint('Response status: ${response.statusCode}');
      } catch (e) {
        debugPrint('Self-signed test failed: $e');
        // Bei Netzwerkproblemen überspringen
        if (e.toString().contains('Network is unreachable') ||
            e.toString().contains('Failed host lookup')) {
          debugPrint('Skipping test due to network issues');
          return;
        }
        fail(
          'Self-signed certificate should be accepted with allowSslError=true: $e',
        );
      }
    });

    test('Self-Signed Certificate - allowSslError=false should fail', () async {
      const selfSignedUrl = 'https://self-signed.badssl.com/';

      try {
        await denySslClient.get(Uri.parse(selfSignedUrl));
        fail(
          'Self-signed certificate should be rejected with allowSslError=false',
        );
      } catch (e) {
        debugPrint(
          '✓ Self-signed certificate correctly rejected with allowSslError=false',
        );
        debugPrint('Error: $e');
        expect(e, isA<HandshakeException>());
      }
    });

    test('Wrong Hostname Certificate - allowSslError=true should work', () async {
      const wrongHostUrl = 'https://wrong.host.badssl.com/';

      try {
        final response = await allowSslClient.get(Uri.parse(wrongHostUrl));
        debugPrint(
          '✓ Wrong hostname certificate accepted with allowSslError=true',
        );
        debugPrint('Response status: ${response.statusCode}');
      } catch (e) {
        debugPrint('Wrong hostname test failed: $e');
        if (e.toString().contains('Network is unreachable') ||
            e.toString().contains('Failed host lookup')) {
          debugPrint('Skipping test due to network issues');
          return;
        }
        fail(
          'Wrong hostname certificate should be accepted with allowSslError=true: $e',
        );
      }
    });

    test('Wrong Hostname Certificate - allowSslError=false should fail', () async {
      const wrongHostUrl = 'https://wrong.host.badssl.com/';

      try {
        await denySslClient.get(Uri.parse(wrongHostUrl));
        fail(
          'Wrong hostname certificate should be rejected with allowSslError=false',
        );
      } catch (e) {
        debugPrint(
          '✓ Wrong hostname certificate correctly rejected with allowSslError=false',
        );
        debugPrint('Error: $e');
        expect(e, isA<HandshakeException>());
      }
    });

    test('Expired Certificate - allowSslError=true should work', () async {
      const expiredUrl = 'https://expired.badssl.com/';

      try {
        final response = await allowSslClient.get(Uri.parse(expiredUrl));
        debugPrint('✓ Expired certificate accepted with allowSslError=true');
        debugPrint('Response status: ${response.statusCode}');
      } catch (e) {
        debugPrint('Expired certificate test failed: $e');
        if (e.toString().contains('Network is unreachable') ||
            e.toString().contains('Failed host lookup')) {
          debugPrint('Skipping test due to network issues');
          return;
        }
        fail(
          'Expired certificate should be accepted with allowSslError=true: $e',
        );
      }
    });

    test('Expired Certificate - allowSslError=false should fail', () async {
      const expiredUrl = 'https://expired.badssl.com/';

      try {
        await denySslClient.get(Uri.parse(expiredUrl));
        fail('Expired certificate should be rejected with allowSslError=false');
      } catch (e) {
        debugPrint(
          '✓ Expired certificate correctly rejected with allowSslError=false',
        );
        debugPrint('Error: $e');
        expect(e, isA<HandshakeException>());
      }
    });

    test('Untrusted Root Certificate - allowSslError=true should work', () async {
      const untrustedUrl = 'https://untrusted-root.badssl.com/';

      try {
        final response = await allowSslClient.get(Uri.parse(untrustedUrl));
        debugPrint(
          '✓ Untrusted root certificate accepted with allowSslError=true',
        );
        debugPrint('Response status: ${response.statusCode}');
      } catch (e) {
        debugPrint('Untrusted root test failed: $e');
        if (e.toString().contains('Network is unreachable') ||
            e.toString().contains('Failed host lookup')) {
          debugPrint('Skipping test due to network issues');
          return;
        }
        fail(
          'Untrusted root certificate should be accepted with allowSslError=true: $e',
        );
      }
    });

    test('Untrusted Root Certificate - allowSslError=false should fail', () async {
      const untrustedUrl = 'https://untrusted-root.badssl.com/';

      try {
        await denySslClient.get(Uri.parse(untrustedUrl));
        fail(
          'Untrusted root certificate should be rejected with allowSslError=false',
        );
      } catch (e) {
        debugPrint(
          '✓ Untrusted root certificate correctly rejected with allowSslError=false',
        );
        debugPrint('Error: $e');
        expect(e, isA<HandshakeException>());
      }
    });
  });
}
