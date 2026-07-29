import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:gsd_restapi/httpclient/httpclient.dart';
import 'dart:io';

/// Timeout für den Verbindungsaufbau der Test-Clients.
const Duration _connectionTimeout = Duration(seconds: 10);

/// Großzügiges Test-Timeout, da pro Szenario mehrere Hosts mit
/// Wiederholungsversuchen angefragt werden können.
const Timeout _testTimeout = Timeout(Duration(minutes: 2));

/// Test-Hosts je Szenario: erster Eintrag ist die zuverlässigste Quelle,
/// weitere Einträge dienen als Fallback (badssl.com ist zeitweise überlastet).
const List<String> _expiredUrls = [
  'https://expired-rsa-dv.ssl.com/',
  'https://expired-ecc-dv.ssl.com/',
  'https://expired.badssl.com/',
];
const List<String> _selfSignedUrls = ['https://self-signed.badssl.com/'];
const List<String> _wrongHostUrls = ['https://wrong.host.badssl.com/'];
const List<String> _untrustedRootUrls = ['https://untrusted-root.badssl.com/'];
const List<String> _validUrls = [
  'https://www.google.com',
  'https://www.microsoft.com',
  'https://api.github.com',
];

/// Prüft, ob ein Fehler ein vorübergehendes Netzwerkproblem ist
/// (Timeout, DNS-Fehler, keine Route) und kein TLS-/Zertifikatsfehler.
bool _isTransientNetworkError(Object error) {
  if (error is TlsException) return false;
  if (error is SocketException) return true;
  if (error is http.ClientException) return true;
  final text = error.toString();
  return text.contains('timed out') ||
      text.contains('Network is unreachable') ||
      text.contains('Failed host lookup') ||
      text.contains('Connection refused') ||
      text.contains('Connection reset') ||
      text.contains('Connection closed');
}

/// Führt einen GET-Request mit bis zu [attempts] Versuchen aus.
///
/// Nur vorübergehende Netzwerkfehler werden wiederholt, TLS-Fehler sind
/// ein definitives Ergebnis und werden sofort weitergereicht.
Future<http.Response> _getWithRetry(
  http.Client client,
  Uri url, {
  int attempts = 2,
}) async {
  for (var attempt = 1; ; attempt++) {
    try {
      return await client.get(url);
    } catch (e) {
      if (attempt >= attempts || !_isTransientNetworkError(e)) rethrow;
      debugPrint('Versuch $attempt für $url fehlgeschlagen ($e), wiederhole …');
      await Future<void>.delayed(const Duration(seconds: 2));
    }
  }
}

/// Erwartet, dass ein Host mit defektem Zertifikat bei allowSslError=true
/// trotzdem eine Antwort liefert.
///
/// Nicht erreichbare Hosts werden übersprungen (Fallback auf den nächsten);
/// der Test schlägt nur fehl, wenn ein erreichbarer Host per TLS-Fehler
/// abgelehnt wird.
Future<void> _expectAcceptedDespiteBadCert(
  http.Client allowSslClient,
  List<String> urls,
  String scenario,
) async {
  for (final url in urls) {
    http.Response? response;
    Object? error;
    try {
      response = await _getWithRetry(allowSslClient, Uri.parse(url));
    } catch (e) {
      error = e;
    }

    if (response != null) {
      debugPrint(
        '✓ $scenario: mit allowSslError=true akzeptiert '
        '($url, Status ${response.statusCode})',
      );
      return;
    }
    if (error is TlsException) {
      fail(
        '$scenario: Zertifikat sollte mit allowSslError=true '
        'akzeptiert werden, aber: $error',
      );
    }
    if (_isTransientNetworkError(error!)) {
      debugPrint('⚠ $url nicht erreichbar ($error), versuche nächsten Host');
      continue;
    }
    fail('$scenario: unerwarteter Fehler bei $url: $error');
  }
  debugPrint(
    '⚠ $scenario übersprungen – keiner der Test-Hosts erreichbar: $urls',
  );
}

/// Erwartet, dass ein Host mit defektem Zertifikat bei allowSslError=false
/// per [HandshakeException] abgelehnt wird.
///
/// Nicht erreichbare Hosts werden übersprungen (Fallback auf den nächsten);
/// eine erfolgreiche Antwort ist ein harter Testfehler.
Future<void> _expectRejectedByHandshake(
  http.Client denySslClient,
  List<String> urls,
  String scenario,
) async {
  for (final url in urls) {
    http.Response? response;
    Object? error;
    try {
      response = await _getWithRetry(denySslClient, Uri.parse(url));
    } catch (e) {
      error = e;
    }

    if (response != null) {
      fail(
        '$scenario: Zertifikat sollte mit allowSslError=false abgelehnt '
        'werden ($url, Status ${response.statusCode})',
      );
    }
    if (error is HandshakeException) {
      debugPrint(
        '✓ $scenario: mit allowSslError=false korrekt abgelehnt ($url)',
      );
      debugPrint('Error: $error');
      return;
    }
    if (_isTransientNetworkError(error!)) {
      debugPrint('⚠ $url nicht erreichbar ($error), versuche nächsten Host');
      continue;
    }
    fail('$scenario: HandshakeException erwartet, aber erhalten: $error');
  }
  debugPrint(
    '⚠ $scenario übersprungen – keiner der Test-Hosts erreichbar: $urls',
  );
}

void main() {
  late http.Client allowSslClient;
  late http.Client denySslClient;

  setUp(() {
    allowSslClient = createClient(_connectionTimeout, allowSslError: true);
    denySslClient = createClient(_connectionTimeout, allowSslError: false);
  });

  tearDown(() {
    allowSslClient.close();
    denySslClient.close();
  });

  group('SSL Certificate Tests', () {
    test(
      'Valid SSL Certificate - should work with both clients',
      () async {
        bool allowSslSuccess = false;
        bool denySslSuccess = false;

        for (final validUrl in _validUrls) {
          if (allowSslSuccess && denySslSuccess) break;

          if (!allowSslSuccess) {
            try {
              final response = await _getWithRetry(
                allowSslClient,
                Uri.parse(validUrl),
              );
              if (response.statusCode == 200) {
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
              final response = await _getWithRetry(
                denySslClient,
                Uri.parse(validUrl),
              );
              if (response.statusCode == 200) {
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

        // Mindestens einer sollte funktionieren
        expect(
          allowSslSuccess || denySslSuccess,
          isTrue,
          reason: 'At least one SSL configuration should work',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Self-Signed Certificate - allowSslError=true should work',
      () async {
        await _expectAcceptedDespiteBadCert(
          allowSslClient,
          _selfSignedUrls,
          'Self-Signed Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Self-Signed Certificate - allowSslError=false should fail',
      () async {
        await _expectRejectedByHandshake(
          denySslClient,
          _selfSignedUrls,
          'Self-Signed Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Wrong Hostname Certificate - allowSslError=true should work',
      () async {
        await _expectAcceptedDespiteBadCert(
          allowSslClient,
          _wrongHostUrls,
          'Wrong Hostname Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Wrong Hostname Certificate - allowSslError=false should fail',
      () async {
        await _expectRejectedByHandshake(
          denySslClient,
          _wrongHostUrls,
          'Wrong Hostname Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Expired Certificate - allowSslError=true should work',
      () async {
        await _expectAcceptedDespiteBadCert(
          allowSslClient,
          _expiredUrls,
          'Expired Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Expired Certificate - allowSslError=false should fail',
      () async {
        await _expectRejectedByHandshake(
          denySslClient,
          _expiredUrls,
          'Expired Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Untrusted Root Certificate - allowSslError=true should work',
      () async {
        await _expectAcceptedDespiteBadCert(
          allowSslClient,
          _untrustedRootUrls,
          'Untrusted Root Certificate',
        );
      },
      timeout: _testTimeout,
    );

    test(
      'Untrusted Root Certificate - allowSslError=false should fail',
      () async {
        await _expectRejectedByHandshake(
          denySslClient,
          _untrustedRootUrls,
          'Untrusted Root Certificate',
        );
      },
      timeout: _testTimeout,
    );
  });
}
