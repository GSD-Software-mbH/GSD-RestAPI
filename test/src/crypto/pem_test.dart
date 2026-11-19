@TestOn('vm')
library;

import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:test/test.dart';

import 'crypto_vectors.dart';

void main() {
  group('Pem.encodePublicKey', () {
    test('ist byte-gleich zu encodeToPem() aus gsd_encryption 0.1.28', () {
      expect(
        Pem.encodePublicKey(CryptoVectors.clientPublicKey),
        CryptoVectors.pem['clientPublicKeyEncoded'],
      );
    });

    test('rückt Kopf, Fuß und erste Zeile ein und trennt mit CRLF', () {
      final pem = Pem.encodePublicKey(CryptoVectors.clientPublicKey);

      expect(pem, startsWith('    -----BEGIN PUBLIC KEY-----\n    MII'));
      expect(pem, endsWith('\n    -----END PUBLIC KEY-----\n    '));
      expect('\r\n'.allMatches(pem), isNotEmpty);
    });
  });

  group('Pem.parsePublicKey', () {
    test('liest ein sauberes Server-PEM', () {
      final key = Pem.parsePublicKey(
        CryptoVectors.pem['serverPublicKeyClean'] as String,
      );

      expect(key.modulus, CryptoVectors.serverPublicKey.modulus);
      expect(key.exponent, CryptoVectors.serverPublicKey.exponent);
    });

    test('liest das eingerückte Client-PEM nach dem Trimmen der Zeilen', () {
      final trimmed = (CryptoVectors.pem['clientPublicKeyEncoded'] as String)
          .split('\n')
          .map((line) => line.trim())
          .join('\n');

      final key = Pem.parsePublicKey(trimmed);

      expect(key.modulus, CryptoVectors.clientPublicKey.modulus);
      expect(key.exponent, CryptoVectors.clientPublicKey.exponent);
    });

    test('verwirft wie gsd_encryption nur Zeilen, die mit --- beginnen', () {
      expect(
        () => Pem.parsePublicKey(
          CryptoVectors.pem['clientPublicKeyEncoded'] as String,
        ),
        throwsFormatException,
      );
    });
  });
}
