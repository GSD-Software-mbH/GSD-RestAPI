@TestOn('vm')
library;

import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/crypto/rsa_key_generator.dart';
import 'package:test/test.dart';

void main() {
  group('RsaKeyGenerator (VM)', () {
    test('erzeugt ein Paar der verlangten Länge mit Exponent 65537', () async {
      final pair = await RsaKeyGenerator.generate(bitLength: 1024);

      expect(pair.publicKey.modulus!.bitLength, 1024);
      expect(pair.publicKey.exponent, BigInt.from(65537));
      expect(pair.privateKey.modulus, pair.publicKey.modulus);
      final plainBytes = HandshakeCrypto.randomBytes(16);
      expect(
        HandshakeCrypto.rsaDecrypt(
          HandshakeCrypto.rsaEncrypt(plainBytes, pair.publicKey),
          pair.privateKey,
        ),
        plainBytes,
      );
    });

    test('erzeugt bei jedem Aufruf ein anderes Paar', () async {
      final first = await RsaKeyGenerator.generate(bitLength: 1024);
      final second = await RsaKeyGenerator.generate(bitLength: 1024);

      expect(first.publicKey.modulus, isNot(second.publicKey.modulus));
    });
  });
}
