// Läuft ab Phase 3 mit `dart test -p chrome`; `flutter test` überspringt ihn.
@TestOn('browser')
library;

import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:gsd_restapi/src/crypto/rsa_key_generator.dart';
import 'package:test/test.dart';

void main() {
  test(
    'das im Browser erzeugte Paar ver- und entschlüsselt mit pointycastle',
    () async {
      final pair = await RsaKeyGenerator.generate();

      expect(pair.publicKey.modulus!.bitLength, 2048);
      expect(pair.publicKey.exponent, BigInt.from(65537));
      final plainBytes = HandshakeCrypto.randomBytes(32);
      expect(
        HandshakeCrypto.rsaDecrypt(
          HandshakeCrypto.rsaEncrypt(plainBytes, pair.publicKey),
          pair.privateKey,
        ),
        plainBytes,
      );
      final trimmedPem = Pem.encodePublicKey(
        pair.publicKey,
      ).split('\n').map((line) => line.trim()).join('\n');
      expect(Pem.parsePublicKey(trimmedPem).modulus, pair.publicKey.modulus);
    },
  );
}
