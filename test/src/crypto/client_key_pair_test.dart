import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:test/test.dart';

void main() {
  group('ClientKeyPair.obtain', () {
    test('liefert im Isolate immer dasselbe Paar, auch gleichzeitig', () async {
      final concurrent = await Future.wait([
        ClientKeyPair.obtain(),
        ClientKeyPair.obtain(),
      ]);
      final later = await ClientKeyPair.obtain();

      expect(identical(concurrent[0], concurrent[1]), isTrue);
      expect(identical(concurrent[0], later), isTrue);
    });

    test(
      'erzeugt ein funktionierendes 2048-Bit-Paar mit Exponent 65537',
      () async {
        final keyPair = await ClientKeyPair.obtain();

        expect(keyPair.publicKey.modulus!.bitLength, 2048);
        expect(keyPair.publicKey.exponent, BigInt.from(65537));
        final plainBytes = HandshakeCrypto.randomBytes(32);
        expect(
          HandshakeCrypto.rsaDecrypt(
            HandshakeCrypto.rsaEncrypt(plainBytes, keyPair.publicKey),
            keyPair.privateKey,
          ),
          plainBytes,
        );
      },
    );

    test(
      'hält den öffentlichen Schlüssel in der PEM-Form des Logins',
      () async {
        final keyPair = await ClientKeyPair.obtain();

        expect(keyPair.publicKeyPem, Pem.encodePublicKey(keyPair.publicKey));
      },
    );
  });
}
