@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:test/test.dart';

import 'crypto_vectors.dart';

void main() {
  group('HandshakeCrypto AES', () {
    final vector = CryptoVectors.aes;
    final key = CryptoVectors.bytes(vector, 'key');
    final iv = CryptoVectors.bytes(vector, 'iv');

    test('ist mit festem Schlüssel und IV byte-gleich zu gsd_encryption', () {
      final cipherBytes = HandshakeCrypto.aesEncrypt(
        Uint8List.fromList(utf8.encode(vector['plainText'] as String)),
        key: key,
        iv: iv,
      );

      expect(base64Encode(cipherBytes), vector['cipherText']);
    });

    test('entschlüsselt das alte Chiffrat', () {
      final plainBytes = HandshakeCrypto.aesDecrypt(
        CryptoVectors.bytes(vector, 'cipherText'),
        key: key,
        iv: iv,
      );

      expect(utf8.decode(plainBytes), vector['plainText']);
    });
  });

  group('HandshakeCrypto RSA', () {
    test('entschlüsselt das alte OAEP-SHA-256-Chiffrat', () {
      final vector = CryptoVectors.rsa;

      final plainBytes = HandshakeCrypto.rsaDecrypt(
        CryptoVectors.bytes(vector, 'cipherText'),
        CryptoVectors.clientPrivateKey,
      );

      expect(plainBytes, CryptoVectors.bytes(vector, 'plainBytes'));
    });

    test('ver- und entschlüsselt im Roundtrip', () {
      final plainBytes = HandshakeCrypto.randomBytes(32);

      final cipherBytes = HandshakeCrypto.rsaEncrypt(
        plainBytes,
        CryptoVectors.serverPublicKey,
      );

      expect(cipherBytes, hasLength(256));
      expect(
        HandshakeCrypto.rsaDecrypt(cipherBytes, CryptoVectors.serverPrivateKey),
        plainBytes,
      );
    });
  });

  test(
    'randomBytes liefert die verlangte Länge und jedes Mal andere Bytes',
    () {
      final first = HandshakeCrypto.randomBytes(HandshakeCrypto.aesKeyLength);
      final second = HandshakeCrypto.randomBytes(HandshakeCrypto.aesKeyLength);

      expect(first, hasLength(32));
      expect(second, hasLength(32));
      expect(first, isNot(equals(second)));
    },
  );

  group('HandshakeCrypto.encryptLoginBody', () {
    final serverPem = CryptoVectors.pem['serverPublicKeyClean'] as String;

    Map<String, dynamic> decode(String body) =>
        jsonDecode(body) as Map<String, dynamic>;

    Uint8List serverAesKey(Map<String, dynamic> body) =>
        HandshakeCrypto.rsaDecrypt(
          base64Decode(body['aesKey'] as String),
          CryptoVectors.serverPrivateKey,
        );

    test(
      'der Server entschlüsselt den Klartext mit seinem Schlüssel',
      () async {
        const clearBody = '{"user":"demo","pass":"md5","appNames":["Ä"]}';

        final body = decode(
          await HandshakeCrypto.encryptLoginBody(
            clearBody,
            serverPublicKeyPem: serverPem,
          ),
        );

        expect(body.keys, unorderedEquals(['aesKey', 'data', 'publicKey']));
        final aesKey = serverAesKey(body);
        expect(aesKey, hasLength(HandshakeCrypto.aesKeyLength));
        final data = base64Decode(body['data'] as String);
        final decrypted = HandshakeCrypto.aesDecrypt(
          data.sublist(HandshakeCrypto.ivLength),
          key: aesKey,
          iv: data.sublist(0, HandshakeCrypto.ivLength),
        );
        expect(utf8.decode(decrypted), clearBody);
        expect(body['publicKey'], (await ClientKeyPair.obtain()).publicKeyPem);
      },
    );

    test('nutzt je Aufruf einen neuen AES-Schlüssel und IV, aber dasselbe '
        'Schlüsselpaar', () async {
      final first = decode(
        await HandshakeCrypto.encryptLoginBody(
          '{}',
          serverPublicKeyPem: serverPem,
        ),
      );
      final second = decode(
        await HandshakeCrypto.encryptLoginBody(
          '{}',
          serverPublicKeyPem: serverPem,
        ),
      );

      expect(serverAesKey(first), isNot(equals(serverAesKey(second))));
      expect(
        base64Decode(first['data'] as String).sublist(0, 16),
        isNot(equals(base64Decode(second['data'] as String).sublist(0, 16))),
      );
      expect(first['publicKey'], second['publicKey']);
    });
  });
}
