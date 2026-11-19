@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/runtime/response/response_decryptor.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:test/test.dart';

import '../../crypto/crypto_vectors.dart';

const _decryptor = ResponseDecryptor();

TransportResponse _response(String body, {int statusCode = 200}) {
  return TransportResponse(
    statusCode: statusCode,
    headers: const {'content-type': 'text/plain', 'x-trace': '1'},
    bodyBytes: Uint8List.fromList(utf8.encode(body)),
    body: body,
    reasonPhrase: 'Reason',
  );
}

/// Der RSA-Teil `aesKey` für das Schlüsselpaar dieses Isolates, das
/// `ResponseDecryptor` über `ClientKeyPair.obtain()` holt.
Future<String> _encryptedKeyForThisIsolate(Uint8List aesKey) async {
  final keyPair = await ClientKeyPair.obtain();
  return base64Encode(HandshakeCrypto.rsaEncrypt(aesKey, keyPair.publicKey));
}

void main() {
  group('ResponseDecryptor: reicht durch', () {
    final bodies = <String, String>{
      'JSON-Objekt': '{"status":{"internalStatus":"0"}}',
      'JSON-Array': '[1, 2]',
      'JSON-String mit einem |': '"a|b"',
      'leerer Body': '',
      'Klartext ohne |': 'kein JSON',
      'mehr als ein |': 'a|b|c',
      'leerer Teil vor dem |': '|YWJj',
      'leerer Teil nach dem |': 'YWJj|',
    };
    for (final MapEntry(key: name, value: body) in bodies.entries) {
      test(name, () async {
        final response = _response(body);

        expect(await _decryptor.decryptIfNeeded(response), same(response));
      });
    }
  });

  group('ResponseDecryptor: entschlüsselt', () {
    test('die alte Antwort aus gsd_encryption', () async {
      // Der Vektor ist an `clientKeyPair` verschlüsselt, der Decryptor nimmt
      // das Schlüsselpaar des Isolates: Nur den RSA-Teil umschlüsseln, IV und
      // AES-Ciphertext bleiben byte-gleich.
      final vector = CryptoVectors.encryptedResponse;
      final parts = (vector['body'] as String).split('|');
      final aesKey = HandshakeCrypto.rsaDecrypt(
        base64Decode(parts[0]),
        CryptoVectors.clientPrivateKey,
      );
      final body = '${await _encryptedKeyForThisIsolate(aesKey)}|${parts[1]}';

      final decrypted = await _decryptor.decryptIfNeeded(
        _response(body, statusCode: 500),
      );

      final clearBody = vector['clearBody'] as String;
      expect(decrypted.body, clearBody);
      expect(decrypted.bodyBytes, utf8.encode(clearBody));
      expect(decrypted.statusCode, 500);
      expect(decrypted.headers, {'content-type': 'text/plain', 'x-trace': '1'});
      expect(decrypted.reasonPhrase, 'Reason');
    });
  });

  group('ResponseDecryptor: Fehler', () {
    test('IV kürzer als 16 Bytes wirft FormatException', () async {
      final aesKey = HandshakeCrypto.randomBytes(HandshakeCrypto.aesKeyLength);
      final body =
          '${await _encryptedKeyForThisIsolate(aesKey)}|'
          '${base64Encode(Uint8List(HandshakeCrypto.ivLength - 1))}';

      await expectLater(
        _decryptor.decryptIfNeeded(_response(body)),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            contains('16-byte IV'),
          ),
        ),
      );
    });

    test('an einen anderen Schlüssel verschlüsselt: ArgumentError aus '
        'RSA-OAEP', () async {
      // Unverändert ist der Vektor an `clientKeyPair` verschlüsselt, nicht an
      // das Schlüsselpaar dieses Isolates.
      final body = CryptoVectors.encryptedResponse['body'] as String;

      await expectLater(
        _decryptor.decryptIfNeeded(_response(body)),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'decoding error',
          ),
        ),
      );
    });

    // Müll mit genau einem `|` gilt als Wire-Format. Der Decryptor bildet die
    // Fehler nicht ab: Ungültiges Base64 kommt als rohe FormatException aus
    // `base64Decode`, gültiges Base64 als ArgumentError aus RSA-OAEP.
    test('Müll mit einem | wirft die rohe FormatException von '
        'base64Decode', () async {
      await expectLater(
        _decryptor.decryptIfNeeded(
          _response('<html>Bad Gateway | nginx</html>', statusCode: 502),
        ),
        throwsA(
          isA<FormatException>().having(
            (e) => e.message,
            'message',
            'Invalid character',
          ),
        ),
      );
    });

    test('Base64-Müll mit einem | wirft ArgumentError aus RSA-OAEP', () async {
      await expectLater(
        _decryptor.decryptIfNeeded(_response('YWJj|ZGVm')),
        throwsA(
          isA<ArgumentError>().having(
            (e) => e.message,
            'message',
            'decryption error',
          ),
        ),
      );
    });
  });
}
