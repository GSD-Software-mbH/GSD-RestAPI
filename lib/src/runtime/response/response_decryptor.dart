import 'dart:convert';
import 'dart:typed_data';

import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/handshake_crypto.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Normalisiert verschlüsselte DOCUframe-Antworten vor dem fachlichen
/// Response-Parsing.
///
/// Gültiges JSON wird unverändert durchgereicht. Das Legacy-Wire-Format
/// `<RSA-verschlüsselter AES-Key>|<IV plus AES-Ciphertext>` wird dagegen mit
/// dem beim Login erzeugten Client-Schlüssel entschlüsselt.
@internal
final class ResponseDecryptor {
  const ResponseDecryptor();

  Future<TransportResponse> decryptIfNeeded(TransportResponse response) async {
    try {
      jsonDecode(response.body);
      return response;
    } on FormatException {
      final parts = response.body.split('|');
      if (parts.length != 2 || parts.any((part) => part.isEmpty)) {
        return response;
      }

      final keyPair = await ClientKeyPair.obtain();
      final aesKey = HandshakeCrypto.rsaDecrypt(
        base64Decode(parts[0]),
        keyPair.privateKey,
      );
      final encryptedBody = base64Decode(parts[1]);
      if (encryptedBody.length < HandshakeCrypto.ivLength) {
        throw const FormatException(
          'Encrypted response body is shorter than its 16-byte IV.',
        );
      }

      final clearBody = utf8.decode(
        HandshakeCrypto.aesDecrypt(
          encryptedBody.sublist(HandshakeCrypto.ivLength),
          key: aesKey,
          iv: encryptedBody.sublist(0, HandshakeCrypto.ivLength),
        ),
      );

      return TransportResponse(
        statusCode: response.statusCode,
        headers: response.headers,
        bodyBytes: Uint8List.fromList(utf8.encode(clearBody)),
        body: clearBody,
        reasonPhrase: response.reasonPhrase,
      );
    }
  }
}
