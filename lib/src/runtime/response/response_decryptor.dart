import 'dart:convert';
import 'dart:typed_data';

import 'package:encrypter_plus/encrypter_plus.dart' as encrypt_plus;
import 'package:gsd_encryption/gsd_encryption.dart';
import 'package:meta/meta.dart';

import '../transport_response.dart';

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

      final manager = EncryptionManager();
      final aesKeyBytes = await manager.decryptRSA(base64Decode(parts[0]));
      final aesKey = encrypt_plus.Key.fromBase64(base64Encode(aesKeyBytes));
      final encryptedBody = base64Decode(parts[1]);
      if (encryptedBody.length < 16) {
        throw const FormatException(
          'Encrypted response body is shorter than its 16-byte IV.',
        );
      }

      final clearBody = await manager.decryptAES(
        jsonEncode(<String, String>{
          'iv': base64Encode(encryptedBody.sublist(0, 16)),
          'data': base64Encode(encryptedBody.sublist(16)),
        }),
        key: aesKey,
        padding: 'PKCS7',
      );

      return TransportResponse(
        statusCode: response.statusCode,
        headers: response.headers,
        bodyBytes: Uint8List.fromList(utf8.encode(clearBody)),
        body: clearBody,
      );
    }
  }
}
