import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:gsd_restapi/src/crypto/client_key_pair.dart';
import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

/// Die Krypto des verschlüsselten Logins (`v2/login`) und verschlüsselter
/// Antworten: AES-256-CBC-PKCS7 und RSA-OAEP-SHA-256 über `pointycastle`.
///
/// Das Wire-Format entspricht `gsd_encryption` 0.1.28 mit `encrypter_plus`.
@internal
abstract final class HandshakeCrypto {
  /// Länge des AES-Schlüssels in Bytes (AES-256).
  static const int aesKeyLength = 32;

  /// Länge des AES-IV in Bytes.
  static const int ivLength = 16;

  /// [length] Bytes aus `Random.secure()`.
  static Uint8List randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => random.nextInt(256)),
    );
  }

  /// Verschlüsselt [plainBytes] mit AES-CBC und PKCS7-Padding.
  static Uint8List aesEncrypt(
    Uint8List plainBytes, {
    required Uint8List key,
    required Uint8List iv,
  }) => _aes(forEncryption: true, key: key, iv: iv).process(plainBytes);

  /// Entschlüsselt [cipherBytes] aus [aesEncrypt].
  static Uint8List aesDecrypt(
    Uint8List cipherBytes, {
    required Uint8List key,
    required Uint8List iv,
  }) => _aes(forEncryption: false, key: key, iv: iv).process(cipherBytes);

  /// Verschlüsselt [plainBytes] (ein Block) mit RSA-OAEP-SHA-256.
  static Uint8List rsaEncrypt(Uint8List plainBytes, RSAPublicKey publicKey) {
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    return cipher.process(plainBytes);
  }

  /// Entschlüsselt [cipherBytes] aus [rsaEncrypt].
  static Uint8List rsaDecrypt(Uint8List cipherBytes, RSAPrivateKey privateKey) {
    final cipher = OAEPEncoding.withSHA256(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    return cipher.process(cipherBytes);
  }

  /// Baut den Body für `POST v2/login` aus dem Klartext [clearBody].
  ///
  /// `{aesKey, data, publicKey}`: Je Login entsteht ein frischer AES-Schlüssel,
  /// der nur im Speicher liegt. `aesKey` ist er, mit RSA für den Schlüssel des
  /// Servers verschlüsselt; `data` ist IV ‖ Ciphertext; `publicKey` ist der
  /// Schlüssel des Clients als PEM ([ClientKeyPair]).
  static Future<String> encryptLoginBody(
    String clearBody, {
    required String serverPublicKeyPem,
  }) async {
    final serverKey = Pem.parsePublicKey(serverPublicKeyPem);
    final clientKeyPair = await ClientKeyPair.obtain();
    final aesKey = randomBytes(aesKeyLength);
    final iv = randomBytes(ivLength);
    final cipherBytes = aesEncrypt(
      Uint8List.fromList(utf8.encode(clearBody)),
      key: aesKey,
      iv: iv,
    );

    return jsonEncode({
      'aesKey': base64Encode(rsaEncrypt(aesKey, serverKey)),
      'data': base64Encode([...iv, ...cipherBytes]),
      'publicKey': clientKeyPair.publicKeyPem,
    });
  }

  static PaddedBlockCipher _aes({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List iv,
  }) =>
      PaddedBlockCipherImpl(PKCS7Padding(), CBCBlockCipher(AESEngine()))..init(
        forEncryption,
        PaddedBlockCipherParameters<CipherParameters, CipherParameters>(
          ParametersWithIV<KeyParameter>(KeyParameter(key), iv),
          null,
        ),
      );
}
