import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Die Testvektoren aus `gsd_encryption` 0.1.28
/// (`test/fixtures/crypto/README.md`).
abstract final class CryptoVectors {
  static final Map<String, dynamic> _json =
      jsonDecode(
            File(
              'test/fixtures/crypto/gsd_encryption_vectors.json',
            ).readAsStringSync(),
          )
          as Map<String, dynamic>;

  static Map<String, dynamic> get aes => _section('aes');
  static Map<String, dynamic> get rsa => _section('rsa');
  static Map<String, dynamic> get encryptedResponse =>
      _section('encryptedResponse');
  static Map<String, dynamic> get pem => _section('pem');

  static RSAPublicKey get clientPublicKey => _publicKey('clientKeyPair');
  static RSAPrivateKey get clientPrivateKey => _privateKey('clientKeyPair');
  static RSAPublicKey get serverPublicKey => _publicKey('serverKeyPair');
  static RSAPrivateKey get serverPrivateKey => _privateKey('serverKeyPair');

  /// Der Base64-Wert [key] aus [section] als Bytes.
  static Uint8List bytes(Map<String, dynamic> section, String key) =>
      base64Decode(section[key] as String);

  static Map<String, dynamic> _section(String name) =>
      _json[name] as Map<String, dynamic>;

  static RSAPublicKey _publicKey(String pair) {
    final values = _section(pair);
    return RSAPublicKey(
      BigInt.parse(values['modulus'] as String),
      BigInt.parse(values['publicExponent'] as String),
    );
  }

  static RSAPrivateKey _privateKey(String pair) {
    final values = _section(pair);
    return RSAPrivateKey(
      BigInt.parse(values['modulus'] as String),
      BigInt.parse(values['privateExponent'] as String),
      BigInt.parse(values['p'] as String),
      BigInt.parse(values['q'] as String),
    );
  }
}
