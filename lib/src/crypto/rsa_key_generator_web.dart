import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';
import 'package:web/web.dart' as web;

/// Erzeugt das RSA-Schlüsselpaar des Clients im Browser über die Web Crypto
/// API.
@internal
abstract final class RsaKeyGenerator {
  /// Erzeugt ein RSA-OAEP-Schlüsselpaar (SHA-256, Exponent 65537) und
  /// übernimmt es über den JWK-Export in `pointycastle`-Schlüssel.
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generate({
    int bitLength = 2048,
  }) async {
    final subtle = web.window.crypto.subtle;
    final keyPair =
        (await subtle
                .generateKey(
                  _RsaHashedKeyGenParams(
                    name: 'RSA-OAEP',
                    modulusLength: bitLength,
                    publicExponent: Uint8List.fromList([1, 0, 1]).toJS,
                    hash: 'SHA-256',
                  ),
                  true,
                  ['encrypt'.toJS, 'decrypt'.toJS].toJS,
                )
                .toDart)!
            as _CryptoKeyPair;
    final jwk =
        (await subtle.exportKey('jwk', keyPair.privateKey).toDart)!
            as web.JsonWebKey;

    final modulus = _bigInt(jwk.n);
    return AsymmetricKeyPair(
      RSAPublicKey(modulus, _bigInt(jwk.e)),
      RSAPrivateKey(modulus, _bigInt(jwk.d), _bigInt(jwk.p), _bigInt(jwk.q)),
    );
  }

  static BigInt _bigInt(String base64UrlValue) {
    final bytes = base64Url.decode(base64Url.normalize(base64UrlValue));
    if (bytes.isEmpty) return BigInt.zero;
    final hex = bytes
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
    return BigInt.parse(hex, radix: 16);
  }
}

extension type _RsaHashedKeyGenParams._(JSObject _) implements JSObject {
  external factory _RsaHashedKeyGenParams({
    String name,
    int modulusLength,
    JSUint8Array publicExponent,
    String hash,
  });
}

extension type _CryptoKeyPair._(JSObject _) implements JSObject {
  external web.CryptoKey get privateKey;
}
