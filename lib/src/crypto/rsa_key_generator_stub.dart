import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

/// Platzhalter für Plattformen ohne `dart.library.io` und ohne
/// `dart.library.js_interop`.
@internal
abstract final class RsaKeyGenerator {
  /// Wirft immer: Auf dieser Plattform gibt es keine Schlüsselerzeugung.
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generate({
    int bitLength = 2048,
  }) {
    throw UnsupportedError('RSA key generation is not supported here.');
  }
}
