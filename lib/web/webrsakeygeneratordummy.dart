import 'package:js/js.dart';
import 'package:pointycastle/export.dart';

// Zugriff auf `window.crypto.subtle` in JavaScript
@JS('window.crypto.subtle')
external dynamic get subtle;

class WebRSAKeyGenerator {
  // Schlüssel generieren
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRSAKeys({int bitLength = 2048}) async {   
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
          RSAPublicKey(BigInt.one, BigInt.one), RSAPrivateKey(BigInt.one, BigInt.one, null, null));
  }
}