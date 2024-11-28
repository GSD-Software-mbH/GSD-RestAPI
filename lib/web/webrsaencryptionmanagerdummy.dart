import 'package:pointycastle/export.dart';

class WebRSAEncryptionManager {
  // Schlüssel generieren
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generateRSAKeys({int bitLength = 2048}) async {   
    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
          RSAPublicKey(BigInt.one, BigInt.one), RSAPrivateKey(BigInt.one, BigInt.one, null, null));
  }
}