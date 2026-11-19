import 'dart:math';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

/// Erzeugt das RSA-Schlüsselpaar des Clients auf der VM mit `pointycastle`.
@internal
abstract final class RsaKeyGenerator {
  /// Erzeugt ein Schlüsselpaar mit Exponent 65537.
  ///
  /// `FortunaRandom` bekommt einen Seed von 32 Bytes aus `Random.secure()`.
  static Future<AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>> generate({
    int bitLength = 2048,
  }) async {
    final seedSource = Random.secure();
    final random = FortunaRandom()
      ..seed(
        KeyParameter(
          Uint8List.fromList(
            List<int>.generate(32, (_) => seedSource.nextInt(256)),
          ),
        ),
      );

    final generator = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(BigInt.from(65537), bitLength, 64),
          random,
        ),
      );

    return generator.generateKeyPair();
  }
}
