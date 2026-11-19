import 'package:gsd_restapi/src/crypto/pem.dart';
import 'package:gsd_restapi/src/crypto/rsa_key_generator.dart';
import 'package:meta/meta.dart';
import 'package:pointycastle/export.dart';

/// Das RSA-Schlüsselpaar (2048 Bit), mit dem der Client sich beim Login
/// ausweist.
///
/// Es gibt eines je Isolate: beim ersten Login erzeugt und von allen Clients
/// geteilt. Der Server verschlüsselt Antworten mit dem öffentlichen Schlüssel
/// des Logins; ein Client, der im selben Prozess eine Session übernimmt, muss
/// sie lesen können. Das Paar liegt nur im Speicher.
@internal
final class ClientKeyPair {
  ClientKeyPair(this.publicKey, this.privateKey)
    : publicKeyPem = Pem.encodePublicKey(publicKey);

  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;

  /// [publicKey] in der Form, die der Login-Body mitschickt.
  final String publicKeyPem;

  static Future<ClientKeyPair>? _shared;

  /// Liefert das Paar dieses Isolates und erzeugt es beim ersten Aufruf.
  ///
  /// Gleichzeitige Aufrufe warten auf dieselbe Erzeugung. Schlägt sie fehl,
  /// versucht der nächste Aufruf es erneut.
  static Future<ClientKeyPair> obtain() async {
    final pending = _shared ??= _generate();
    try {
      return await pending;
    } catch (_) {
      if (identical(_shared, pending)) _shared = null;
      rethrow;
    }
  }

  static Future<ClientKeyPair> _generate() async {
    final pair = await RsaKeyGenerator.generate();
    return ClientKeyPair(pair.publicKey, pair.privateKey);
  }
}
