import 'dart:convert';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

/// PEM-Kodierung öffentlicher RSA-Schlüssel (SPKI) für den Login-Handshake.
///
/// Beide Richtungen bilden `gsd_encryption` 0.1.28 Zeichen für Zeichen nach,
/// weil der Server genau diese Form kennt.
@internal
abstract final class Pem {
  /// Kodiert [publicKey] wie `RSAPublicKey.encodeToPem()` aus
  /// `gsd_encryption` 0.1.28.
  ///
  /// Kopf, Fuß und die erste Base64-Zeile tragen vier Leerzeichen Einrückung,
  /// die Base64-Zeilen trennt CRLF, am Ende stehen ein Zeilenumbruch und
  /// vier Leerzeichen. Ob der Server sauberes PEM annimmt, ist ungeprüft.
  static String encodePublicKey(RSAPublicKey publicKey) {
    final keySequence = ASN1Sequence()
      ..add(ASN1Integer(publicKey.modulus))
      ..add(ASN1Integer(publicKey.exponent));
    final algorithm = ASN1Sequence()
      ..add(ASN1ObjectIdentifier.fromName('rsaEncryption'))
      ..add(ASN1Null());
    final spki = ASN1Sequence()
      ..add(algorithm)
      ..add(ASN1BitString(stringValues: keySequence.encode()));

    final base64Key = base64Encode(spki.encode());
    final lines = RegExp(
      '.{1,64}',
    ).allMatches(base64Key).map((match) => match.group(0)).join('\r\n');

    return '    -----BEGIN PUBLIC KEY-----\n'
        '    $lines\n'
        '    -----END PUBLIC KEY-----\n'
        '    ';
  }

  /// Liest einen öffentlichen RSA-Schlüssel (SPKI) wie
  /// `String.parsePublicKeyFromPem()` aus `gsd_encryption` 0.1.28: Leere
  /// Zeilen und Zeilen, die mit `---` beginnen, fallen weg, danach jeder
  /// Leerraum.
  static RSAPublicKey parsePublicKey(String pem) {
    final base64Key = pem
        .split('\n')
        .where((line) => line.isNotEmpty && !line.startsWith('---'))
        .join()
        .replaceAll(RegExp(r'\s'), '');

    final spki =
        ASN1Parser(base64.decode(base64Key)).nextObject() as ASN1Sequence;
    final keyBits = spki.elements![1] as ASN1BitString;
    final keySequence =
        ASN1Parser(Uint8List.fromList(keyBits.stringValues!)).nextObject()
            as ASN1Sequence;

    return RSAPublicKey(
      _unsigned(keySequence.elements![0] as ASN1Integer),
      _unsigned(keySequence.elements![1] as ASN1Integer),
    );
  }

  static BigInt _unsigned(ASN1Integer integer) {
    final hex = integer.valueBytes!
        .map((byte) => byte.toRadixString(16).padLeft(2, '0'))
        .join();
    return BigInt.parse(hex, radix: 16);
  }
}
