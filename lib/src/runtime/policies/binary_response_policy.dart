import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:meta/meta.dart';

import '../transport_response.dart';
import 'response_policy.dart';

/// Markiert eine [ResponsePolicy], deren Antwort-Bytes NIE über die
/// Response-Entschlüsselung (`ResponseDecryptor`) laufen dürfen.
///
/// Datei- und Preview-Downloads müssen byte-für-byte exakt bleiben; sie sind
/// niemals das JSON- oder `<key>|<data>`-Envelope, das `ResponseDecryptor`
/// erkennt, und ein zufällig zum Envelope-Schema passender Binärinhalt darf
/// nicht versehentlich als "verschlüsselte Antwort" fehlinterpretiert
/// werden. `ApiRuntime` erkennt dieses reine Markerinterface über einen
/// `is BinaryResponsePolicy`-Test und überspringt die Entschlüsselung dafür
/// vollständig - unabhängig vom konkreten Ergebnistyp [T].
@internal
abstract interface class BinaryResponsePolicy<T> implements ResponsePolicy<T> {}

/// Konstruktor-Funktions-Variante von [BinaryResponsePolicy], analog zu
/// `LegacyResponsePolicy` aber für binäre Legacy-Antworttypen (z.B. Datei-
/// oder Preview-Wrapper), deren Bytes exakt erhalten bleiben müssen.
@internal
class BinaryLegacyResponsePolicy<T> implements BinaryResponsePolicy<T> {
  final T Function(http.Response response) construct;

  const BinaryLegacyResponsePolicy(this.construct);

  @override
  T decode(TransportResponse response) => construct(_toHttpResponse(response));
}

/// Liefert die rohen Antwort-Bytes bei HTTP-Status 200, sonst `null`.
///
/// Entspricht dem Legacy-Vertrag nullbarer Datei-/Preview-Downloads: ein
/// Fehlerstatus liefert kein (Teil-)Ergebnis statt fehlerhafter Bytes.
@internal
class NullableBinaryBytesResponsePolicy
    implements BinaryResponsePolicy<Uint8List?> {
  const NullableBinaryBytesResponsePolicy();

  @override
  Uint8List? decode(TransportResponse response) {
    if (response.statusCode != 200) {
      return null;
    }
    return response.bodyBytes;
  }
}

/// Adapter TransportResponse -> http.Response OHNE Envelope-Validierung
/// (siehe `LegacyResponsePolicy`, dieselbe Semantik für binäre Policies).
http.Response _toHttpResponse(TransportResponse response) =>
    http.Response.bytes(
      response.bodyBytes,
      response.statusCode,
      headers: response.headers,
    );
