import 'dart:typed_data';

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/models/gsd_file_download.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Markiert eine [IResponsePolicy], deren Antwort-Bytes NIE über die
/// Response-Entschlüsselung (`ResponseDecryptor`) laufen dürfen.
///
/// Datei- und Preview-Downloads müssen byte-für-byte exakt bleiben; sie sind
/// niemals das JSON- oder `<key>|<data>`-Envelope, das `ResponseDecryptor`
/// erkennt, und ein zufällig zum Envelope-Schema passender Binärinhalt darf
/// nicht versehentlich als "verschlüsselte Antwort" fehlinterpretiert
/// werden. `ApiRuntime` erkennt dieses reine Markerinterface über einen
/// `is IBinaryResponsePolicy`-Test und überspringt die Entschlüsselung dafür
/// vollständig - unabhängig vom konkreten Ergebnistyp [T].
@internal
abstract interface class IBinaryResponsePolicy<T>
    implements IResponsePolicy<T> {}

/// Liefert eine Datei als [GsdFileDownload] mit Bytes und Headern.
///
/// Ein HTTP-Status ungleich 200 wirft [GsdHttpException]; Dateiantworten
/// haben keinen DOCUframe-Umschlag.
@internal
class FileDownloadResponsePolicy
    implements IBinaryResponsePolicy<GsdFileDownload> {
  const FileDownloadResponsePolicy();

  @override
  GsdFileDownload decode(
    TransportResponse response, {
    required String operationId,
  }) {
    if (response.statusCode != 200) {
      throw GsdHttpException(
        'HTTPResponseException: ${response.statusCode} '
        '${response.reasonPhrase ?? ''}',
        response.statusCode,
        reasonPhrase: response.reasonPhrase,
      );
    }
    return GsdFileDownload(
      bytes: response.bodyBytes,
      headers: response.headers,
    );
  }
}

/// Liefert die rohen Antwort-Bytes bei HTTP-Status 200, sonst `null`.
///
/// Entspricht dem Legacy-Vertrag nullbarer Datei-/Preview-Downloads: ein
/// Fehlerstatus liefert kein (Teil-)Ergebnis statt fehlerhafter Bytes.
@internal
class NullableBinaryBytesResponsePolicy
    implements IBinaryResponsePolicy<Uint8List?> {
  const NullableBinaryBytesResponsePolicy();

  @override
  Uint8List? decode(TransportResponse response, {required String operationId}) {
    if (response.statusCode != 200) {
      return null;
    }
    return response.bodyBytes;
  }
}
