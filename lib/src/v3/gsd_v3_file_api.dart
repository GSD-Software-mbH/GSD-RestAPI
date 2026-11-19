import 'dart:async';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_file_download.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/binary_response_policy.dart';
import 'package:meta/meta.dart';

/// Native V3-Dateioperationen.
class GsdV3FileApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV3FileApi.internal(this._runtime);
  static const FileDownloadResponsePolicy _fileResponsePolicy =
      FileDownloadResponsePolicy();

  final ApiRuntime _runtime;

  /// Lädt eine Datei über `GET v3/file/{oid}` herunter.
  ///
  /// [oid] adressiert die Datei. Bei E-Mail-Anhängen kann wahlweise die OID
  /// des Abschnitts oder die OID des Anhangs verwendet werden.
  ///
  /// Alle Zusatzparameter sind optional und werden NUR dann als
  /// Query-Parameter gesendet, wenn sie explizit gesetzt sind. Ohne Angabe
  /// bleibt die URL exakt `v3/file/{oid}`.
  ///
  /// [page] - Seitenzahl bei mehrseitigen Dokumenten.
  /// [usePdf] - Liefert die PDF-Repräsentation statt des Originals.
  /// [attachItem] - Index des E-Mail-Anhangs, wenn [oid] eine E-Mail ist
  ///   (z.B. `3` für Anhang 3).
  /// [zipItem] - Index des Items innerhalb eines ZIP-Anhangs.
  /// [maxSize] - Verkleinert Bilder; der Wert definiert die kurze Seite.
  ///
  /// Returns: [GsdFileDownload] mit den unveränderten Bytes und den
  /// Response-Headern (Binärantwort, umgeht die Response-Entschlüsselung).
  ///
  /// Throws: `GsdHttpException` bei einem Statuscode != 200.
  ///
  /// Beispiel:
  /// ```dart
  /// // v3/file/1PTF?page=3
  /// final GsdFileDownload page = await api.v3.file.get('1PTF', page: 3);
  /// final Uint8List bytes = page.bytes;
  /// final String? type = page.headers['content-type'];
  ///
  /// // Anhang 3 einer E-Mail als verkleinertes Bild
  /// final GsdFileDownload attachment = await api.v3.file.get(
  ///   mailOid,
  ///   attachItem: 3,
  ///   maxSize: 512,
  /// );
  /// ```
  Future<GsdFileDownload> get(
    String oid, {
    int? page,
    bool? usePdf,
    int? attachItem,
    int? zipItem,
    int? maxSize,
  }) {
    final query = <String, String>{};
    if (page != null) {
      query['page'] = page.toString();
    }
    if (usePdf != null) {
      query['usePdf'] = usePdf.toString();
    }
    if (attachItem != null) {
      query['attachItem'] = attachItem.toString();
    }
    if (zipItem != null) {
      query['zipItem'] = zipItem.toString();
    }
    if (maxSize != null) {
      query['maxSize'] = maxSize.toString();
    }

    return _runtime.execute(
      ApiRequest<GsdFileDownload>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v3,
        path: '/file/$oid',
        queryParameters: query.isEmpty ? null : query,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _fileResponsePolicy,
        operationId: 'v3.file.get',
      ),
    );
  }
}
