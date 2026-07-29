part of '../../../../docuframe_api.dart';

/// Native V2-Dateioperationen.
class V2FileApi {
  static const BinaryLegacyResponsePolicy<RestApiFileResponse>
  _fileResponsePolicy = BinaryLegacyResponsePolicy<RestApiFileResponse>(
    RestApiFileResponse.new,
  );

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V2FileApi.internal(this._runtime);

  /// Lädt eine Datei über `GET v2/file/{oid}` herunter.
  ///
  /// [oid] adressiert die Datei. Bei E-Mail-Anhängen kann wahlweise die OID
  /// des Abschnitts oder die OID des Anhangs verwendet werden.
  ///
  /// Alle Zusatzparameter sind optional und werden NUR dann als
  /// Query-Parameter gesendet, wenn sie explizit gesetzt sind. Ohne Angabe
  /// bleibt die URL exakt `v2/file/{oid}`.
  ///
  /// [page] - Seitenzahl bei mehrseitigen Dokumenten.
  /// [usePdf] - Liefert die PDF-Repräsentation statt des Originals.
  /// [attachItem] - Index des E-Mail-Anhangs, wenn [oid] eine E-Mail ist
  ///   (z.B. `3` für Anhang 3).
  /// [zipItem] - Index des Items innerhalb eines ZIP-Anhangs.
  /// [maxSize] - Verkleinert Bilder; der Wert definiert die kurze Seite.
  ///
  /// Returns: [RestApiFileResponse] mit den unveränderten Bytes und den
  /// Response-Headern (Binärantwort, umgeht die Response-Entschlüsselung).
  ///
  /// Throws: `HttpRequestException` bei einem Statuscode != 200.
  ///
  /// Beispiel:
  /// ```dart
  /// // v2/file/1PTF?page=3
  /// final RestApiFileResponse response = await api.v2.file.get(
  ///   '1PTF',
  ///   page: 3,
  /// );
  /// if (response.isOk) {
  ///   final Uint8List bytes = response.httpResponse.bodyBytes;
  /// }
  ///
  /// // Anhang 3 einer E-Mail als verkleinertes Bild
  /// final RestApiFileResponse attachment = await api.v2.file.get(
  ///   mailOid,
  ///   attachItem: 3,
  ///   maxSize: 512,
  /// );
  /// ```
  Future<RestApiFileResponse> get(
    String oid, {
    int? page,
    bool? usePdf,
    int? attachItem,
    int? zipItem,
    int? maxSize,
  }) {
    final Map<String, String> query = <String, String>{};
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
      ApiRequest<RestApiFileResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v2,
        path: '/file/$oid',
        queryParameters: query.isEmpty ? null : query,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _fileResponsePolicy,
        operationId: 'v2.file.get',
      ),
    );
  }
}
