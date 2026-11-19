import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:meta/meta.dart';

/// Native Makro-, Druck- und Telefonie-Integrationen der V1-Fassade.
class GsdV1IntegrationsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1IntegrationsApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();

  final ApiRuntime _runtime;

  /// Führt ein Schnittstellenmakro auf dem Server aus
  ///
  /// Diese Methode ermöglicht die Ausführung von benutzerdefinierten
  /// Interface-Makros, die in DOCUframe hinterlegt sind.
  ///
  /// Das Makro wird über den `/v1/execute/{macroName}` Endpunkt ausgeführt und
  /// erhält die übergebenen Daten als JSON-Body. Die Antwort enthält das
  /// Ergebnis der Makro-Ausführung und kann je nach Makro unterschiedliche
  /// Datenstrukturen enthalten.
  ///
  /// [macroName] - Der Name des auszuführenden Interface-Makros
  /// [body] - Die Eingabedaten für das Makro als Map (werden als JSON
  ///   übertragen)
  ///
  /// Returns: `data` der Antwort, das Ergebnis des Makros
  ///
  /// Throws: die `GsdApiException` zum Status. Wie jeder andere Endpunkt
  /// erneuert der Aufruf eine abgelaufene Session und fragt bei 341 nach dem
  /// 2FA-Token (bis 0.2.x lieferte er die Antwort ungeprüft).
  ///
  /// Beispiel:
  /// ```dart
  /// Map<String, dynamic> macroData = {
  ///   "parameter1": "wert1",
  ///   "parameter2": 123,
  ///   "objekte": ["oid1", "oid2"]
  /// };
  ///
  /// final Object? result =
  ///     await api.v1.integrations.postExecuteInterfaceMacro(
  ///   "MeinCustomMakro",
  ///   body: macroData,
  /// );
  /// print("Makro erfolgreich ausgeführt: $result");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Führt ein Interface-Makro aus (`POST v1/execute/{macroName}`); [body]
  /// wird nur bei Nicht-null gesendet.
  ///
  /// Hinweis: Der Legacy-Manager rief NICHT `_synchronizedRefreshSession()`
  /// vorab auf (anders als `postPrintMacrosExecute`); das Session-Handling
  /// erfolgt hier über die reaktive Session-Policy der Runtime.
  Future<Object?> postExecuteInterfaceMacro(
    String macroName, {
    Map<String, dynamic>? body,
  }) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/execute/$macroName',
        body: body != null ? jsonEncode(body) : null,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.integrations.postExecuteInterfaceMacro',
      ),
    );
  }

  /// Führt Druck-Makros aus und ersetzt Platzhalter mit Objektdaten
  ///
  /// Verarbeitet Textvorlagen mit Makro-Platzhaltern und ersetzt diese
  /// mit Daten aus den angegebenen Objekten (Adresse, Vorgang, etc.).
  ///
  /// [text] - Der Text mit Makro-Platzhaltern (z.B. "Sehr geehrte
  ///   {Adresse.Anrede}")
  /// [addressOid] - OID der Adresse für Adress-Makros
  /// [addressNrOid] - OID der Adressnummer
  /// [contactPersonOid] - OID der Kontaktperson
  /// [incidentOid] - OID des Vorgangs
  /// [objectOid] - OID eines allgemeinen Objekts
  ///
  /// Returns: `data` der Antwort mit dem verarbeiteten Text
  ///
  /// Beispiel:
  /// ```dart
  /// String template = "Sehr geehrte/r {Adresse.Anrede} {Adresse.Name}";
  /// final Object? text =
  ///     await api.v1.integrations.postPrintMacrosExecute(
  ///   template,
  ///   addressOid: "12345"
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Führt Druck-Makros aus (`POST v1/printMacros/execute`).
  ///
  /// Bewusste Verhaltensabweichung: Der Legacy-Manager erzwang vor diesem
  /// Request ein `_synchronizedRefreshSession()` (proaktiver Login). Die neue
  /// Runtime zentralisiert Session-Erneuerung REAKTIV im SessionCoordinator
  /// (Refresh bei ungültiger Session), daher entfällt der proaktive
  /// Vorab-Login. Der Wire-Vertrag des Makro-Requests selbst bleibt identisch.
  Future<Object?> postPrintMacrosExecute(
    String text, {
    String addressOid = '',
    String addressNrOid = '',
    String contactPersonOid = '',
    String incidentOid = '',
    String objectOid = '',
  }) {
    final body = <String, dynamic>{'text': text};
    if (addressOid.isNotEmpty) body['address'] = addressOid;
    if (addressNrOid.isNotEmpty) body['addressNr'] = addressNrOid;
    if (contactPersonOid.isNotEmpty) body['contactPerson'] = contactPersonOid;
    if (incidentOid.isNotEmpty) body['incident'] = incidentOid;
    if (objectOid.isNotEmpty) body['object'] = objectOid;

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/printMacros/execute',
        body: jsonEncode(body),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.integrations.postPrintMacrosExecute',
      ),
    );
  }

  /// Ruft Anruflisten und Telefonie-Daten ab
  ///
  /// Lädt Anrufinformationen, Anruflisten und Telefonie-bezogene Daten
  /// mit Filterung und Paginierung.
  ///
  /// [query] - Suchfilter für Anrufdaten
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Einträge pro Seite (Standard: aus Konfiguration)
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [rightsControlKey] - Berechtigungsschlüssel für Zugriffskontrolle
  ///
  /// Returns: `data` der Antwort mit den Anrufdaten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.integrations.getCalls(
  ///   query: "direction:incoming",
  ///   page: 1
  /// ) as Map<String, Object?>;
  /// List calls = data['calls'] as List;
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Anrufe/Calls (`GET v1/calls`); `perPage` fällt auf den
  /// Runtime-Konfigurationswert zurück und wird immer gesendet.
  Future<Object?> getCalls({
    String query = '',
    int page = 0,
    int? perPage,
    String serialization = '',
    String rightsControlKey = '',
  }) {
    final params = <String, String>{};
    if (query.isNotEmpty) params['query'] = query;
    if (page != 0) params['page'] = page.toString();
    params['perPage'] = (perPage ?? _runtime.configuration.perPageCount)
        .toString();
    if (serialization.isNotEmpty) params['serialization'] = serialization;
    if (rightsControlKey.isNotEmpty) {
      params['rightsControlKey'] = rightsControlKey;
    }

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/calls',
        queryParameters: params,
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.integrations.getCalls',
      ),
    );
  }
}
