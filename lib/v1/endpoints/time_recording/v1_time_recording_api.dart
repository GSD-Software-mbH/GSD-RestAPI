part of '../../../docuframe_api.dart';

/// Native Personalzeiterfassungs-Operationen (PZE) der V1-Fassade.
class V1TimeRecordingApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1TimeRecordingApi.internal(this._runtime);

  /// Startet die Zeiterfassung (Einstempeln) für einen Mitarbeiter
  ///
  /// Registriert den Arbeitsbeginn für die Personalzeiterfassung (PZE).
  /// Kann mit optionalem Schlüssel für verschiedene Tätigkeitsarten verwendet werden.
  ///
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  /// [key] - Tätigkeitsschlüssel für verschiedene Arbeitsarten (optional)
  ///
  /// Returns: [RestApiResponse] mit dem Status der Zeiterfassung
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.timeRecording.postPZEClockIn(
  ///   employeeoid: "emp-12345",
  ///   key: "PROJEKT_A"
  /// );
  /// if (response.isOk) {
  ///   print("Zeiterfassung gestartet");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Stempelt einen Mitarbeiter ein (`POST v1/pze/clockIn`).
  ///
  /// `employeeoid`/`key` landen nur bei Nicht-null im Body; der Body wird -
  /// wie im Legacy - IMMER gesendet (leer als `{}`).
  Future<RestApiResponse> postPZEClockIn({String? employeeoid, String? key}) {
    final Map<String, dynamic> body = <String, dynamic>{};
    if (employeeoid != null) body['employeeoid'] = employeeoid;
    if (key != null) body['key'] = key;

    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/pze/clockIn',
        body: jsonEncode(body),
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.timeRecording.postPZEClockIn',
      ),
    );
  }

  /// Beendet die Zeiterfassung (Ausstempeln) für einen Mitarbeiter
  ///
  /// Registriert das Arbeitsende für die Personalzeiterfassung (PZE).
  /// Berechnet automatisch die Arbeitszeit seit dem letzten Einstempeln.
  ///
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  ///
  /// Returns: [RestApiResponse] mit den erfassten Arbeitszeiten
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.timeRecording.postPZEClockOut(
  ///   employeeoid: "emp-12345"
  /// );
  /// if (response.isOk) {
  ///   print("Zeiterfassung beendet");
  ///   // Arbeitszeit wird automatisch berechnet
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Stempelt einen Mitarbeiter aus (`POST v1/pze/clockOut`).
  ///
  /// `employeeoid` ist hier ein QUERY-Parameter (kein Body).
  Future<RestApiResponse> postPZEClockOut({String? employeeoid}) {
    final Map<String, String> params = <String, String>{};
    if (employeeoid != null) params['employeeoid'] = employeeoid;

    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
        path: '/pze/clockOut',
        queryParameters: params.isEmpty ? null : params,
        authentication: AuthenticationPolicy.session,
        responsePolicy: _responsePolicy,
        operationId: 'v1.timeRecording.postPZEClockOut',
      ),
    );
  }

  /// Ruft verfügbare Arbeitszeitschlüssel für die PZE ab
  ///
  /// Lädt alle verfügbaren Tätigkeitsschlüssel und Arbeitszeitkategorien
  /// für die Personalzeiterfassung.
  ///
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  ///
  /// Returns: [RestApiResponse] mit der Liste verfügbarer Zeitschlüssel
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.timeRecording.getPZEWorkingTimeKeys();
  /// if (response.isOk) {
  ///   List keys = response.data['workingTimeKeys'];
  ///   // keys enthält: [{"key": "PROJEKT_A", "name": "Projekt A"}, ...]
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die verfügbaren Arbeitszeitschlüssel
  /// (`GET v1/pze/workingTimeKeys`).
  Future<RestApiResponse> getPZEWorkingTimeKeys({String serialization = ''}) {
    final Map<String, String> params = <String, String>{};
    if (serialization.isNotEmpty) params['serialization'] = serialization;

    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/pze/workingTimeKeys',
        queryParameters: params.isEmpty ? null : params,
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.timeRecording.getPZEWorkingTimeKeys',
      ),
    );
  }

  /// Ruft Arbeitszeitkonten für einen Zeitraum ab
  ///
  /// Lädt die Arbeitszeiterfassung und Stundensalden für einen bestimmten
  /// Mitarbeiter und Zeitraum aus der PZE.
  ///
  /// [serialization] - Serialisierungsoptionen für die Ausgabe
  /// [employeeOid] - OID des Mitarbeiters (optional, Standard: aktueller Benutzer)
  /// [from] - Startzeitpunkt für den Abfragezeitraum
  /// [to] - Endzeitpunkt für den Abfragezeitraum
  ///
  /// Returns: [RestApiResponse] mit Arbeitszeitdaten und Salden
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime start = DateTime.now().subtract(Duration(days: 30));
  /// DateTime end = DateTime.now();
  /// RestApiResponse response = await api.v1.timeRecording.getPZEWorkingTimeAccounts(
  ///   employeeOid: "emp-12345",
  ///   from: start,
  ///   to: end
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Arbeitszeitkonten für einen Zeitraum
  /// (`GET v1/pze/workingTimeAccounts`).
  Future<RestApiResponse> getPZEWorkingTimeAccounts({
    String serialization = '',
    String? employeeOid,
    DateTime? from,
    DateTime? to,
  }) {
    final Map<String, String> params = <String, String>{};
    if (serialization.isNotEmpty) params['serialization'] = serialization;
    if (employeeOid != null) params['employeeOid'] = employeeOid;
    if (from != null) params['from'] = from.toISOFormatString();
    if (to != null) params['to'] = to.toISOFormatString();

    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/pze/workingTimeAccounts',
        queryParameters: params.isEmpty ? null : params,
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _responsePolicy,
        operationId: 'v1.timeRecording.getPZEWorkingTimeAccounts',
      ),
    );
  }
}
