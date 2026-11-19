import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/v1/extensions.dart';
import 'package:meta/meta.dart';

/// Native Personalzeiterfassungs-Operationen (PZE) der V1-Fassade.
class GsdV1TimeRecordingApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1TimeRecordingApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();

  final ApiRuntime _runtime;

  /// Startet die Zeiterfassung (Einstempeln) für einen Mitarbeiter
  ///
  /// Registriert den Arbeitsbeginn für die Personalzeiterfassung (PZE).
  /// Kann mit optionalem Schlüssel für verschiedene Tätigkeitsarten verwendet
  /// werden.
  ///
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller
  ///   Benutzer)
  /// [key] - Tätigkeitsschlüssel für verschiedene Arbeitsarten (optional)
  ///
  /// Returns: `data` der Antwort mit dem Status der Zeiterfassung
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.timeRecording.postPZEClockIn(
  ///   employeeoid: "emp-12345",
  ///   key: "PROJEKT_A"
  /// );
  /// print("Zeiterfassung gestartet");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Stempelt einen Mitarbeiter ein (`POST v1/pze/clockIn`).
  ///
  /// `employeeoid`/`key` landen nur bei Nicht-null im Body; der Body wird -
  /// wie im Legacy - IMMER gesendet (leer als `{}`).
  Future<Object?> postPZEClockIn({String? employeeoid, String? key}) {
    final body = <String, dynamic>{};
    if (employeeoid != null) body['employeeoid'] = employeeoid;
    if (key != null) body['key'] = key;

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
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
  /// [employeeoid] - OID des Mitarbeiters (optional, Standard: aktueller
  ///   Benutzer)
  ///
  /// Returns: `data` der Antwort mit den erfassten Arbeitszeiten
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.timeRecording.postPZEClockOut(
  ///   employeeoid: "emp-12345"
  /// );
  /// print("Zeiterfassung beendet");
  /// // Arbeitszeit wird automatisch berechnet
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Stempelt einen Mitarbeiter aus (`POST v1/pze/clockOut`).
  ///
  /// `employeeoid` ist hier ein QUERY-Parameter (kein Body).
  Future<Object?> postPZEClockOut({String? employeeoid}) {
    final params = <String, String>{};
    if (employeeoid != null) params['employeeoid'] = employeeoid;

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
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
  /// Returns: `data` der Antwort mit der Liste verfügbarer Zeitschlüssel
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.timeRecording.getPZEWorkingTimeKeys()
  ///     as Map<String, Object?>;
  /// List keys = data['workingTimeKeys'] as List;
  /// // keys enthält: [{"key": "PROJEKT_A", "name": "Projekt A"}, ...]
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die verfügbaren Arbeitszeitschlüssel
  /// (`GET v1/pze/workingTimeKeys`).
  Future<Object?> getPZEWorkingTimeKeys({String serialization = ''}) {
    final params = <String, String>{};
    if (serialization.isNotEmpty) params['serialization'] = serialization;

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
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
  /// [employeeOid] - OID des Mitarbeiters (optional, Standard: aktueller
  ///   Benutzer)
  /// [from] - Startzeitpunkt für den Abfragezeitraum
  /// [to] - Endzeitpunkt für den Abfragezeitraum
  ///
  /// Returns: `data` der Antwort mit Arbeitszeitdaten und Salden
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime start = DateTime.now().subtract(Duration(days: 30));
  /// DateTime end = DateTime.now();
  /// final data =
  ///     await api.v1.timeRecording.getPZEWorkingTimeAccounts(
  ///   employeeOid: "emp-12345",
  ///   from: start,
  ///   to: end
  /// );
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt Arbeitszeitkonten für einen Zeitraum
  /// (`GET v1/pze/workingTimeAccounts`).
  Future<Object?> getPZEWorkingTimeAccounts({
    String serialization = '',
    String? employeeOid,
    DateTime? from,
    DateTime? to,
  }) {
    final params = <String, String>{};
    if (serialization.isNotEmpty) params['serialization'] = serialization;
    if (employeeOid != null) params['employeeOid'] = employeeOid;
    if (from != null) params['from'] = from.toISOFormatString();
    if (to != null) params['to'] = to.toISOFormatString();

    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
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
