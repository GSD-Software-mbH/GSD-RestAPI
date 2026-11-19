import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_check_service_result.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/models/gsd_version_info.dart';
import 'package:gsd_restapi/src/runtime/api_request.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/data_response_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/model_response_policy.dart';
import 'package:meta/meta.dart';

/// Native Service-, Lizenz- und Versionsoperationen der V1-Fassade.
class GsdV1ServiceApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1ServiceApi.internal(this._runtime);
  static const DataResponsePolicy<Object?> _responsePolicy =
      DataResponsePolicy<Object?>();
  static const ModelResponsePolicy<GsdCheckServiceResult>
  _checkServiceResponsePolicy = ModelResponsePolicy<GsdCheckServiceResult>(
    GsdCheckServiceResult.fromJson,
  );
  static const ModelResponsePolicy<GsdVersionInfo> _versionInfoResponsePolicy =
      ModelResponsePolicy<GsdVersionInfo>(GsdVersionInfo.fromJson);

  final ApiRuntime _runtime;

  /// Überprüft den aktuellen Webservice über '/CheckService'
  ///
  /// Prüft die Verfügbarkeit und den Status des konfigurierten Webservices.
  /// Diese Methode verwendet die bereits konfigurierte Server-URL der Instanz.
  ///
  /// Returns: [GsdCheckServiceResult] mit Service-Status und
  /// Datenbank-Informationen
  ///
  /// Throws: Exception bei Netzwerkfehlern oder Service-Problemen
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   final GsdCheckServiceResult result =
  ///       await api.v1.service.checkService();
  ///   print("Service verfügbar, Datenbanken: ${result.databases.length}");
  /// } catch (e) {
  ///   print("Service-Check fehlgeschlagen: $e");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Prüft den konfigurierten Service über `_CheckService`.
  Future<GsdCheckServiceResult> checkService() {
    return _runtime.execute(
      const ApiRequest<GsdCheckServiceResult>.unversioned(
        method: GsdHttpMethod.get,
        path: '/_CheckService',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _checkServiceResponsePolicy,
        operationId: 'v1.service.checkService',
      ),
    );
  }

  /// Prüft einen DOCUframe-Service über eine absolute URI.
  ///
  /// Anders als [checkService] verwendet diese Methode nicht die konfigurierte
  /// Basis-URL, sondern exakt die übergebene [requestUri]. Es werden keine
  /// Standardheader ergänzt.
  ///
  /// [requestUri] - Vollständige URI des `_CheckService`-Endpunkts
  ///
  /// Returns: [GsdCheckServiceResult] mit Service- und Lizenzstatus
  Future<GsdCheckServiceResult> checkServiceWithUri(Uri requestUri) {
    return _runtime.executeAbsoluteGet(
      uri: requestUri,
      timeout: const Duration(seconds: 10),
      responsePolicy: _checkServiceResponsePolicy,
      operationId: 'v1.service.checkServiceWithUri',
    );
  }

  /// Gibt Lizenzen für Anwendungen frei
  ///
  /// Gibt die Lizenzen für bestimmte Anwendungen in einer spezifizierten
  /// Session frei. Wird zur Lizenz-Verwaltung und zur Freigabe nicht mehr
  /// benötigter Lizenzen verwendet.
  ///
  /// [appnames] - Liste der Anwendungsnamen, für die Lizenzen freigegeben
  ///   werden sollen
  /// [sessionId] - Session-ID für die Lizenz-Freigabe
  ///
  /// Returns: `data` der Antwort
  ///
  /// Beispiel:
  /// ```dart
  /// await api.v1.service.postLicenseRelease(["app1", "app2"], "session-123");
  /// print("Lizenzen erfolgreich freigegeben");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Gibt die angegebenen App-Lizenzen für die übergebene Session frei.
  Future<Object?> postLicenseRelease(
    List<String> appnames,
    String sessionId,
  ) {
    return _runtime.execute(
      ApiRequest<Object?>(
        method: GsdHttpMethod.post,
        version: GsdApiVersion.v1,
        path: '/license/release',
        body: jsonEncode(<String, dynamic>{'appNames': appnames}),
        additionalHeaders: <String, String>{'sessionId': sessionId},
        authentication: AuthenticationPolicy.none,
        responsePolicy: _responsePolicy,
        operationId: 'v1.service.postLicenseRelease',
      ),
    );
  }

  /// Ruft Versionsinformationen des Servers ab
  ///
  /// Lädt detaillierte Informationen über die Server-Version, installierte
  /// Module und verfügbare Features der API.
  ///
  /// Returns: [GsdVersionInfo] mit Server-Versionsdaten und
  /// Modul-Informationen
  ///
  /// Beispiel:
  /// ```dart
  /// final GsdVersionInfo info = await api.v1.service.getVersionInfo();
  /// String serverVersion = info.serviceVersion;
  /// List<GsdDocuframeModule> modules = info.modules;
  /// print("Server-Version: $serverVersion");
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die typisierten V1-Versionsinformationen.
  Future<GsdVersionInfo> getVersionInfo() {
    return _runtime.execute(
      const ApiRequest<GsdVersionInfo>(
        method: GsdHttpMethod.get,
        version: GsdApiVersion.v1,
        path: '/versioninfo',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _versionInfoResponsePolicy,
        operationId: 'v1.service.getVersionInfo',
      ),
    );
  }
}
