part of '../../../docuframe_api.dart';

/// Native Service-, Lizenz- und Versionsoperationen der V1-Fassade.
class V1ServiceApi {
  static const RestApiResponsePolicy _responsePolicy = RestApiResponsePolicy();
  static const LegacyResponsePolicy<RestApiCheckServiceResponse>
  _checkServiceResponsePolicy =
      LegacyResponsePolicy<RestApiCheckServiceResponse>(
        RestApiCheckServiceResponse.new,
      );
  static const LegacyResponsePolicy<RestApiVersionInfoResponse>
  _versionInfoResponsePolicy = LegacyResponsePolicy<RestApiVersionInfoResponse>(
    RestApiVersionInfoResponse.new,
  );

  final ApiRuntime _runtime;

  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  V1ServiceApi.internal(this._runtime);

  /// Überprüft den aktuellen Webservice über '/CheckService'
  ///
  /// Prüft die Verfügbarkeit und den Status des konfigurierten Webservices.
  /// Diese Methode verwendet die bereits konfigurierte Server-URL der Instanz.
  ///
  /// Returns: [RestApiCheckServiceResponse] mit Service-Status und Datenbank-Informationen
  ///
  /// Throws: Exception bei Netzwerkfehlern oder Service-Problemen
  ///
  /// Beispiel:
  /// ```dart
  /// try {
  ///   RestApiCheckServiceResponse response = await api.v1.service.checkService();
  ///   if (response.isOk) {
  ///     print("Service verfügbar, Datenbanken: ${response.databases.length}");
  ///   }
  /// } catch (e) {
  ///   print("Service-Check fehlgeschlagen: $e");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Prüft den konfigurierten Service über `_CheckService`.
  Future<RestApiCheckServiceResponse> checkService() {
    return _runtime.execute(
      ApiRequest<RestApiCheckServiceResponse>.unversioned(
        method: ApiHttpMethod.get,
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
  /// Returns: [RestApiCheckServiceResponse] mit Service- und Lizenzstatus
  Future<RestApiCheckServiceResponse> checkServiceWithUri(Uri requestUri) {
    return _runtime.executeAbsoluteGet(
      uri: requestUri,
      timeout: const Duration(seconds: 10),
      responsePolicy: _checkServiceResponsePolicy,
      operationId: 'v1.service.checkServiceWithUri',
    );
  }

  /// Gibt Lizenzen für Anwendungen frei
  ///
  /// Gibt die Lizenzen für bestimmte Anwendungen in einer spezifizierten Session frei.
  /// Wird zur Lizenz-Verwaltung und zur Freigabe nicht mehr benötigter Lizenzen verwendet.
  ///
  /// [appnames] - Liste der Anwendungsnamen, für die Lizenzen freigegeben werden sollen
  /// [sessionId] - Session-ID für die Lizenz-Freigabe
  ///
  /// Returns: [RestApiResponse] mit dem Status der Lizenz-Freigabe
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiResponse response = await api.v1.service.postLicenseRelease(
  ///   ["app1", "app2"],
  ///   "session-123"
  /// );
  /// if (response.isOk) {
  ///   print("Lizenzen erfolgreich freigegeben");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Gibt die angegebenen App-Lizenzen für die übergebene Session frei.
  Future<RestApiResponse> postLicenseRelease(
    List<String> appnames,
    String sessionId,
  ) {
    return _runtime.execute(
      ApiRequest<RestApiResponse>(
        method: ApiHttpMethod.post,
        version: ApiVersion.v1,
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
  /// Lädt detaillierte Informationen über die Server-Version, installierte Module
  /// und verfügbare Features der API.
  ///
  /// Returns: [RestApiVersionInfoResponse] mit Server-Versionsdaten und Modul-Informationen
  ///
  /// Beispiel:
  /// ```dart
  /// RestApiVersionInfoResponse response = await api.v1.service.getVersionInfo();
  /// if (response.isOk) {
  ///   String serverVersion = response.version;
  ///   List<RestApiModule> modules = response.modules;
  ///   print("Server-Version: $serverVersion");
  /// }
  /// ```
  ///
  /// Hinweis zur neuen API:
  /// Lädt die typisierten V1-Versionsinformationen.
  Future<RestApiVersionInfoResponse> getVersionInfo() {
    return _runtime.execute(
      ApiRequest<RestApiVersionInfoResponse>(
        method: ApiHttpMethod.get,
        version: ApiVersion.v1,
        path: '/versioninfo',
        authentication: AuthenticationPolicy.session,
        deduplication: DeduplicationPolicy.enabled,
        responsePolicy: _versionInfoResponsePolicy,
        operationId: 'v1.service.getVersionInfo',
      ),
    );
  }
}
