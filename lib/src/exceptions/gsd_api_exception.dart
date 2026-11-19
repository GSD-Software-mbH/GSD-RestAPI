/// Basis aller Fehler, die `gsd_restapi` selbst wirft.
///
/// `sealed`: Ein `switch` über die direkten Untertypen ist erschöpfend.
/// [GsdServerException] fasst alle Fehler zusammen, die der Server im
/// Umschlag (`status.internalStatus`) meldet; ihre Untertypen stehen vor ihr
/// im `switch`.
///
/// Transportfehler (`SocketException`, `ClientException`,
/// `TimeoutException`) und der `StateError` nach `dispose()` gehen unverändert
/// durch und sind keine [GsdApiException].
sealed class GsdApiException implements Exception {
  const GsdApiException(this.message);

  /// Beschreibende Fehlernachricht.
  final String message;
}

/// HTTP-Fehler ohne lesbaren DOCUframe-Umschlag.
///
/// Wird geworfen, wenn die Antwort kein JSON ist und der HTTP-Status nicht 2xx
/// ist (etwa HTML vom Proxy), wenn JSON ohne `status` ankommt, oder wenn ein
/// Datei-Download einen Fehlerstatus liefert.
class GsdHttpException extends GsdApiException {
  /// Erstellt eine [GsdHttpException].
  ///
  /// [message] - Beschreibende Fehlernachricht
  /// [statusCode] - HTTP-Statuscode der Antwort
  /// [reasonPhrase] - HTTP-Statusnachricht, sofern bekannt
  const GsdHttpException(super.message, this.statusCode, {this.reasonPhrase});

  /// HTTP-Statuscode der Antwort, etwa 404, 502 oder 503.
  final int statusCode;

  /// HTTP-Statusnachricht, etwa "Not Found".
  final String? reasonPhrase;

  @override
  String toString() => 'GsdHttpException: $message';
}

/// Die Antwort hatte einen OK-Status, ihr Inhalt passt aber nicht zur
/// erwarteten Form.
///
/// Trägt nie den Body der Antwort, nur die Stelle ([path]), an der das
/// Lesen scheiterte. Kein [GsdServerException]: Der Server hat den Request
/// angenommen.
class GsdParseException extends GsdApiException {
  /// Erstellt eine [GsdParseException].
  ///
  /// [operationId] - Kennung des Endpunkts, etwa `v1.login`
  /// [path] - Stelle in der Antwort, etwa `data` oder `data.uploadId`; leer,
  /// wenn die ganze Antwort unlesbar ist
  GsdParseException({
    required this.operationId,
    required this.path,
    String? message,
  }) : super(
         message ??
             'Antwort von $operationId nicht lesbar'
                 '${path.isEmpty ? '' : ' an "$path"'}.',
       );

  /// Kennung des Endpunkts, dessen Antwort nicht lesbar war.
  final String operationId;

  /// Stelle in der Antwort, an der das Lesen scheiterte.
  final String path;

  @override
  String toString() => 'GsdParseException: $message';
}

/// Eine Aktion wurde aus Sicherheitsgründen blockiert, etwa eine
/// `http://`-Verbindung ohne `allowSslError`.
class GsdSecurityException extends GsdApiException {
  /// Erstellt eine [GsdSecurityException].
  ///
  /// [message] - Beschreibung der Sicherheitsverletzung
  const GsdSecurityException(super.message);

  @override
  String toString() => 'GsdSecurityException: $message';
}

/// Ein Upload wurde über `GsdFileUploadController.cancel()` abgebrochen.
class GsdUploadCancelledException extends GsdApiException {
  /// Erstellt eine [GsdUploadCancelledException].
  const GsdUploadCancelledException([super.message = 'Upload cancelled']);

  @override
  String toString() => 'GsdUploadCancelledException: $message';
}

/// Der Server meldet im Umschlag einen Fehlerstatus
/// (`status.internalStatus` ungleich `0` und `200`).
///
/// Fallback für alle Codes ohne eigene Klasse. Die Untertypen bilden die
/// Codes ab, auf die Runtime und App gezielt reagieren.
///
/// Für alle Fehlercodes siehe: https://docs.gsd.pl/restapi/errorCodes/errorCodes/
class GsdServerException extends GsdApiException {
  /// Erstellt eine [GsdServerException].
  ///
  /// [internalStatus] - `status.internalStatus` aus dem Umschlag
  /// [statusMessage] - `status.statusMessage` aus dem Umschlag
  /// [message] - Beschreibende Fehlernachricht
  const GsdServerException({
    required this.internalStatus,
    required this.statusMessage,
    String message = '',
  }) : super(message);

  /// `status.internalStatus` aus dem Umschlag, als String.
  final String internalStatus;

  /// `status.statusMessage` aus dem Umschlag.
  final String statusMessage;

  /// Format "internalStatus: statusMessage".
  @override
  String toString() => '$internalStatus: $statusMessage';
}

/// Status 201: Die Session ist ungültig oder abgelaufen.
///
/// Der Runtime erneuert die Session einmal und wiederholt den Request.
class GsdSessionInvalidException extends GsdServerException {
  /// Erstellt eine [GsdSessionInvalidException].
  const GsdSessionInvalidException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 204: Session-ID oder Token fehlen im Request.
///
/// Der Runtime erneuert die Session einmal und wiederholt den Request.
class GsdSessionMissingException extends GsdServerException {
  /// Erstellt eine [GsdSessionMissingException].
  const GsdSessionMissingException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 302: Benutzername oder Passwort sind falsch.
class GsdInvalidCredentialsException extends GsdServerException {
  /// Erstellt eine [GsdInvalidCredentialsException].
  const GsdInvalidCredentialsException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 306 oder 101: Die Lizenz fehlt, ist abgelaufen oder erschöpft.
class GsdLicenseException extends GsdServerException {
  /// Erstellt eine [GsdLicenseException].
  const GsdLicenseException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 340: Die Anmeldung verlangt 2FA.
class GsdTwoFactorRequiredException extends GsdServerException {
  /// Erstellt eine [GsdTwoFactorRequiredException].
  const GsdTwoFactorRequiredException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 341: Das 2FA-Token fehlt.
///
/// Innerhalb einer Sitzung fragt der Runtime das Token über den
/// `GsdTwoFactorTokenProvider` ab; beim expliziten Login geht die Exception an
/// den Aufrufer.
class GsdTwoFactorTokenMissingException extends GsdServerException {
  /// Erstellt eine [GsdTwoFactorTokenMissingException].
  const GsdTwoFactorTokenMissingException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}

/// Status 342: Das 2FA-Token ist ungültig.
class GsdTwoFactorTokenInvalidException extends GsdServerException {
  /// Erstellt eine [GsdTwoFactorTokenInvalidException].
  const GsdTwoFactorTokenInvalidException({
    required super.internalStatus,
    required super.statusMessage,
    super.message,
  });
}
