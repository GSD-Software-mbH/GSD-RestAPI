import 'dart:convert';

import 'package:gsd_restapi/src/exceptions/gsd_api_exception.dart';
import 'package:gsd_restapi/src/runtime/transport_response.dart';
import 'package:meta/meta.dart';

/// Der DOCUframe-Umschlag
/// `{"status": {"internalStatus", "statusMessage"}, "data": ...}` einer
/// Antwort, nach der Statusauswertung.
///
/// Einzige Stelle der Statusauswertung, für Einzelantworten wie für die
/// Einträge eines `v1/multi`. Regeln:
///
/// 1. Zuerst der Status, erst bei OK `data`: Ein Fehlerstatus wirft, bevor
///    eine Policy `data` liest. So kommen 201, 204 und 341 als die
///    Exceptions an, auf die der Session-Retry des Runtimes reagiert.
/// 2. Ist der Body kein JSON-Objekt, wirft er bei HTTP-Status ungleich 2xx
///    [GsdHttpException], sonst [GsdParseException].
/// 3. JSON ohne `status` wirft [GsdHttpException].
/// 4. `internalStatus` darf `int` oder `String` sein; `0` und `200` sind OK.
/// 5. Der Umschlag-Status hat Vorrang vor dem HTTP-Status: HTTP 500 mit
///    Umschlag 201 wirft [GsdSessionInvalidException].
@internal
final class ResponseEnvelope {
  const ResponseEnvelope._(
    this.body, {
    required this.internalStatus,
    required this.statusMessage,
  });

  /// Wertet den Umschlag von [response] aus.
  ///
  /// Liefert ihn bei OK-Status; wirft sonst die [GsdApiException] zum Status
  /// (siehe Klassendoku). [operationId] landet in einer
  /// [GsdParseException].
  factory ResponseEnvelope.decode(
    TransportResponse response, {
    required String operationId,
  }) {
    final Object? json;
    try {
      json = jsonDecode(response.body);
    } on FormatException {
      throw _unreadable(response, operationId: operationId, path: '');
    }
    if (json is! Map<String, Object?>) {
      throw _unreadable(response, operationId: operationId, path: '');
    }

    if (!json.containsKey('status')) {
      throw _httpError(response);
    }

    final status = json['status'];
    final internalStatus = internalStatusOf(json);
    if (status is! Map<String, Object?> || internalStatus == null) {
      throw _unreadable(
        response,
        operationId: operationId,
        path: status is Map ? 'status.internalStatus' : 'status',
      );
    }

    final rawMessage = status['statusMessage'];
    final statusMessage = rawMessage is String
        ? rawMessage
        : rawMessage?.toString() ?? '';

    final error = errorFor(internalStatus, statusMessage);
    if (error != null) {
      throw error;
    }

    return ResponseEnvelope._(
      json,
      internalStatus: internalStatus,
      statusMessage: statusMessage,
    );
  }

  /// `status.internalStatus` eines bereits dekodierten Bodys als String, oder
  /// `null`, wenn [decoded] keinen lesbaren Umschlag-Status hat.
  static String? internalStatusOf(Object? decoded) {
    if (decoded is! Map<String, Object?>) return null;
    final status = decoded['status'];
    if (status is! Map<String, Object?>) return null;

    return switch (status['internalStatus']) {
      final int value => '$value',
      final String value => value,
      _ => null,
    };
  }

  /// Die Exception zum Fehlerstatus [internalStatus], oder `null` bei OK
  /// (`0`, `200`).
  static GsdServerException? errorFor(
    String internalStatus,
    String statusMessage,
  ) {
    final message = 'webservice error: $internalStatus $statusMessage';
    return switch (internalStatus) {
      '0' || '200' => null,
      '201' => GsdSessionInvalidException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '204' => GsdSessionMissingException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '302' => GsdInvalidCredentialsException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '306' || '101' => GsdLicenseException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '340' => GsdTwoFactorRequiredException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '341' => GsdTwoFactorTokenMissingException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      '342' => GsdTwoFactorTokenInvalidException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
      _ => GsdServerException(
        internalStatus: internalStatus,
        statusMessage: statusMessage,
        message: message,
      ),
    };
  }

  static GsdApiException _unreadable(
    TransportResponse response, {
    required String operationId,
    required String path,
  }) {
    if (response.statusCode < 200 || response.statusCode > 299) {
      return _httpError(response);
    }
    return GsdParseException(operationId: operationId, path: path);
  }

  static GsdHttpException _httpError(TransportResponse response) =>
      GsdHttpException(
        'HTTPResponseException: ${response.statusCode} '
        '${response.reasonPhrase ?? ''}',
        response.statusCode,
        reasonPhrase: response.reasonPhrase,
      );

  /// Der ganze dekodierte Body.
  final Map<String, Object?> body;

  /// `status.internalStatus`, als String.
  final String internalStatus;

  /// `status.statusMessage`; leer, wenn er fehlt.
  final String statusMessage;

  /// `data` des Umschlags; `null`, wenn es fehlt.
  Object? get data => body['data'];
}
