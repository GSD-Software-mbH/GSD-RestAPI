import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/api_types.dart';

import 'policies/authentication_policy.dart';
import 'policies/deduplication_policy.dart';
import 'policies/response_policy.dart';

/// Vollständige, unveränderliche Beschreibung eines einzelnen API-Requests
/// für den `ApiRuntime`.
///
/// `ApiRequest` beschreibt AUSSCHLIESSLICH den fachlich-technischen
/// Endpunkt-Vertrag (Verb, Route, Query, Body, Header, Authentifizierung,
/// Deduplizierung, Response-Policy und Operation-ID). Priorität und
/// Buffering sind AUSSCHLIESSLICH Zone-gesteuerte Runtime-Policy (siehe
/// `RuntimeExecutionContext`/`RuntimeExecutionPolicy`) - ein Endpunkt kann
/// beides nicht selbst vorgeben. Ob ein Endpunkt grundsätzlich für
/// Multi-Request-Buffering geeignet ist, entscheidet ausschließlich
/// `MultiRequestEligibility` anhand von Version und Pfad.
///
/// ```dart
/// ApiRequest<RawApiResponse>(
///   method: ApiHttpMethod.get,
///   version: ApiVersion.v2,
///   path: '/model/structure',
///   authentication: AuthenticationPolicy.session,
///   responsePolicy: RawResponsePolicy(),
///   operationId: 'v2.model.structure',
/// );
/// ```
@internal
class ApiRequest<T> {
  /// Ob der Pfad direkt unter dem Alias statt unter `v1`/`v2` liegt.
  final bool _unversioned;

  /// Explizites Request-Ziel. Normale Requests sind versioniert;
  /// `_CheckSession` und `_CheckService` verwenden ein unversioniertes Ziel.
  ApiRequestTarget get target => _unversioned
      ? ApiRequestTarget.unversioned(path)
      : ApiRequestTarget.versioned(version: version, path: path);

  /// HTTP-Methode der Anfrage.
  final ApiHttpMethod method;

  /// API-Version, die das URL-Präfix (`v1`/`v2`) bestimmt.
  final ApiVersion version;

  /// Endpunkt-Pfad relativ zum Versions-Präfix (z.B. `/model/structure`),
  /// ohne Alias- und ohne Versions-Anteil.
  final String path;

  /// Optionale Query-Parameter.
  final Map<String, String>? queryParameters;

  /// Optionaler Request-Body.
  final String? body;

  /// Optionaler Content-Type; `null` verwendet den Standard
  /// `application/json; charset=utf-8`, ein leerer String unterdrückt den
  /// `Content-type`-Header vollständig.
  final String? contentType;

  /// Zusätzliche Header; überschreiben bei Namensgleichheit die vom
  /// `HeaderProvider` erzeugten Standard-Header.
  final Map<String, String>? additionalHeaders;

  /// Authentifizierungsverhalten des Requests.
  final AuthenticationPolicy authentication;

  /// Ob nebenläufige, technisch identische Requests eine Ausführung teilen
  /// dürfen. Standardmäßig deaktiviert, damit schreibende Operationen nicht
  /// versehentlich unterdrückt werden.
  ///
  /// WICHTIG: Der Dedup-Schlüssel des `ApiRuntime` vergleicht [responsePolicy]
  /// per IDENTITÄT, nicht per Wert. Übergibt ein Endpunkt bei `enabled` pro
  /// Aufruf eine frisch konstruierte (nicht `const`, nicht gecachte)
  /// `ResponsePolicy`-Instanz, greift die Deduplizierung STILL und OHNE
  /// FEHLER nie. Für wirksames Dedup muss dieselbe (z.B. `const`) Instanz
  /// wiederverwendet werden.
  final DeduplicationPolicy deduplication;

  /// Übersetzt die Transport-Antwort in das Ergebnis vom Typ [T].
  final ResponsePolicy<T> responsePolicy;

  /// Eindeutige, stabile Operations-ID für Logging und Metriken
  /// (z.B. `v2.model.structure`).
  final String operationId;

  const ApiRequest({
    required this.method,
    required this.version,
    required this.path,
    this.queryParameters,
    this.body,
    this.contentType,
    this.additionalHeaders,
    required this.authentication,
    this.deduplication = DeduplicationPolicy.disabled,
    required this.responsePolicy,
    required this.operationId,
  }) : _unversioned = false;

  /// Erstellt einen Request direkt unterhalb des konfigurierten Alias, ohne
  /// ein `/v1`- oder `/v2`-Segment einzufügen.
  ///
  /// Diese Form ist ausschließlich für die historisch unversionierten
  /// DOCUframe-Routen wie `_CheckSession` und `_CheckService` vorgesehen.
  const ApiRequest.unversioned({
    required this.method,
    required this.path,
    this.body,
    this.contentType,
    this.additionalHeaders,
    required this.authentication,
    this.deduplication = DeduplicationPolicy.disabled,
    required this.responsePolicy,
    required this.operationId,
  }) : _unversioned = true,
       version = ApiVersion.v1,
       queryParameters = null;

  @override
  String toString() =>
      'ApiRequest(operationId: $operationId, method: $method, '
      'target: $target)';
}

/// Explizite Zielangabe eines Requests, unabhängig von [ApiRequest].
///
/// Dient als gemeinsame Eingabe für `MultiRequestEligibility.allows` und
/// `UriBuilder.buildTarget`:
///
/// - [ApiRequestTarget.versioned] - der normale Fall: Pfad relativ zum
///   `v1`/`v2`-Präfix (wie [ApiRequest.version]/[ApiRequest.path]).
/// - [ApiRequestTarget.unversioned] - ein Pfad direkt unter dem
///   konfigurierten Alias, OHNE ein `/v1`- oder `/v2`-Präfix zu
///   synthetisieren (z.B. `_CheckSession`/`_CheckService`:
///   `https://host:port/<alias>/_CheckSession`).
/// - [ApiRequestTarget.absolute] - eine vollständige, bereits fertige [Uri],
///   die byte-für-byte unverändert verwendet wird (z.B.
///   `checkServiceWithUri`).
///
/// Alle drei Varianten sind niemals Multi-Request-fähig, MIT AUSNAHME von
/// [ApiRequestTarget.versioned] - dort entscheidet `MultiRequestEligibility`
/// anhand von Version und Pfad.
@internal
sealed class ApiRequestTarget {
  const ApiRequestTarget._();

  /// Ein Pfad relativ zum `v1`/`v2`-Versions-Präfix (Normalfall).
  const factory ApiRequestTarget.versioned({
    required ApiVersion version,
    required String path,
  }) = VersionedApiRequestTarget;

  /// Ein Pfad direkt unter dem konfigurierten Alias, ohne synthetisiertes
  /// Versions-Präfix (z.B. `_CheckSession`/`_CheckService`).
  const factory ApiRequestTarget.unversioned(String path) =
      UnversionedApiRequestTarget;

  /// Eine vollständige, byte-für-byte zu verwendende [Uri].
  const factory ApiRequestTarget.absolute(Uri uri) = AbsoluteApiRequestTarget;
}

/// Siehe [ApiRequestTarget.versioned].
@internal
final class VersionedApiRequestTarget extends ApiRequestTarget {
  final ApiVersion version;
  final String path;

  const VersionedApiRequestTarget({required this.version, required this.path})
    : super._();

  @override
  String toString() =>
      'ApiRequestTarget.versioned(version: $version, path: $path)';
}

/// Siehe [ApiRequestTarget.unversioned].
@internal
final class UnversionedApiRequestTarget extends ApiRequestTarget {
  final String path;

  const UnversionedApiRequestTarget(this.path) : super._();

  @override
  String toString() => 'ApiRequestTarget.unversioned(path: $path)';
}

/// Siehe [ApiRequestTarget.absolute].
@internal
final class AbsoluteApiRequestTarget extends ApiRequestTarget {
  final Uri uri;

  const AbsoluteApiRequestTarget(this.uri) : super._();

  @override
  String toString() => 'ApiRequestTarget.absolute(uri: $uri)';
}
