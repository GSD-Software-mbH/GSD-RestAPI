import 'package:gsd_restapi/src/models/gsd_api_version.dart';
import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/policies/authentication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/deduplication_policy.dart';
import 'package:gsd_restapi/src/runtime/policies/response_policy.dart';
import 'package:meta/meta.dart';

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
/// ApiRequest<GsdRawApiResponse>(
///   method: GsdHttpMethod.get,
///   version: GsdApiVersion.v3,
///   path: '/model/structure',
///   authentication: AuthenticationPolicy.session,
///   responsePolicy: RawSessionAwareResponsePolicy(),
///   operationId: 'v3.model.structure',
/// );
/// ```
@internal
class ApiRequest<T> {
  const ApiRequest({
    required this.method,
    required this.version,
    required this.path,
    required this.authentication,
    required this.responsePolicy,
    required this.operationId,
    this.queryParameters,
    this.body,
    this.contentType,
    this.additionalHeaders,
    this.deduplication = DeduplicationPolicy.disabled,
  }) : _unversioned = false;

  /// Erstellt einen Request direkt unterhalb des konfigurierten Alias, ohne
  /// ein Versions-Segment (siehe [GsdApiVersion]) einzufügen.
  ///
  /// Diese Form ist ausschließlich für die historisch unversionierten
  /// DOCUframe-Routen wie `_CheckSession` und `_CheckService` vorgesehen.
  const ApiRequest.unversioned({
    required this.method,
    required this.path,
    required this.authentication,
    required this.responsePolicy,
    required this.operationId,
    this.body,
    this.contentType,
    this.additionalHeaders,
    this.deduplication = DeduplicationPolicy.disabled,
  }) : _unversioned = true,
       version = GsdApiVersion.v1,
       queryParameters = null;

  /// Ob der Pfad direkt unter dem Alias statt unter dem Versions-Präfix liegt.
  final bool _unversioned;

  /// Explizites Request-Ziel. Normale Requests sind versioniert;
  /// `_CheckSession` und `_CheckService` verwenden ein unversioniertes Ziel.
  ApiRequestTarget get target => _unversioned
      ? ApiRequestTarget.unversioned(path)
      : ApiRequestTarget.versioned(version: version, path: path);

  /// HTTP-Methode der Anfrage.
  final GsdHttpMethod method;

  /// API-Version, die das Versions-Präfix der URL bestimmt.
  final GsdApiVersion version;

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
  /// `IResponsePolicy`-Instanz, greift die Deduplizierung STILL und OHNE
  /// FEHLER nie. Für wirksames Dedup muss dieselbe (z.B. `const`) Instanz
  /// wiederverwendet werden.
  final DeduplicationPolicy deduplication;

  /// Übersetzt die Transport-Antwort in das Ergebnis vom Typ [T].
  final IResponsePolicy<T> responsePolicy;

  /// Eindeutige, stabile Operations-ID für Logging und Metriken
  /// (z.B. `v3.model.structure`).
  final String operationId;

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
///   Versions-Präfix (wie [ApiRequest.version]/[ApiRequest.path]).
/// - [ApiRequestTarget.unversioned] - ein Pfad direkt unter dem
///   konfigurierten Alias, OHNE ein Versions-Präfix zu synthetisieren
///   (z.B. `_CheckSession`/`_CheckService`:
///   `https://host:port/<alias>/_CheckSession`); nie Multi-Request-fähig.
///
/// Für [ApiRequestTarget.versioned] entscheidet `MultiRequestEligibility`
/// anhand von Version und Pfad. Absolute Ziele (`checkServiceWithUri`) laufen
/// nicht über [ApiRequest], sondern über `ApiRuntime.executeAbsoluteGet`.
@internal
sealed class ApiRequestTarget {
  const ApiRequestTarget._();

  /// Ein Pfad relativ zum Versions-Präfix der [GsdApiVersion] (Normalfall).
  const factory ApiRequestTarget.versioned({
    required GsdApiVersion version,
    required String path,
  }) = VersionedApiRequestTarget;

  /// Ein Pfad direkt unter dem konfigurierten Alias, ohne synthetisiertes
  /// Versions-Präfix (z.B. `_CheckSession`/`_CheckService`).
  const factory ApiRequestTarget.unversioned(String path) =
      UnversionedApiRequestTarget;
}

/// Siehe [ApiRequestTarget.versioned].
@internal
final class VersionedApiRequestTarget extends ApiRequestTarget {
  const VersionedApiRequestTarget({required this.version, required this.path})
    : super._();
  final GsdApiVersion version;
  final String path;

  @override
  String toString() =>
      'ApiRequestTarget.versioned(version: $version, path: $path)';
}

/// Siehe [ApiRequestTarget.unversioned].
@internal
final class UnversionedApiRequestTarget extends ApiRequestTarget {
  const UnversionedApiRequestTarget(this.path) : super._();
  final String path;

  @override
  String toString() => 'ApiRequestTarget.unversioned(path: $path)';
}
