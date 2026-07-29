import 'dart:convert';

import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/api_types.dart';

import '../api_request.dart';
import '../runtime_configuration.dart';

/// Baut vollständige Request-URIs nach dem Legacy-URL-Schema
/// `{serverUrlPfad}/{alias}/{v1|v2}/{endpunktPfad}?{query}`.
///
/// Verhalten:
/// - Ein leerer Alias entfernt das Alias-Segment vollständig.
/// - Der Endpunkt-Pfad darf mit oder ohne führenden `/` angegeben werden.
/// - Bei aktiviertem `useBase64UrlParameter` werden alle Query-Parameter zu
///   einem einzelnen `qb64`-Parameter kollabiert (siehe [encodeQb64]).
/// - Eine leere Query-Map erzeugt - anders als der Legacy-Manager - KEIN
///   angehängtes `?` (der Legacy-Trailing-`?`-Bug wird bewusst nicht
///   reproduziert).
@internal
class UriBuilder {
  /// Runtime-Konfiguration (Basis-URI, Alias, qb64-Modus).
  final RuntimeConfiguration configuration;

  const UriBuilder(this.configuration);

  /// Baut die vollständige Request-URI für [version], [path] und optionale
  /// [queryParameters].
  Uri build({
    required ApiVersion version,
    required String path,
    Map<String, String>? queryParameters,
  }) {
    final String normalizedPath = path.startsWith('/')
        ? path.substring(1)
        : path;
    final String aliasSegment = configuration.alias.isEmpty
        ? ''
        : '/${configuration.alias}';
    final String combinedPath =
        '${configuration.baseUri.path}$aliasSegment'
        '/${version.name}/$normalizedPath';

    // Leere Query-Map wie "keine Query" behandeln, damit kein trailing "?"
    // entsteht (Uri.replace mit leerer Map erzeugt "...pfad?").
    Map<String, String>? params =
        (queryParameters == null || queryParameters.isEmpty)
        ? null
        : queryParameters;

    if (params != null && configuration.useBase64UrlParameter) {
      params = {'qb64': encodeQb64(params)};
    }

    return configuration.baseUri.replace(
      path: combinedPath,
      queryParameters: params,
    );
  }

  /// Baut die Ziel-[Uri] für ein explizites [ApiRequestTarget].
  ///
  /// - [VersionedApiRequestTarget] entspricht [build] ohne Query-Parameter.
  /// - [UnversionedApiRequestTarget] hängt den Pfad direkt unter den
  ///   konfigurierten Alias, OHNE ein `/v1`- oder `/v2`-Präfix zu
  ///   synthetisieren (z.B. `_CheckSession`/`_CheckService`).
  /// - [AbsoluteApiRequestTarget] liefert die übergebene [Uri] byte-für-byte
  ///   unverändert zurück.
  Uri buildTarget({required ApiRequestTarget target}) {
    return switch (target) {
      VersionedApiRequestTarget(:final version, :final path) => build(
        version: version,
        path: path,
      ),
      UnversionedApiRequestTarget(:final path) => _buildUnversioned(path),
      AbsoluteApiRequestTarget(:final uri) => uri,
    };
  }

  Uri _buildUnversioned(String path) {
    final String normalizedPath = path.startsWith('/')
        ? path.substring(1)
        : path;
    final String aliasSegment = configuration.alias.isEmpty
        ? ''
        : '/${configuration.alias}';
    final String combinedPath =
        '${configuration.baseUri.path}$aliasSegment/$normalizedPath';

    return configuration.baseUri.replace(path: combinedPath);
  }

  /// Kodiert Query-Parameter im Legacy-`qb64`-Schema: Paare
  /// `schlüssel=Uri.encodeComponent(wert)` mit `&` verbunden, anschließend
  /// UTF-8- und Base64Url-kodiert (identisch zu `_getUri` im
  /// Legacy-Manager).
  static String encodeQb64(Map<String, String> params) {
    return base64Url.encode(
      utf8.encode(
        params.entries
            .map((e) => '${e.key}=${Uri.encodeComponent(e.value)}')
            .join('&'),
      ),
    );
  }
}
