import 'package:meta/meta.dart';

import 'package:gsd_restapi/raw/api_types.dart';

import '../api_request.dart';

/// Einzige Quelle darüber, ob ein Endpunkt grundsätzlich in einen
/// `v1/multi`-Request eintreten darf.
///
/// Native Endpoints deklarieren ihre Multi-Eignung NICHT mehr selbst (siehe
/// `ApiRequest`) - stattdessen entscheidet diese zentrale Klasse ANHAND DES
/// [ApiRequestTarget] abschließend, ob überhaupt gepuffert werden darf. Ein
/// No-Buffer-Zone-Scope (`RuntimeExecutionContext.runWithoutBuffering`) kann
/// Buffering danach zusätzlich abschalten, aber NIE einen hier
/// ausgeschlossenen Endpunkt bufferbar machen.
///
/// Ausgeschlossen sind:
/// - [ApiRequestTarget.absolute] - externe/absolute Ziele sind nie relativ
///   zum konfigurierten Multi-Endpunkt adressierbar.
/// - [ApiRequestTarget.unversioned] - `_CheckSession`/`_CheckService` sind
///   die einzigen unversionierten Routen und laufen immer direkt.
/// - [ApiRequestTarget.versioned] mit: `_CheckSession`/`_CheckService` (auch
///   wenn ein Aufrufer sie fälschlich versioniert anfragt), jeder
///   `ApiVersion.v2`-Pfad, `v1/logout`, `v1/xSync` (Präfix, siehe unten),
///   `v1/uploadFile`, `v1/file/...` und `v1/preview/...` (Multipart-/
///   Binär-Downloads/-Uploads).
///
/// `/xSync` wird per PRÄFIX geprüft (`/xSync` oder `/xSync/...`), NICHT per
/// Exact-Match: Der Legacy-Manager verglich exakt `/v1/xSync`, was auf reale
/// Pfade wie `/v1/xSync/ClassInfo/App1` nie zutraf - dieser Bug wird hier
/// bewusst NICHT kopiert. Ähnlich benannte, aber andere Pfade wie
/// `/xSyncArchive/...` bleiben davon unberührt (kein Präfix-Treffer, da kein
/// `/` unmittelbar nach `xSync` folgt).
///
/// Raw-Ausführungen (`RawApi`) werden NICHT über diese Klasse ausgeschlossen
/// - sie laufen stattdessen immer über eine interne No-Buffer-Runtime-Grenze
/// (`RuntimeExecutionContext.runWithoutBuffering`), da derselbe Pfad über
/// einen nativen Endpoint durchaus multi-fähig sein kann.
@internal
abstract final class MultiRequestEligibility {
  static bool allows({required ApiRequestTarget target}) {
    return switch (target) {
      AbsoluteApiRequestTarget() => false,
      UnversionedApiRequestTarget() => false,
      VersionedApiRequestTarget(:final version, :final path) =>
        _allowsVersioned(version, path),
    };
  }

  static bool _allowsVersioned(ApiVersion version, String path) {
    final String normalizedPath = _normalize(path);

    if (normalizedPath == '/_CheckSession' ||
        normalizedPath == '/_CheckService') {
      return false;
    }

    if (version == ApiVersion.v2) {
      return false;
    }

    if (normalizedPath == '/logout') {
      return false;
    }
    if (normalizedPath == '/xSync' || normalizedPath.startsWith('/xSync/')) {
      return false;
    }
    if (normalizedPath == '/uploadFile' ||
        normalizedPath.startsWith('/uploadFile/')) {
      return false;
    }
    if (normalizedPath == '/file' || normalizedPath.startsWith('/file/')) {
      return false;
    }
    if (normalizedPath == '/preview' ||
        normalizedPath.startsWith('/preview/')) {
      return false;
    }

    return true;
  }

  static String _normalize(String path) {
    final String withoutQuery = path.split('?').first.split('#').first;
    return withoutQuery.startsWith('/') ? withoutQuery : '/$withoutQuery';
  }
}
