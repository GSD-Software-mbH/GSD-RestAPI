import 'package:gsd_restapi/src/runtime/runtime_configuration.dart';
import 'package:meta/meta.dart';

/// Unveränderlicher Abzug der kontrolliert veränderbaren Runtime-Werte.
class GsdRuntimeSettings {
  /// Liest die Werte aus der internen [configuration].
  @internal
  GsdRuntimeSettings.fromConfiguration(RuntimeConfiguration configuration)
    : appNames = List<String>.unmodifiable(configuration.appNames),
      additionalAppNames = List<String>.unmodifiable(
        configuration.additionalAppNames,
      ),
      multiRequest = configuration.multiRequest,
      useBase64UrlParameter = configuration.useBase64UrlParameter,
      useFolderPathEncoding = configuration.useFolderPathEncoding,
      perPageCount = configuration.perPageCount,
      maxBufferSize = configuration.maxBufferSize,
      bufferFlushDelayMs = configuration.bufferFlushDelayMs;

  /// Liste der Anwendungsnamen.
  final List<String> appNames;

  /// Zusätzliche Anwendungsnamen.
  final List<String> additionalAppNames;

  /// Ob der Multi-Request-Modus aktiv ist.
  final bool multiRequest;

  /// Ob Base64-kodierte URL-Parameter verwendet werden.
  final bool useBase64UrlParameter;

  /// Ob die Ordnerpfad-Codierung verwendet wird.
  final bool useFolderPathEncoding;

  /// Anzahl der Elemente pro Seite bei paginierten Anfragen.
  final int perPageCount;

  /// Maximale Buffer-Größe vor automatischem Flush.
  final int maxBufferSize;

  /// Maximale Wartezeit in Millisekunden vor Flush.
  final int bufferFlushDelayMs;
}
