part of '../docuframe_api.dart';

/// Öffentliche Management-Oberfläche der gruppierten DOCUframe-API.
///
/// Sie ersetzt die frei veränderlichen Management-Felder des Legacy-Managers
/// durch klar begrenzte Lifecycle- und Konfigurationsoperationen.
class DocuframeManagementApi {
  final ApiRuntime _runtime;

  /// Effektive Callback-Instanz des Runtimes. Ihre Handler können auch nach
  /// dem Erzeugen der API gesetzt, ersetzt oder mit `clearAllCallbacks()`
  /// entfernt werden.
  final RestApiDOCUframeCallbacks callbacks;

  @internal
  DocuframeManagementApi.internal(this._runtime, this.callbacks);

  /// Ob mindestens ein logischer API-Aufruf noch nicht abgeschlossen ist.
  bool get hasPendingRequests => _runtime.hasPendingRequests;

  /// Anzahl der aktuell offenen logischen API-Aufrufe.
  int get pendingRequestCount => _runtime.pendingRequestCount;

  /// Ob die API bereits freigegeben wurde.
  bool get isDisposed => _runtime.isDisposed;

  /// Aktuell für Login und Demo-Account verwendetes Gerät. Der bestehende
  /// Legacy-Typ ist selbst veränderlich; ein vollständiger Austausch erfolgt
  /// kontrolliert über [setDevice].
  RestApiDevice? get device => _runtime.configuration.device;

  /// Wartet, bis alle aktuell laufenden API-Aufrufe abgeschlossen sind.
  Future<void> waitForIdle() => _runtime.waitForIdle();

  /// Liefert eine unveränderliche Momentaufnahme der zur Laufzeit
  /// veränderbaren Einstellungen.
  DocuframeRuntimeSettings get runtimeSettings =>
      DocuframeRuntimeSettings._(_runtime.configuration);

  /// Ändert ausschließlich unterstützte Runtime-Werte. `null` bedeutet
  /// jeweils "unverändert"; mit einer leeren Liste lassen sich App-Namen
  /// bewusst leeren. Änderungen sind nur im Idle-Zustand erlaubt.
  void updateRuntimeSettings({
    List<String>? appNames,
    List<String>? additionalAppNames,
    bool? multiRequest,
    bool? useBase64UrlParameter,
    bool? useFolderPathEncoding,
    int? perPageCount,
    int? maxBufferSize,
    int? bufferFlushDelayMs,
  }) {
    _runtime.updateRuntimeSettings(
      appNames: appNames,
      additionalAppNames: additionalAppNames,
      multiRequest: multiRequest,
      useBase64UrlParameter: useBase64UrlParameter,
      useFolderPathEncoding: useFolderPathEncoding,
      perPageCount: perPageCount,
      maxBufferSize: maxBufferSize,
      bufferFlushDelayMs: bufferFlushDelayMs,
    );
  }

  /// Ersetzt oder entfernt (`null`) das bei Login und Demo-Account verwendete
  /// Gerät. Die Änderung ist wie alle Runtime-Änderungen nur idle erlaubt.
  void setDevice(RestApiDevice? device) {
    _runtime.setDevice(device);
  }
}

/// Unveränderlicher Abzug der kontrolliert veränderbaren Runtime-Werte.
class DocuframeRuntimeSettings {
  final List<String> appNames;
  final List<String> additionalAppNames;
  final bool multiRequest;
  final bool useBase64UrlParameter;
  final bool useFolderPathEncoding;
  final int perPageCount;
  final int maxBufferSize;
  final int bufferFlushDelayMs;

  DocuframeRuntimeSettings._(RuntimeConfiguration configuration)
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
}
