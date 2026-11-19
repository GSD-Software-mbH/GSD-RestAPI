/// Version der nativen DOCUframe-REST-API.
///
/// Wählt das URL-Präfix (`v1`/`v2`/`v3`) und - in den künftigen
/// Response-Pipelines (Task 4/5) - die versionsspezifische
/// Deserialisierung und Fehlerbehandlung.
enum GsdApiVersion {
  /// Bestehende, dokumentierte V1-API.
  v1,

  /// V2-API. Wird nativ nur noch für den verschlüsselten Login (`v2/login`)
  /// verwendet; darüber hinaus ausschließlich über `GsdRawApi` erreichbar.
  v2,

  /// Neue, native V3-API.
  v3,
}
