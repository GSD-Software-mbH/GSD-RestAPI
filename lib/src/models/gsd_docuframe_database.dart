import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_docuframe_module.dart';

/// Eine Datenbank des DOCUframe-Service mit ihren Modulen.
///
/// Wird verwendet von:
/// - `GsdCheckServiceResult` zur Service-Status-Überprüfung
/// - Kompatibilitätsprüfungen zwischen Client und Server
/// - Modul-Versions-Management
class GsdDocuframeDatabase extends Equatable {
  /// Erstellt eine Datenbank [name] mit den Modulen [modules].
  const GsdDocuframeDatabase(this.name, this.modules);

  /// Name/Alias der Datenbank
  ///
  /// Eindeutige Identifikation der Datenbank, wird in API-Aufrufen
  /// als Pfad-Parameter verwendet (z.B. "/dbname/v1/login").
  final String name;

  /// Liste der in dieser Datenbank verfügbaren Module
  ///
  /// Jedes Modul enthält Name und Versionsinformationen,
  /// die für Funktionskompatibilität wichtig sind.
  final List<GsdDocuframeModule> modules;

  @override
  List<Object?> get props => [name, modules];
}
