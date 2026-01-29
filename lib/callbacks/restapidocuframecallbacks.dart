part of '../gsd_restapi.dart';

/// Erweiterte Callback-Management-System für DOCUframe REST-API-Events
///
/// Diese Klasse erweitert RestApiCallbacks und verwaltet spezielle Callback-Funktionen
/// für DOCUframe-spezifische Events:
/// - Session-Management-Events (Anmeldung, Session-Änderungen)
/// - Authentifizierungs-Events (Login-Fehler, 2FA-Token)
/// - Lizenz- und Sicherheits-Events
/// - Zusätzlich zu den Basis-Events (Logging, HTTP-Metriken)
///
/// Die Klasse erweitert die Basis-Funktionalität um DOCUframe-spezifische
/// Event-Handler und bietet vollständige Event-Abdeckung für die Anwendung.
///
/// Vorteile:
/// - Zentrale Verwaltung aller DOCUframe-Event-Handler
/// - Typ-sichere Callback-Definitionen für spezielle Events
/// - Einfache Event-Registrierung und -Verwaltung
/// - Bessere Testbarkeit durch isolierte Event-Logik
/// - Flexible Event-Behandlung ohne Tight Coupling
class RestApiDOCUframeCallbacks extends RestApiCallbacks {
  /// Callback-Funktion für fehlende 2FA-Token
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, wenn während der
  /// Session-Erneuerung ein 2FA-Token erforderlich ist, aber fehlt.
  ///
  /// Die Funktion sollte ein gültiges 2FA-Token vom Benutzer anfordern
  /// und als String zurückgeben. Bei Abbruch oder Fehler sollte ein
  /// leerer String zurückgegeben werden.
  ///
  /// Returns: Future&lt;String&gt; mit dem 2FA-Token oder leerem String bei Abbruch
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onMissing2FAToken = () async {
  ///   // Zeige 2FA-Eingabedialog
  ///   String? token = await showTwoFactorDialog();
  ///   return token ?? "";
  /// };
  /// ```
  Future<String> Function()? onMissing2FAToken;

  /// Callback-Funktion für Lizenzfehler
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, wenn während der
  /// API-Kommunikation eine LicenseException auftritt. Dies kann passieren bei:
  /// - Abgelaufenen Lizenzen
  /// - Überschrittenen Benutzerlimits
  /// - Fehlenden Modul-Lizenzen
  ///
  /// Parameter: [e] - Die LicenseException mit Details zum Lizenzfehler
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onLicenseWrong = (LicenseException e) async {
  ///   showDialog(
  ///     context: context,
  ///     builder: (context) => AlertDialog(
  ///       title: Text("Lizenzfehler"),
  ///       content: Text("Lizenz ungültig: ${e.message}"),
  ///     ),
  ///   );
  /// };
  /// ```
  Future<void> Function(LicenseException e)? onLicenseWrong;

  /// Callback-Funktion für Session-ID-Änderungen
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, wenn sich die
  /// Session-ID des aktuellen Benutzers ändert. Dies passiert bei:
  /// - Erfolgreicher Anmeldung (neue Session-ID wird gesetzt)
  /// - Abmeldung (Session-ID wird geleert)
  /// - Automatischer Session-Erneuerung
  /// - Session-Ablauf oder -Invalidierung
  ///
  /// Parameter: [sessionId] - Die neue Session-ID (leer bei Abmeldung)
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onSessionIdChanged = (String sessionId) async {
  ///   if (sessionId.isEmpty) {
  ///     // Benutzer wurde abgemeldet
  ///     navigatorKey.currentState?.pushReplacementNamed('/login');
  ///   } else {
  ///     // Session-ID für Persistierung speichern
  ///     await prefs.setString('session_id', sessionId);
  ///   }
  /// };
  /// ```
  Future<void> Function(String sessionId)? onSessionIdChanged;

  /// Callback-Funktion für Authentifizierungsfehler
  ///
  /// Diese optionale Callback-Funktion wird aufgerufen, wenn während der
  /// Anmeldung eine UserAndPassWrongException auftritt. Dies passiert bei:
  /// - Falschem Benutzernamen oder Passwort
  /// - Deaktivierten Benutzerkonten
  /// - Fehlgeschlagener Authentifizierung
  /// - Abgelaufenen Passwörtern
  ///
  /// Parameter: [e] - Die UserAndPassWrongException mit Fehlerdetails
  ///
  /// Beispiel-Implementierung:
  /// ```dart
  /// callbacks.onUserAndPassWrong = (UserAndPassWrongException e) async {
  ///   ScaffoldMessenger.of(context).showSnackBar(
  ///     SnackBar(
  ///       content: Text("Anmeldung fehlgeschlagen: ${e.message}"),
  ///       backgroundColor: Colors.red,
  ///     ),
  ///   );
  /// };
  /// ```
  Future<void> Function(UserAndPassWrongException e)? onUserAndPassWrong;

  /// Erstellt ein neues RestApiCallbacks-System
  RestApiDOCUframeCallbacks({
    super.onLogMessage,
    super.onHttpMetricRecorded,
    this.onMissing2FAToken,
    this.onLicenseWrong,
    this.onSessionIdChanged,
    this.onUserAndPassWrong,
  });

  /// Löst das Session-ID-Changed-Event aus
  ///
  /// [sessionId] - Die neue Session-ID
  Future<void> triggerSessionIdChangedEvent(String sessionId) async {
    await onSessionIdChanged?.call(sessionId);
  }

  /// Löst das License-Wrong-Event aus
  ///
  /// [exception] - Die LicenseException
  Future<void> triggerLicenseWrongEvent(LicenseException exception) async {
    await onLicenseWrong?.call(exception);
  }

  /// Löst das User-And-Pass-Wrong-Event aus
  ///
  /// [exception] - Die UserAndPassWrongException
  Future<void> triggerUserAndPassWrongEvent(
    UserAndPassWrongException exception,
  ) async {
    await onUserAndPassWrong?.call(exception);
  }

  /// Löst das Missing-2FA-Token-Event aus
  ///
  /// Returns: Das 2FA-Token oder leerer String
  Future<String> triggerMissing2FATokenEvent() async {
    return await onMissing2FAToken?.call() ?? "";
  }

  /// Entfernt alle Callbacks
  @override
  void clearAllCallbacks() {
    super.clearAllCallbacks();

    onMissing2FAToken = null;
    onLicenseWrong = null;
    onSessionIdChanged = null;
    onUserAndPassWrong = null;
  }
}
