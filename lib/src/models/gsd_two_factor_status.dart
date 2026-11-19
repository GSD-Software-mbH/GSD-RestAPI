import 'package:json_annotation/json_annotation.dart';

/// Enum für die verschiedenen 2FA (Zwei-Faktor-Authentifizierung) Status-Werte
///
/// Diese Enumeration definiert die möglichen Zustände der
/// Zwei-Faktor-Authentifizierung im REST-API-System. Jeder Status hat eine
/// eindeutige numerische ID, die auch auf dem Draht steht (`2faStatus`).
@JsonEnum(valueField: 'id')
enum GsdTwoFactorStatus {
  /// Nicht verfügbar - 2FA ist nicht verfügbar oder nicht unterstützt
  na(0),

  /// Deaktiviert - 2FA ist nicht verfügbar
  deactivated(1),

  /// Optional - 2FA ist verfügbar und kann vom Benutzer aktiviert werden
  optional(2),

  /// Erzwungen - 2FA ist vom System vorgeschrieben und muss verwendet werden
  forced(3);

  /// Erstellt eine neue GsdTwoFactorStatus-Instanz mit der angegebenen ID
  const GsdTwoFactorStatus(this.id);

  /// Die numerische ID des 2FA-Status
  final int id;
}
