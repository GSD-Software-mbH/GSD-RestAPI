import 'package:equatable/equatable.dart';
import 'package:gsd_restapi/src/models/gsd_two_factor_status.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_two_factor_secret.g.dart';

/// 2FA-Zustand eines Benutzers für eine Anwendung, das Ergebnis von
/// `v1.authentication.get2FASecret`.
///
/// Fehlende Werte gelten als „nichts eingerichtet“.
@JsonSerializable(createToJson: false)
class GsdTwoFactorSecret extends Equatable {
  /// Erstellt einen 2FA-Zustand.
  const GsdTwoFactorSecret({
    this.isActivated = false,
    this.isConfirmed = false,
    this.status = GsdTwoFactorStatus.na,
  });

  /// Liest den Zustand aus `data`.
  factory GsdTwoFactorSecret.fromJson(Map<String, Object?> json) =>
      _$GsdTwoFactorSecretFromJson(json);

  /// Ob 2FA für den Benutzer aktiviert ist.
  @JsonKey(defaultValue: false)
  final bool isActivated;

  /// Ob der Benutzer die Einrichtung bestätigt hat.
  @JsonKey(defaultValue: false)
  final bool isConfirmed;

  /// Was der Server für die Anwendung vorgibt; ein unbekannter Wert ergibt
  /// [GsdTwoFactorStatus.na].
  @JsonKey(
    name: '2faStatus',
    defaultValue: GsdTwoFactorStatus.na,
    unknownEnumValue: GsdTwoFactorStatus.na,
  )
  final GsdTwoFactorStatus status;

  @override
  List<Object?> get props => [isActivated, isConfirmed, status];
}
