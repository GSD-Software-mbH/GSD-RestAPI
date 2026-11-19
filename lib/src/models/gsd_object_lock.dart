import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

part 'gsd_object_lock.g.dart';

/// Sperrzustand eines Objekts, das Ergebnis von `v1.objects.getLockObject`.
///
/// Eine Sperre verhindert, dass mehrere Benutzer dasselbe Objekt zugleich
/// bearbeiten.
@JsonSerializable(createToJson: false)
class GsdObjectLock extends Equatable {
  /// Erstellt einen Sperrzustand.
  const GsdObjectLock({required this.isLocked, this.messages = const []});

  /// Liest den Sperrzustand aus `data`; Pflicht ist `isLocked`.
  factory GsdObjectLock.fromJson(Map<String, Object?> json) =>
      _$GsdObjectLockFromJson(json);

  /// Ob das Objekt gesperrt ist.
  final bool isLocked;

  /// Meldungen zur Sperre, etwa wer sie seit wann hält; `null`-Einträge
  /// fallen weg.
  @JsonKey(fromJson: _messagesFromJson)
  final List<String> messages;

  @override
  List<Object?> get props => [isLocked, messages];

  static List<String> _messagesFromJson(Object? json) => [
    for (final (index, message)
        in ((json as List<Object?>?) ?? const <Object?>[]).indexed)
      if (message is String)
        message
      else if (message != null)
        throw CheckedFromJsonException(
          const <String, Object?>{},
          'messages[$index]',
          'GsdObjectLock',
          'kein String',
        ),
  ];
}
