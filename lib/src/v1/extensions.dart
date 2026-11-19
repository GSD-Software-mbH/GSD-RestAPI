/// ISO-8601-Form einer [Duration] für die Termin-Endpunkte.
extension DurationIsoFormat on Duration {
  /// Die Dauer als ISO-8601-Dauer, etwa `P1D` oder `PT0H15M0S`.
  ///
  /// Tage stehen im Datumsteil, Stunden, Minuten und Sekunden im Zeitteil.
  /// Ist eines davon gesetzt, enthält der Zeitteil alle drei, auch mit `0`;
  /// das ist die Form, die die API bisher gesendet hat. Bruchteile von
  /// Sekunden fallen weg.
  String toISOFormatString() {
    final days = inDays;
    final hours = inHours % Duration.hoursPerDay;
    final minutes = inMinutes % Duration.minutesPerHour;
    final seconds = inSeconds % Duration.secondsPerMinute;

    final date = days > 0 ? '${days}D' : '';
    final hasTime = hours > 0 || minutes > 0 || seconds > 0;
    final time = hasTime ? 'T${hours}H${minutes}M${seconds}S' : '';

    return 'P$date$time';
  }
}

/// Extension für DateTime-Klasse mit ISO-Formatierung
///
/// Bietet Methoden zur Konvertierung von DateTime in ISO 8601 Format
/// für REST-API-Kompatibilität.
extension DateTimeExtention on DateTime {
  /// Konvertiert DateTime in ISO 8601 Format-String
  ///
  /// [utc] - Ob das Datum in UTC konvertiert werden soll (Standard: true)
  ///
  /// Returns: ISO 8601 formatierter DateTime-String
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime.now().toISOFormatString() // => "2024-01-01T12:00:00.000Z"
  /// ```
  String toISOFormatString({bool utc = true}) {
    var isoFormatedDT = '';

    if (microsecond > 0) {
      final noMicroseconds = subtract(Duration(microseconds: microsecond));
      isoFormatedDT = utc
          ? noMicroseconds.toUtc().toIso8601String()
          : noMicroseconds.toIso8601String();
    } else {
      isoFormatedDT = utc ? toUtc().toIso8601String() : toIso8601String();
    }

    return isoFormatedDT;
  }
}
