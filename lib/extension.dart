part of 'gsd_restapi.dart';

/// Extension für String-Klasse mit REST-API-spezifischen Hilfsmethoden
///
/// Bietet nützliche Funktionen für String-Manipulation, Validierung und Konvertierung
/// die häufig bei der Arbeit mit REST-APIs benötigt werden.
extension StringExtensions on String {
  /// Konvertiert den String in einen MD5-Hash
  ///
  /// Returns: MD5-Hash des Strings als hexadezimaler String
  String toMd5Hash() {
    return md5.convert(utf8.encode(this)).toString();
  }

  /// Überprüft, ob der String gültiges JSON enthält
  ///
  /// Returns: true wenn String gültiges JSON ist, sonst false
  bool isValidJson() {
    try {
      dynamic result = jsonDecode(this);

      if (result != null) {
        return true;
      }
    } catch (e) {
      return false;
    }

    return false;
  }
}

/// Extension für ISODuration-Klasse mit Formatierung
///
/// Bietet Methoden zur benutzerfreundlichen Darstellung von ISO-Dauern.
extension ISODurationExtensions on ISODuration {
  /// Konvertiert ISODuration in ISO 8601 Dauer-Format
  ///
  /// Returns: ISO 8601 formatierter Dauer-String (z.B. "P1DT2H30M")
  String toISOFormatString() {
    String result = "P";
    String dateformat = "";
    String timeformat = "T";
    bool hasDate = false;
    bool hasTime = false;

    if (year! > 0) {
      hasDate = true;
      dateformat += "${year}Y";
    }

    if (month! > 0) {
      hasDate = true;
      dateformat += "${month}M";
    }

    if (day! > 0) {
      hasDate = true;
      dateformat += "${day}D";
    }

    if (hour! > 0) {
      hasTime = true;
    }

    timeformat += "${hour}H";

    if (minute! > 0) {
      hasTime = true;
    }

    timeformat += "${minute}M";

    if (seconds! > 0) {
      hasTime = true;
    }

    timeformat += "${seconds}S";

    if (hasDate) {
      result += dateformat;
    }

    if (hasTime) {
      result += timeformat;
    }

    return result;
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
    String isoFormatedDT = "";

    if (microsecond > 0) {
      DateTime noMicroseconds = subtract(Duration(microseconds: microsecond));
      isoFormatedDT = utc
          ? noMicroseconds.toUtc().toIso8601String()
          : noMicroseconds.toIso8601String();
    } else {
      isoFormatedDT = utc ? toUtc().toIso8601String() : toIso8601String();
    }

    return isoFormatedDT;
  }
}
