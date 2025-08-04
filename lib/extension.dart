part of 'restapi.dart';

/// Extension für String-Klasse mit REST-API-spezifischen Hilfsmethoden
/// 
/// Bietet nützliche Funktionen für String-Manipulation, Validierung und Konvertierung
/// die häufig bei der Arbeit mit REST-APIs benötigt werden.
extension StringExtensions on String {
  /// Ersetzt Platzhalter in einem String mit gegebenen Parametern
  /// 
  /// Platzhalter haben das Format %1, %2, %3, etc.
  /// 
  /// [params] - Liste der Werte, die die Platzhalter ersetzen sollen
  /// 
  /// Returns: String mit ersetzten Platzhaltern
  /// 
  /// Beispiel:
  /// ```dart
  /// "Hallo %1, du bist %2 Jahre alt".replaceParams(["Max", "25"])
  /// // => "Hallo Max, du bist 25 Jahre alt"
  /// ```
  String replaceParams(List<String> params) {
    var result = this;
    for (var i = 0; i < params.length; i++) {
      result = result.replaceAll('%${i + 1}', params[i]);
    }
    return result;
  }

  /// Überprüft, ob der String ein gültiger MD5-Hash ist
  /// 
  /// Ein MD5-Hash besteht aus 32 hexadezimalen Zeichen (0-9, a-f, A-F).
  /// 
  /// Returns: true wenn String ein gültiger MD5-Hash ist, sonst false
  bool isMd5Hash() {
    final md5Regex = RegExp(r'^[a-fA-F0-9]{32}$');
    return md5Regex.hasMatch(this);
  }

  /// Konvertiert den String in einen MD5-Hash
  /// 
  /// Returns: MD5-Hash des Strings als hexadezimaler String
  String toMd5Hash() {
    return md5.convert(utf8.encode(this)).toString();
  }

  /// Vergleicht zwei Versionsnummern
  /// 
  /// [v2] - Die zu vergleichende Version
  /// 
  /// Returns: 
  /// - Negativ wenn diese Version kleiner ist als v2
  /// - 0 wenn beide Versionen gleich sind  
  /// - Positiv wenn diese Version größer ist als v2
  /// 
  /// Beispiel:
  /// ```dart
  /// "1.2.3".compareVersions("1.2.4") // => -1
  /// "2.0.0".compareVersions("1.9.9") // => 1
  /// ```
  int compareVersions(String v2) {
    List<String> parts1 = _splitVersion(this);
    List<String> parts2 = _splitVersion(v2);

    for (int i = 0; i < parts1.length; i++) {
      if (parts2.length <= i) {
        return 1; // this hat mehr Teile und ist daher größer
      }

      int comparison = _comparePart(parts1[i], parts2[i]);
      if (comparison != 0) {
        return comparison;
      }
    }

    // Wenn v1 alle Teile gleich hat, aber kürzer ist als v2
    if (parts1.length < parts2.length) {
      return -1;
    }

    return 0; // Die Versionen sind gleich
  }
  
  /// Zerlegt eine Versionsnummer in ihre Bestandteile
  /// 
  /// [version] - Die zu zerlegende Version
  /// 
  /// Returns: Liste der Versionsbestandteile
  List<String> _splitVersion(String version) {
    // Zerlege die Version in ihre Bestandteile
    RegExp regExp = RegExp(r'(\d+|\D+)');
    return regExp.allMatches(version).map((m) => m.group(0)!).toList();
  }

  /// Vergleicht zwei Versionsteile
  /// 
  /// Numerische Teile werden numerisch verglichen, andere lexikalisch.
  /// 
  /// [part1] - Erster Versionsteil
  /// [part2] - Zweiter Versionsteil
  /// 
  /// Returns: Vergleichsergebnis (-1, 0, 1)
  int _comparePart(String part1, String part2) {
    // Vergleiche numerische Teile numerisch und andere Teile lexikalisch
    int? num1 = int.tryParse(part1);
    int? num2 = int.tryParse(part2);

    if (num1 != null && num2 != null) {
      return num1.compareTo(num2);
    } else {
      return part1.compareTo(part2);
    }
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

  /// Konvertiert einen Hex-Farbcode in eine Flutter Color
  /// 
  /// Unterstützt sowohl 6-stellige (#RRGGBB) als auch 7-stellige (#RRGGBB) Formate.
  /// Fügt automatisch Alpha-Kanal (ff) hinzu wenn nicht vorhanden.
  /// 
  /// Returns: Flutter Color-Objekt
  /// 
  /// Beispiel:
  /// ```dart
  /// "#FF0000".fromHexToColor() // => Rote Farbe
  /// "00FF00".fromHexToColor()  // => Grüne Farbe
  /// ```
  Color fromHexToColor() {
    final buffer = StringBuffer();
    if (length == 6 || length == 7) buffer.write('ff');
    buffer.write(replaceFirst('#', ''));
    return Color(int.parse(buffer.toString(), radix: 16));
  }

  /// Konvertiert Unicode-Escape-Sequenzen in normale Zeichen
  /// 
  /// Behandelt sowohl Unicode-Escape-Sequenzen (\uXXXX) als auch
  /// Standard-Escape-Sequenzen (\n, \r, \t, \b, \f).
  /// 
  /// Returns: String mit konvertierten Zeichen
  String convertFromUnicode() {
    return replaceAllMapped(
            RegExp(r'\\u([0-9A-Fa-f]{4})'), (Match match) => String.fromCharCode(int.parse(match.group(1)!, radix: 16)))
        // Ersetzt bekannte Escape-Sequenzen wie \n, \r und \t
        .replaceAllMapped(RegExp(r'(?<!\\)\\n'), (_) => '\n')
        .replaceAllMapped(RegExp(r'(?<!\\)\\r'), (_) => '\r')
        .replaceAllMapped(RegExp(r'(?<!\\)\\t'), (_) => '\t')
        .replaceAllMapped(RegExp(r'(?<!\\)\\b'), (_) => '\b')
        .replaceAllMapped(RegExp(r'(?<!\\)\\f'), (_) => '\f')
        .replaceAll(r'\\', '\\');
  }
}

/// Extension für int-Klasse mit Byte-Formatierung
/// 
/// Bietet Hilfsmethoden für die Darstellung von Byte-Größen in lesbarer Form.
extension IntExtensions on int {
  /// Konvertiert Byte-Anzahl in lesbaren String
  /// 
  /// [decimals] - Anzahl der Dezimalstellen in der Ausgabe
  /// 
  /// Returns: Formatierter String mit Byte-Einheit (B, KB, MB, GB, etc.)
  /// 
  /// Beispiel:
  /// ```dart
  /// 1024.getBytesString(1) // => "1.0 KB"
  /// 1048576.getBytesString(2) // => "1.00 MB"
  /// ```
  String getBytesString(int decimals) {
    if (this <= 0) return "0 B";
    const suffixes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    var i = (math.log(this) / math.log(1024)).floor();
    return '${(this / math.pow(1024, i)).toStringAsFixed(decimals)} ${suffixes[i]}';
  }
}

/// Extension für ISODuration-Klasse mit Formatierung
/// 
/// Bietet Methoden zur benutzerfreundlichen Darstellung von ISO-Dauern.
extension ISODurationExtensions on ISODuration {
  /// Konvertiert ISODuration in lesbaren String
  /// 
  /// [includeSeconds] - Ob Sekunden in der Ausgabe enthalten sein sollen
  /// 
  /// Returns: Formatierter Dauer-String
  /// 
  /// Beispiel:
  /// ```dart
  /// duration.toFormatString() // => "2h 30min"
  /// duration.toFormatString(includeSeconds: true) // => "2h 30min 45s"
  /// ```
  String toFormatString({bool includeSeconds = false}) {
    if (day == 0) {
      return "${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
    }
    if (day == 0) {
      return "${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
    }
    return "${day}t ${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
  }

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
      isoFormatedDT = utc ? noMicroseconds.toUtc().toIso8601String() : noMicroseconds.toIso8601String();
    } else {
      isoFormatedDT = utc ? toUtc().toIso8601String() : toIso8601String();
    }

    return isoFormatedDT;
  }
}
