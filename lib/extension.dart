import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:iso8601_duration/iso8601_duration.dart';

extension StringExtensions on String {
  String replaceParams(List<String> params) {
    var result = this;
    for (var i = 0; i < params.length; i++) {
      result = result.replaceAll('%${i + 1}', params[i]);
    }
    return result;
  }

  bool isMd5Hash() {
    final md5Regex = RegExp(r'^[a-fA-F0-9]{32}$');
    return md5Regex.hasMatch(this);
  }

  String toMd5Hash() {
    return md5.convert(utf8.encode(this)).toString();
  }

  int compareVersions(String v2) {
    List<String> parts1 = _splitVersion(this);
    List<String> parts2 = _splitVersion(v2);

    for (int i = 0; i < parts1.length; i++) {
      if (parts2.length <= i) {
        return 1; // this hat mehr Teile und ist daher grÃ¶ÃŸer
      }

      int comparison = _comparePart(parts1[i], parts2[i]);
      if (comparison != 0) {
        return comparison;
      }
    }

    // Wenn v1 alle Teile gleich hat, aber kÃ¼rzer ist als v2
    if (parts1.length < parts2.length) {
      return -1;
    }

    return 0; // Die Versionen sind gleich
  }
  
  List<String> _splitVersion(String version) {
    // Zerlege die Version in ihre Bestandteile
    RegExp regExp = RegExp(r'(\d+|\D+)');
    return regExp.allMatches(version).map((m) => m.group(0)!).toList();
  }

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

  Color fromHexToColor() {
    final buffer = StringBuffer();
    if (length == 6 || length == 7) buffer.write('ff');
    buffer.write(replaceFirst('#', ''));
    return Color(int.parse(buffer.toString(), radix: 16));
  }

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

extension IntExtensions on int {
  String getBytesString(int decimals) {
    if (this <= 0) return "0 B";
    const suffixes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
    var i = (log(this) / log(1024)).floor();
    return '${(this / pow(1024, i)).toStringAsFixed(decimals)} ${suffixes[i]}';
  }
}

extension ISODurationExtensions on ISODuration {
  String toFormatString({bool includeSeconds = false}) {
    if (day == 0) {
      return "${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
    }
    if (day == 0) {
      return "${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
    }
    return "${day}t ${hour}h ${minute}min${includeSeconds ? " ${seconds}s" : ""}";
  }

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

extension DateTimeExtention on DateTime {
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
