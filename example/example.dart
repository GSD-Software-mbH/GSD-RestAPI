// Meldet sich an einem DOCUframe-Server an, liest die V3-Versionsinfo und
// meldet sich wieder ab.
//
// Die Zugangsdaten kommen aus Umgebungsvariablen:
//
//   GSD_SERVER_URL=https://server:8080 GSD_ALIAS=dfapp GSD_APP_KEY=… \
//   GSD_USER=… GSD_PASSWORD=… dart run example/example.dart
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:gsd_restapi/gsd_restapi.dart';

Future<void> main() async {
  final environment = Platform.environment;
  String require(String name) {
    final value = environment[name];
    if (value == null || value.isEmpty) {
      throw StateError('Umgebungsvariable $name fehlt.');
    }
    return value;
  }

  final api = GsdApiClient(
    configuration: GsdApiConfig(
      serverUrl: require('GSD_SERVER_URL'),
      alias: require('GSD_ALIAS'),
      appKey: require('GSD_APP_KEY'),
      userName: require('GSD_USER'),
      appNames: const ['GSD-RestApi'],
    ),
  );
  final sessionIds = api.sessionIdChanges.listen(
    (sessionId) => stdout.writeln('Session-ID geändert: $sessionId'),
  );

  try {
    // DOCUframe erwartet den MD5-Hash des Passworts.
    final password = md5.convert(utf8.encode(require('GSD_PASSWORD')));
    final login = await api.v1.authentication.login(password.toString());
    stdout.writeln('Angemeldet, Anwendungen: ${login.applications.length}');

    final versionInfo = await api.v3.system.versionInfo();
    stdout.writeln('Version: $versionInfo');

    await api.v1.authentication.logout();
  } on GsdApiException catch (error) {
    stderr.writeln('${error.runtimeType}: ${error.message}');
    exitCode = 1;
  } finally {
    await api.dispose();
    await sessionIds.cancel();
  }
}
