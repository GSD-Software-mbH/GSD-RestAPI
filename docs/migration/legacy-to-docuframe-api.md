# Migration vom Legacy-Manager zu `DOCUframeApi`

Dieser Guide beschreibt die Migration von `RestApiDOCUframeManager` zur
gruppierten `DOCUframeApi`. Ziel ist nicht nur ein Umbenennen von Methoden,
sondern genau eine neue API-Instanz pro fachlichem Session-Flow, mit gemeinsamem
Sessionzustand, Buffering, Telemetrie und Lifecycle.

## Voraussetzungen

- Die verwendete Package-Version muss die vollständigen 14 V1-Gruppen sowie
  `api.management` enthalten.
- Bei einer Git-Abhängigkeit reicht ein geänderter Branch-Ref nicht immer aus:
  den tatsächlich aufgelösten Commit in `pubspec.lock` kontrollieren und bei
  Bedarf `flutter pub upgrade gsd_restapi` ausführen.
- Legacy-Manager und `DOCUframeApi` nicht innerhalb desselben fachlichen Flows
  mischen. Beide besitzen sonst getrennte Clients, Sessions und Request-Buffer.

## 1. Import und Instanz ersetzen

Vorher:

```dart
import 'package:gsd_restapi/gsd_restapi.dart';

final manager = RestApiDOCUframeManager(
  config: configuration,
  callbacks: callbacks,
);
```

Nachher:

```dart
import 'package:gsd_restapi/docuframe_api.dart';

final api = DOCUframeApi(
  configuration: configuration,
  callbacks: callbacks,
);
```

`docuframe_api.dart` exportiert die gemeinsamen Config-, Callback-, Response-,
Exception-, Upload- und Modelltypen weiter. Nur Legacy-Manager und interne
Legacy-Requesttypen werden ausgeblendet.

## 2. Endpunkte ihrer Gruppe zuordnen

Methodennamen, Parameter, Defaults und Rückgabetypen der nativen V1-Endpunkte
bleiben erhalten. Ergänzt wird nur die fachliche Gruppe:

| Legacy-Aufruf | Neue Gruppe |
| --- | --- |
| Login, Logout, Session-Check, 2FA | `api.v1.authentication` |
| Service-Check, Version, Lizenzfreigabe | `api.v1.service` |
| Ordner | `api.v1.folders` |
| Dateien, Previews, Dokumentstatus, Upload | `api.v1.documents` |
| Objekte, Aktionen, Locks, Rechte | `api.v1.objects` |
| Persönliche Dokumente und Papierkorb | `api.v1.personal` |
| Termine | `api.v1.appointments` |
| Sync, Interface-/Print-Makros, Anrufe | `api.v1.integrations` |
| E-Mail | `api.v1.mail` |
| Nachrichten | `api.v1.messages` |
| Modellstruktur und Wörterbücher | `api.v1.models` |
| Benutzer-/Systemeinstellungen | `api.v1.settings` |
| Demo-Account | `api.v1.account` |
| Personalzeiterfassung | `api.v1.timeRecording` |

Beispiele:

```dart
await manager.getObject(oid, serialization: serialization);
await manager.postMailSend(to: recipients, subject: subject);
await manager.getPZEWorkingTimeAccounts(employeeOid: employeeOid);
```

wird zu:

```dart
await api.v1.objects.getObject(oid, serialization: serialization);
await api.v1.mail.postMailSend(to: recipients, subject: subject);
await api.v1.timeRecording.getPZEWorkingTimeAccounts(
  employeeOid: employeeOid,
);
```

## 3. Login und persistierte Sessions

Ein normaler Login bleibt nahezu identisch:

```dart
final RestApiLoginResponse login = await api.v1.authentication.login(
  md5Password,
  twoFactorAuthToken: token,
);
```

Für eine bereits persistierte Session gibt es zwei Varianten.

Wenn `sessionId` bereits in der Konstruktor-Konfiguration steht:

```dart
final api = DOCUframeApi(configuration: configurationWithSessionId);
api.v1.authentication.setPassword(md5Password);
```

Oder Session und Credentials nach der Erzeugung atomar wiederherstellen:

```dart
api.v1.authentication.restoreSession(
  persistedSessionId,
  md5Password: md5Password,
);
```

Damit kann bereits der erste Request bei einer abgelaufenen Session denselben
automatischen Refresh wie nach einem regulären Login ausführen. Ein leerer
Passwortwert deaktiviert die automatische Wiederanmeldung.

Im Session-Callback immer den übergebenen Wert oder `api.sessionId` verwenden:

```dart
Future<void> onSessionChanged(String sessionId) async {
  account.setCurrentSessionId(sessionId);
  await saveAccount();
}
```

## 4. Öffentliche Management-Oberfläche

Die neue API legt keinen frei veränderlichen `config`- oder
`pendingResponses`-Zustand offen. Die Entsprechungen befinden sich unter
`api.management`:

| Legacy | Neue API |
| --- | --- |
| `manager.callbacks` | `api.management.callbacks` |
| `manager.pendingResponses.isNotEmpty` | `api.management.hasPendingRequests` |
| auf leere Pending-Map pollen | `await api.management.waitForIdle()` |
| `manager.loggedIn` | `api.isAuthenticated` |
| `manager.config.sessionId` | `api.sessionId` |
| `manager.config.appNames` | `api.management.runtimeSettings.appNames` |
| `manager.config.additionalAppNames` | `api.management.runtimeSettings.additionalAppNames` |
| `manager.config.multiRequest` | `api.management.runtimeSettings.multiRequest` |
| `manager.config.perPageCount` | `api.management.runtimeSettings.perPageCount` |
| `manager.config.device` | `api.management.device` |

Unterstützte Werte werden nur im Idle-Zustand geändert:

```dart
await api.management.waitForIdle();

api.management.updateRuntimeSettings(
  appNames: <String>['GSD-DFApp'],
  additionalAppNames: <String>['LicensedModule'],
  multiRequest: true,
  useBase64UrlParameter: true,
  useFolderPathEncoding: true,
  perPageCount: 100,
  maxBufferSize: 10,
  bufferFlushDelayMs: 100,
);

api.management.setDevice(updatedDevice); // `null` entfernt das Gerät.
```

Server, Alias, App-Key, Benutzer, SSL-Verhalten und Timeouts sind an den
Transport gebunden. Für Änderungen an diesen Werten eine neue API-Instanz
erzeugen. Logging und Metriken werden über Callbacks beobachtet, nicht durch
direkten Zugriff auf einen internen Runtime-Schalter.

## 5. Priority und Buffering

Die Zone-basierten Aufrufe bleiben auf der Fassade:

```dart
await api.executeWithoutBuffering(
  () => api.v1.folders.getFolderByOid(folderOid),
);

await api.executeWithPriority(
  () => api.v1.objects.getObjects('Dokument'),
  RequestPriority.low,
);
```

Scopes müssen die vollständige asynchrone Aktion umschließen. Schreibende,
Login-, Service-, Upload-, Raw- und V2-Requests laufen unabhängig davon direkt,
wenn sie technisch nicht Multi-Request-fähig sind.

## 6. `customRequest` durch `RawApi` ersetzen

Vorher:

```dart
final http.Response response = await manager.customRequest(
  HttpMethod.post,
  'v1/Abwesenheitsantrag/$oid/$action',
);
```

Nachher:

```dart
final RawApiResponse response = await api.raw.request(
  version: ApiVersion.v1,
  method: ApiHttpMethod.post,
  path: '/Abwesenheitsantrag/$oid/$action',
);

if (response.statusCode == 200) {
  // Erfolgsbehandlung
}
```

Wichtig:

- Version nicht mehr in `path` schreiben.
- `RawApiResponse` statt `http.Response` verwenden.
- Raw ist für kundenspezifische oder noch nicht native Endpunkte gedacht.
- Wiederholt genutzte fachliche Endpunkte sollten als native, typisierte
  Methode ergänzt werden.

## 7. Absoluten Service-Check migrieren

`checkServiceWithUri` ist in der neuen Struktur eine Instanzmethode. Für einen
Verbindungscheck vor dem eigentlichen Account-Login eine kurzlebige API
verwenden:

```dart
Future<RestApiCheckServiceResponse> checkServiceUri(Uri uri) async {
  final probeApi = DOCUframeApi(
    configuration: RestApiDOCUframeConfig(
      appKey: '',
      userName: '',
      appNames: <String>[],
      serverUrl: '${uri.scheme}://${uri.authority}',
      alias: '',
    ),
  );

  try {
    return await probeApi.v1.service.checkServiceWithUri(uri);
  } finally {
    await probeApi.dispose();
  }
}
```

Der absolute Request wird exakt an die angegebene URI, ohne App-/Sessionheader,
gesendet.

## 8. Uploads und externe Hilfspakete

Direkte Uploads werden gruppiert aufgerufen:

```dart
final RestAPIFileUploadController controller =
    await api.v1.documents.uploadFileWithController(file);
final RestApiResponse result = await controller.result;
```

Hilfspakete, deren Konstruktor ausdrücklich einen
`RestApiDOCUframeManager` verlangt, sind nicht mit `DOCUframeApi` typkompatibel.
Diese Hilfen müssen auf `V1DocumentsApi` oder besser auf eine injizierte
Upload-Funktion umgestellt werden. Keinen zweiten Legacy-Manager nur für den
Upload erzeugen: Er würde einen getrennten Sessionzustand verwenden.

## 9. Zweite oder temporäre API-Instanzen

Separate fachliche Sessions, beispielsweise für das Erstellen eines
Demo-Accounts, erhalten bewusst eine eigene `DOCUframeApi`:

```dart
final demoApi = DOCUframeApi(configuration: demoConfiguration);
try {
  await demoApi.v1.authentication.login(servicePasswordMd5);
  return await demoApi.v1.account.createDemoAccount(password);
} finally {
  try {
    await demoApi.v1.authentication.logout();
  } finally {
    await demoApi.dispose();
  }
}
```

## 10. Lifecycle

`dispose()` ist asynchron und idempotent. Es beendet lokale Runtime-Ressourcen,
führt aber bewusst keinen Server-Logout aus:

```dart
try {
  await api.v1.authentication.logout();
} finally {
  await api.dispose();
}
```

Jede erzeugte Haupt-, Demo- oder Probe-Instanz muss freigegeben werden.

## Empfohlene Reihenfolge für `docuframeapp-flutter`

1. Package-Commit aktualisieren und sicherstellen, dass `DOCUframeApi`, alle
   14 V1-Gruppen und `api.management` aufgelöst werden.
2. Den zentralen Typ in `DOCUframeSession` auf `DOCUframeApi` umstellen.
3. Alle 67 genutzten Endpunkte mit dem jeweiligen Gruppenpräfix versehen.
4. Login-/Lizenzfluss auf `setPassword`, `restoreSession` und
   `updateRuntimeSettings` umstellen.
5. `pendingResponses` durch `waitForIdle()` ersetzen.
6. Den Abwesenheitsantrag über `api.raw` senden.
7. Den statischen Account-Servicecheck auf eine kurzlebige Probe-API umstellen.
8. `DOCUframeUploadManager` aktualisieren oder durch direkte
   `api.v1.documents`-Aufrufe ersetzen.
9. Haupt-, Demo- und Probe-API zuverlässig disposen.
10. Erst danach Legacy-Manager-Imports entfernen.

## Abschlussprüfung

```shell
flutter analyze
flutter test
```

Zusätzlich prüfen:

- kein `RestApiDOCUframeManager` mehr im Anwendungscode,
- kein `manager.customRequest`,
- keine direkten `manager.config`-Zugriffe,
- keine Nutzung von `pendingResponses`,
- jede erzeugte `DOCUframeApi` wird freigegeben,
- Login, wiederhergestellte Session, Session-Refresh, 2FA, Lizenzwechsel,
  Multi-Request, Raw-Workflow, Upload und Demo-Account sind getestet.
