// ignore_for_file: deprecated_member_use_from_same_package

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:gsd_restapi/docuframe_api.dart';
import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:iso8601_duration/iso8601_duration.dart';

import '../legacy/legacy_test_server.dart';
import 'v1_test_support.dart';

void main() {
  final DateTime from = DateTime.utc(2026, 7, 20, 10, 30);
  final DateTime to = DateTime.utc(2026, 7, 20, 11, 45);
  final DateTime remindAt = DateTime.utc(2026, 7, 20, 10);
  const ISODuration remindBefore = ISODuration(minute: 15);

  late LegacyTestServer legacyServer;
  late RestApiDOCUframeManager legacy;
  late V1TestHarness native;

  setUp(() async {
    HttpOverrides.global = null;
    legacyServer = LegacyTestServer();
    await legacyServer.start();
    legacy = RestApiDOCUframeManager(
      config: buildLegacyConfig(
        legacyServer,
        sessionId: V1TestHarness.sessionId,
      ),
    );
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    legacyServer.fallback = success;
    native.server.fallback = success;
  });

  tearDown(() async {
    legacy.dispose();
    await legacyServer.close();
    await native.close();
  });

  final List<
    (
      String,
      Future<void> Function(RestApiDOCUframeManager),
      Future<void> Function(V1AppointmentsApi),
    )
  >
  cases =
      <
        (
          String,
          Future<void> Function(RestApiDOCUframeManager),
          Future<void> Function(V1AppointmentsApi),
        )
      >[
        (
          'getAppointments',
          (api) async {
            await api.getAppointments(
              from,
              to,
              username: 'demo',
              query: '',
              page: 2,
              perPage: 25,
            );
          },
          (api) async {
            await api.getAppointments(
              from,
              to,
              username: 'demo',
              query: '',
              page: 2,
              perPage: 25,
            );
          },
        ),
        (
          'postAppointments',
          (api) async {
            await api.postAppointments(
              from,
              to,
              title: 'Besprechung',
              place: 'Raum A',
              description: 'Planung',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: true,
              group: true,
              attendeesUserNames: <String>['alice'],
              attendeesAddresses: <String>['Adresse-1'],
              attendeesEmails: <String>['alice@example.test'],
              notificationComment: 'Bitte teilnehmen',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 2,
              occupancy: 1,
              rrule: 'FREQ=WEEKLY',
            );
          },
          (api) async {
            await api.postAppointments(
              from,
              to,
              title: 'Besprechung',
              place: 'Raum A',
              description: 'Planung',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: true,
              group: true,
              attendeesUserNames: <String>['alice'],
              attendeesAddresses: <String>['Adresse-1'],
              attendeesEmails: <String>['alice@example.test'],
              notificationComment: 'Bitte teilnehmen',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 2,
              occupancy: 1,
              rrule: 'FREQ=WEEKLY',
            );
          },
        ),
        (
          'postAppointmentsNextFreeDate',
          (api) async {
            await api.postAppointmentsNextFreeDate(
              from,
              to,
              DateTime.utc(2026, 7, 27),
              <String>['alice', 'bob'],
            );
          },
          (api) async {
            await api.postAppointmentsNextFreeDate(
              from,
              to,
              DateTime.utc(2026, 7, 27),
              <String>['alice', 'bob'],
            );
          },
        ),
        (
          'postAppointmentsInvitation',
          (api) async {
            await api.postAppointmentsInvitation(
              'appointment-1',
              'decline',
              true,
            );
          },
          (api) async {
            await api.postAppointmentsInvitation(
              'appointment-1',
              'decline',
              true,
            );
          },
        ),
        (
          'patchAppointmentsRemoveFromSeries',
          (api) async {
            await api.patchAppointmentsRemoveFromSeries('appointment-1', from);
          },
          (api) async {
            await api.patchAppointmentsRemoveFromSeries('appointment-1', from);
          },
        ),
        (
          'patchAppointmentsUpdateAppointment',
          (api) async {
            await api.patchAppointmentsUpdateAppointment(
              'appointment-1',
              from,
              to,
              title: 'Geändert',
              place: 'Raum B',
              description: 'Neue Planung',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: true,
              group: true,
              attendeesUserNames: <String>['bob'],
              attendeesAddresses: <String>['Adresse-2'],
              attendeesEmails: <String>['bob@example.test'],
              notificationComment: 'Aktualisiert',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 3,
              occupancy: 2,
              rrule: 'FREQ=DAILY',
            );
          },
          (api) async {
            await api.patchAppointmentsUpdateAppointment(
              'appointment-1',
              from,
              to,
              title: 'Geändert',
              place: 'Raum B',
              description: 'Neue Planung',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: true,
              group: true,
              attendeesUserNames: <String>['bob'],
              attendeesAddresses: <String>['Adresse-2'],
              attendeesEmails: <String>['bob@example.test'],
              notificationComment: 'Aktualisiert',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 3,
              occupancy: 2,
              rrule: 'FREQ=DAILY',
            );
          },
        ),
        (
          'patchAppointmentsCreateException',
          (api) async {
            await api.patchAppointmentsCreateException(
              'appointment-1',
              DateTime.utc(2026, 7, 27, 10, 30),
              from,
              to,
              title: 'Ausnahme',
              place: 'Raum C',
              description: 'Verschoben',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: false,
              group: true,
              attendeesUserNames: <String>['alice'],
              attendeesAddresses: <String>['Adresse-3'],
              attendeesEmails: <String>['alice@example.test'],
              notificationComment: 'Ausnahme',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 4,
              occupancy: 3,
              rrule: 'FREQ=MONTHLY',
            );
          },
          (api) async {
            await api.patchAppointmentsCreateException(
              'appointment-1',
              DateTime.utc(2026, 7, 27, 10, 30),
              from,
              to,
              title: 'Ausnahme',
              place: 'Raum C',
              description: 'Verschoben',
              owner: 'demo',
              remindBefore: remindBefore,
              remindAt: remindAt,
              wholeDay: false,
              group: true,
              attendeesUserNames: <String>['alice'],
              attendeesAddresses: <String>['Adresse-3'],
              attendeesEmails: <String>['alice@example.test'],
              notificationComment: 'Ausnahme',
              notifyAllAttendees: true,
              isSerial: true,
              public: true,
              extern: true,
              type: 4,
              occupancy: 3,
              rrule: 'FREQ=MONTHLY',
            );
          },
        ),
      ];

  for (final (name, callLegacy, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callLegacy(legacy);
      await callNative(native.api.v1.appointments);

      expect(legacyServer.requests, hasLength(1));
      expect(native.server.requests, hasLength(1));
      final RecordedRequest legacyRequest = legacyServer.requests.single;
      final RecordedRequest nativeRequest = native.server.requests.single;
      expect(nativeRequest.method, legacyRequest.method);
      expect(nativeRequest.path, legacyRequest.path);
      expect(nativeRequest.query, legacyRequest.query);
      expect(nativeRequest.body, legacyRequest.body);
      expect(
        nativeRequest.header('sessionid'),
        legacyRequest.header('sessionid'),
      );
      expect(nativeRequest.header('appkey'), legacyRequest.header('appkey'));
    });
  }

  test(
    'getAppointments übernimmt Pagination und feste Serialization',
    () async {
      await native.api.v1.appointments.getAppointments(from, to);

      expect(native.server.requests.single.query, <String, String>{
        'from': '2026-07-20T10:30:00.000Z',
        'to': '2026-07-20T11:45:00.000Z',
        'page': '0',
        'perPage': '50',
        'serialization': '{"type":"class","style":"preview"}',
      });
    },
  );

  test(
    'CreateException bewahrt den historischen group/wholeDay-Fehler',
    () async {
      await native.api.v1.appointments.patchAppointmentsCreateException(
        'appointment-1',
        from,
        from,
        to,
        group: true,
        wholeDay: false,
      );

      final Map<String, dynamic> body =
          jsonDecode(native.server.requests.single.body)
              as Map<String, dynamic>;
      expect(body['exceptionBody'], containsPair('group', false));
    },
  );
}
