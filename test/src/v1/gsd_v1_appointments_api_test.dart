@TestOn('vm')
library;

import 'dart:convert';

import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

import '../../helpers/test_server.dart';
import 'v1_test_support.dart';

void main() {
  final from = DateTime.utc(2026, 7, 20, 10, 30);
  final to = DateTime.utc(2026, 7, 20, 11, 45);
  final remindAt = DateTime.utc(2026, 7, 20, 10);
  const remindBefore = Duration(minutes: 15);

  late V1TestHarness native;

  setUp(() async {
    native = await V1TestHarness.start();

    ScriptedResponse success(RecordedRequest _) => ScriptedResponse(
      jsonEncode(TestServer.v1Envelope(data: <String, dynamic>{'ok': true})),
    );
    native.server.fallback = success;
  });

  tearDown(() async {
    await native.close();
  });

  final cases = <(String, Future<void> Function(GsdV1AppointmentsApi))>[
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
    ),
    (
      'patchAppointmentsRemoveFromSeries',
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

  for (final (name, callNative) in cases) {
    test('$name entspricht dem beobachteten Legacy-Wire-Vertrag', () async {
      await callNative(native.api.v1.appointments);

      expect(native.server.requests, hasLength(1));
      native.expectLegacyWire(
        'appointments.$name',
        native.server.requests.single,
      );
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
      );

      final body =
          jsonDecode(native.server.requests.single.body)
              as Map<String, dynamic>;
      expect(body['exceptionBody'], containsPair('group', false));
    },
  );
}
