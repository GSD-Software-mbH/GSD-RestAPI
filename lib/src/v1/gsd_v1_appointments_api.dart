import 'dart:async';
import 'dart:convert';

import 'package:gsd_restapi/src/models/gsd_http_method.dart';
import 'package:gsd_restapi/src/runtime/api_runtime.dart';
import 'package:gsd_restapi/src/v1/extensions.dart';
import 'package:gsd_restapi/src/v1/v1_requester.dart';
import 'package:meta/meta.dart';

/// Native Terminoperationen der V1-Fassade.
class GsdV1AppointmentsApi {
  /// Interner Konstruktor für Subklassen.
  /// Nicht für öffentliche Verwendung bestimmt.
  @internal
  GsdV1AppointmentsApi.internal(this._runtime);
  late final V1Requester _requests = V1Requester(_runtime, 'appointments');

  final ApiRuntime _runtime;

  /// Ruft Termine aus einem bestimmten Zeitraum ab
  ///
  /// Lädt alle Termine zwischen den angegebenen Datumsangaben
  /// mit optionaler Filterung nach Benutzer und Suchtext.
  ///
  /// [from] - Startzeit für den Zeitraum
  /// [to] - Endzeit für den Zeitraum
  /// [username] - Name des Kalender-Besitzers (leer = aktueller Benutzer)
  /// [query] - Suchtext für Termine (optional)
  /// [page] - Seitenzahl für Paginierung (Standard: 0)
  /// [perPage] - Anzahl Termine pro Seite (Standard: aus Konfiguration)
  ///
  /// Returns: `data` der Antwort mit Termin-Liste und Metadaten
  ///
  /// Beispiel:
  /// ```dart
  /// DateTime start = DateTime.now();
  /// DateTime end = start.add(Duration(days: 7));
  /// final data = await api.v1.appointments.getAppointments(
  ///   start,
  ///   end,
  ///   username: "mueller",
  ///   query: "meeting"
  /// );
  /// ```
  Future<Object?> getAppointments(
    DateTime from,
    DateTime to, {
    String username = '',
    String? query,
    int page = 0,
    int? perPage,
  }) {
    final parameters = <String, String>{
      'from': from.toISOFormatString(),
      'to': to.toISOFormatString(),
      'page': page.toString(),
      'perPage': (perPage ?? _runtime.configuration.perPageCount).toString(),
    };
    if (username.isNotEmpty) parameters['username'] = username;
    if (query != null) parameters['queryString'] = query;
    parameters['serialization'] = '{"type":"class","style":"preview"}';
    return _requests.execute(
      method: GsdHttpMethod.get,
      path: '/appointments',
      queryParameters: parameters,
      operation: 'getAppointments',
    );
  }

  /// Erstellt einen neuen Termin im Kalender
  ///
  /// Legt einen neuen Kalendereintrag mit allen erforderlichen Informationen
  /// an.
  /// Unterstützt Teilnehmer, Erinnerungen, Terminserien und Benachrichtigungen.
  ///
  /// [from] - Startzeit des Termins
  /// [to] - Endzeit des Termins
  /// [title] - Titel des Termins
  /// [place] - Ort des Termins
  /// [description] - Beschreibung des Termins
  /// [owner] - Besitzer des Termins
  /// [remindBefore] - Erinnerung vor dem Termin; gesendet als ISO-8601-Dauer
  /// [remindAt] - Erinnerung zu bestimmter Zeit
  /// [wholeDay] - Ganztägiger Termin (Standard: false)
  /// [attendeesUserNames] - Liste der Teilnehmer-Benutzernamen
  /// [attendeesAddresses] - Liste der Teilnehmer-Adressen
  /// [attendeesEmails] - Liste der Teilnehmer-E-Mail-Adressen
  /// [isSerial] - Terminserie (Standard: false)
  /// [rrule] - Wiederholungsregel (iCalendar RRULE)
  ///
  /// Returns: `data` der Antwort mit Termin-ID und Erstellungsstatus
  ///
  /// Beispiel:
  /// ```dart
  /// final data = await api.v1.appointments.postAppointments(
  ///   DateTime.now().add(Duration(hours: 1)),
  ///   DateTime.now().add(Duration(hours: 2)),
  ///   title: "Team Meeting",
  ///   place: "Konferenzraum A",
  ///   attendeesUserNames: ["mueller", "schmidt"]
  /// );
  /// ```
  Future<Object?> postAppointments(
    DateTime from,
    DateTime to, {
    String title = '',
    String place = '',
    String description = '',
    String owner = '',
    Duration? remindBefore,
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = '',
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = '',
  }) {
    final body = <String, dynamic>{
      'from': from.toISOFormatString(),
      'to': to.toISOFormatString(),
      'title': title,
      'place': place,
      'description': description,
      'owner': owner,
    };
    if (remindBefore != null) {
      body['remindBefore'] = remindBefore.toISOFormatString();
    }
    if (remindAt != null) body['remindAt'] = remindAt.toISOFormatString();
    body['wholeDay'] = wholeDay;
    final attendees = _attendees(
      attendeesUserNames,
      attendeesAddresses,
      attendeesEmails,
      notificationComment,
      notifyAllAttendees,
    );
    if (attendees.isNotEmpty) body['attendees'] = attendees;
    if (type != null) body['type'] = type;
    if (occupancy != null) body['occupancy'] = occupancy;
    body['isSerial'] = isSerial;
    body['public'] = public;
    body['extern'] = extern;
    if (rrule.isNotEmpty) body['rrule'] = rrule;
    return _bodyRequest(
      GsdHttpMethod.post,
      '/appointments',
      'postAppointments',
      body,
    );
  }

  /// This request allows to find next free date with given duration
  ///
  /// [from] Appointment start
  ///
  /// [to] Appointment end
  ///
  /// [searchArea] end date for search
  ///
  /// [users] checks free dates in user calenders
  Future<Object?> postAppointmentsNextFreeDate(
    DateTime from,
    DateTime to,
    DateTime searchArea,
    List<String> users,
  ) {
    return _bodyRequest(
      GsdHttpMethod.post,
      '/appointments/nextFreeDate',
      'postAppointmentsNextFreeDate',
      <String, dynamic>{
        'from': from.toISOFormatString(),
        'to': to.toISOFormatString(),
        'searchArea': searchArea.toISOFormatString(),
        'users': users,
      },
    );
  }

  /// This request allows to reply to appointment invitation
  ///
  /// [id] OID or ~UUID of appointment or EMail appointment
  ///
  /// [action] (one of accept, tentative, decline) Possible actions for replying
  /// to appointments invitation
  ///
  /// [deleteAppointment] It allows to delete the appointment when the
  /// invitation is going to be declined
  Future<Object?> postAppointmentsInvitation(
    String id,
    String action,
    // Öffentliche Signatur; ein benannter Parameter bräche die Aufrufer.
    // ignore: avoid_positional_boolean_parameters
    bool deleteAppointment,
  ) {
    return _bodyRequest(
      GsdHttpMethod.post,
      '/appointments/$id/invitation/$action',
      'postAppointmentsInvitation',
      <String, dynamic>{'deleteAppointment': deleteAppointment},
    );
  }

  ///  This request allows to remove date from Termin series
  ///
  /// [id] OID or ~UUID of appointment (Termin series)
  ///
  /// [date] utc start date of the the appointment that gets deleted from Termin
  /// series
  Future<Object?> patchAppointmentsRemoveFromSeries(
    String id,
    DateTime date,
  ) {
    return _bodyRequest(
      GsdHttpMethod.patch,
      '/appointments/$id/removeFromSeries',
      'patchAppointmentsRemoveFromSeries',
      <String, dynamic>{'date': date.toISOFormatString()},
    );
  }

  /// This request allows to edit an appointment
  ///
  /// [id] OID or ~UUID of appointment
  /// [from] New UTC start date and time of the appointment
  /// [to] New UTC end date and time of the appointment
  /// [title] New appointment title
  /// [place] New appointment location
  /// [description] New appointment description
  /// [owner] User name of the appointment owner
  /// [remindBefore] Relative reminder interval
  /// [remindAt] Absolute reminder time
  /// [wholeDay] Whether the appointment spans the whole day
  /// [attendeesUserNames] DOCUframe user names to invite
  /// [attendeesAddresses] Address OIDs to invite
  /// [attendeesEmails] External email addresses to invite
  /// [notificationComment] Comment included in attendee notifications
  /// [notifyAllAttendees] Whether all attendees should be notified
  /// [isSerial] Whether this is a serial appointment
  /// [public] Whether the appointment is public
  /// [extern] Whether the appointment is external
  /// [type] Optional appointment type
  /// [occupancy] Optional occupancy state
  /// [rrule] Recurrence rule for serial appointments
  ///
  /// Returns: `data` der Antwort mit dem geänderten Termin
  Future<Object?> patchAppointmentsUpdateAppointment(
    String id,
    DateTime from,
    DateTime to, {
    String title = '',
    String place = '',
    String description = '',
    String owner = '',
    Duration? remindBefore,
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = '',
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = '',
  }) {
    final body = <String, dynamic>{
      'from': from.toISOFormatString(),
      'to': to.toISOFormatString(),
      'title': title,
      'place': place,
      'description': description,
      'owner': owner,
    };
    if (remindBefore != null && remindBefore != Duration.zero) {
      body['remindBefore'] = remindBefore.toISOFormatString();
    }
    if (remindAt != null) body['remindAt'] = remindAt.toISOFormatString();
    body['wholeDay'] = wholeDay;
    final attendees = _attendees(
      attendeesUserNames,
      attendeesAddresses,
      attendeesEmails,
      notificationComment,
      notifyAllAttendees,
    );
    if (attendees.isNotEmpty) body['attendees'] = attendees;
    body['isSerial'] = isSerial;
    body['public'] = public;
    body['extern'] = extern;
    if (type != null) body['type'] = type;
    if (occupancy != null) body['occupancy'] = occupancy;
    if (rrule.isNotEmpty) body['rrule'] = rrule;
    return _bodyRequest(
      GsdHttpMethod.patch,
      '/appointments/$id/updateAppointment',
      'patchAppointmentsUpdateAppointment',
      body,
    );
  }

  /// This request allows to create Termin series exception
  ///
  /// [id] OID or ~UUID of the Termin series appointment
  ///
  /// [exceptionFrom] start date of the appointment
  ///
  /// optional fields: new appointment data
  Future<Object?> patchAppointmentsCreateException(
    String id,
    DateTime exceptionFrom,
    DateTime from,
    DateTime to, {
    String title = '',
    String place = '',
    String description = '',
    String owner = '',
    Duration remindBefore = Duration.zero,
    DateTime? remindAt,
    bool wholeDay = false,
    bool group = false,
    List<String>? attendeesUserNames,
    List<String>? attendeesAddresses,
    List<String>? attendeesEmails,
    String notificationComment = '',
    bool notifyAllAttendees = false,
    bool isSerial = false,
    bool public = false,
    bool extern = false,
    int? type,
    int? occupancy,
    String rrule = '',
  }) {
    final exceptionBody = <String, dynamic>{
      'from': from.toISOFormatString(),
      'to': to.toISOFormatString(),
    };
    if (title.isNotEmpty) exceptionBody['title'] = title;
    if (place.isNotEmpty) exceptionBody['place'] = place;
    if (description.isNotEmpty) exceptionBody['description'] = description;
    if (owner.isNotEmpty) exceptionBody['owner'] = owner;
    if (remindBefore != Duration.zero) {
      exceptionBody['remindBefore'] = remindBefore.toISOFormatString();
    }
    if (remindAt != null) {
      exceptionBody['remindAt'] = remindAt.toISOFormatString();
    }
    if (wholeDay) exceptionBody['wholeDay'] = wholeDay;
    if (group) {
      // Bewusste Legacy-Parität: Das alte API schreibt hier wholeDay.
      exceptionBody['group'] = wholeDay;
    }
    final attendees = _attendees(
      attendeesUserNames,
      attendeesAddresses,
      attendeesEmails,
      notificationComment,
      notifyAllAttendees,
    );
    if (attendees.isNotEmpty) exceptionBody['attendees'] = attendees;
    if (isSerial) exceptionBody['isSerial'] = isSerial;
    exceptionBody['public'] = public;
    exceptionBody['extern'] = extern;
    if (type != null) exceptionBody['type'] = type;
    if (occupancy != null) exceptionBody['occupancy'] = occupancy;
    if (rrule.isNotEmpty) exceptionBody['rrule'] = rrule;
    return _bodyRequest(
      GsdHttpMethod.patch,
      '/appointments/$id/createException',
      'patchAppointmentsCreateException',
      <String, dynamic>{
        'exceptionFrom': exceptionFrom.toISOFormatString(),
        'exceptionBody': exceptionBody,
      },
    );
  }

  Map<String, dynamic> _attendees(
    List<String>? users,
    List<String>? addresses,
    List<String>? emails,
    String notificationComment,
    bool notifyAllAttendees,
  ) {
    final attendees = <String, dynamic>{};
    if (users != null) attendees['users'] = users;
    if (addresses != null) attendees['addresses'] = addresses;
    if (emails != null) attendees['emails'] = emails;
    if (notificationComment.isNotEmpty) {
      attendees['notificationComment'] = notificationComment;
    }
    if (notifyAllAttendees) {
      attendees['notifyAllAttendees'] = notifyAllAttendees;
    }
    return attendees;
  }

  Future<Object?> _bodyRequest(
    GsdHttpMethod method,
    String path,
    String operation,
    Map<String, dynamic> body,
  ) {
    return _requests.execute(
      method: method,
      path: path,
      body: jsonEncode(body),
      operation: operation,
    );
  }
}
