import 'dart:convert';

import 'package:iso8601_duration/iso8601_duration.dart';
import 'package:restapi/responses/restapiresponse.dart';

/// class for login rest-api responses
class RestApiUserSystemSettingsResponse extends RestApiResponse {

  bool autoDocReadOnOpen = false;
  bool noPromptInsertNewDocsUserFolders = false;
  bool noPromptInsertNewDocsGlobalFolders = false;
  ISODuration dateDefaultReminderTimeSpan = ISODuration(minute: 5);
  int userRights = 0;
  int nextNewDocumentsCount = 0;

  /// Creates a [RestApiLoginResponse] object
  ///
  /// Throws a [FormatException] if the response body is missing the 'data.sessionId' field.
  RestApiUserSystemSettingsResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {
        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];

        autoDocReadOnOpen = dataJson['autoDocReadOnOpen'] ?? false;
        noPromptInsertNewDocsUserFolders = dataJson['noPromptInsertNewDocsUserFolders'] ?? false;
        noPromptInsertNewDocsGlobalFolders = dataJson['noPromptInsertNewDocsGlobalFolders'] ?? false;

        if(dataJson['dateDefaultReminderTimeSpan'] != null) {
          dateDefaultReminderTimeSpan = ISODurationConverter().parseString(isoDurationString: dataJson['dateDefaultReminderTimeSpan']);
        }

        userRights = dataJson['userRights'] ?? 0;
        nextNewDocumentsCount = dataJson['nextNewDocumentsCount'] ?? 0;
      }
    }
  }
}
