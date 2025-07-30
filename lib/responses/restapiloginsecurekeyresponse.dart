import 'dart:convert';

import 'package:restapi/responses/restapiresponse.dart';

class RestApiLoginSecureKeyResponse extends RestApiResponse {

  String key = "";

  RestApiLoginSecureKeyResponse(super._httpResponse) {
    var responseJson = jsonDecode(httpResponse.body);

    if (isOk) {
      if (!responseJson.containsKey("data")) {

        throw const FormatException("missing 'data' field in response body");
      } else {
        var dataJson = responseJson['data'];
        if (!dataJson.containsKey("key")) {

          throw const FormatException("missing 'data.key' field in response body");
        } else {
          key = dataJson['key'];
        }
      }
    }
  }
}
