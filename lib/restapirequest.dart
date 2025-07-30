import 'package:http/http.dart';

class RestApiRequest {

  Future<Response> response;
  bool login;

  RestApiRequest(this.response, {this.login = false});
}