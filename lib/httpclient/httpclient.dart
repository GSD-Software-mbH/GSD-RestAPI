import 'package:http/http.dart' as http;

import 'httpclientstub.dart'
  if (dart.library.io) 'httpclientio.dart'
  if (dart.library.html) 'httpclientweb.dart';

http.Client createClient(Duration connectionTimeout, {bool allowSslError = false}) => createPlatformClient(connectionTimeout, allowSslError: allowSslError);