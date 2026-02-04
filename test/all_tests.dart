import 'package:flutter_test/flutter_test.dart';

// Import aller Test-Dateien
import 'config/restapi_config_test.dart' as config_tests;
import 'config/restapi_docuframe_config_test.dart' as docuframe_config_tests;
import 'callbacks/restapi_callbacks_test.dart' as callbacks_tests;
import 'callbacks/restapi_docuframe_callbacks_test.dart'
    as docuframe_callbacks_tests;

void main() {
  group('GSD RestAPI Library Tests', () {
    group('Config Tests', () {
      config_tests.main();
      docuframe_config_tests.main();
    });

    group('Callbacks Tests', () {
      callbacks_tests.main();
      docuframe_callbacks_tests.main();
    });
  });
}
