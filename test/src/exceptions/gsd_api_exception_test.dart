import 'package:gsd_restapi/gsd_restapi.dart';
import 'package:test/test.dart';

/// Ohne `default`: Kompiliert nur, solange der `switch` über die
/// `sealed`-Basis erschöpfend ist.
String _kind(GsdApiException error) => switch (error) {
  GsdHttpException() => 'http',
  GsdParseException() => 'parse',
  GsdSecurityException() => 'security',
  GsdUploadCancelledException() => 'cancelled',
  GsdServerException() => 'server',
};

void main() {
  group('GsdApiException', () {
    final cases = <GsdApiException, String>{
      const GsdHttpException('m', 503): 'http',
      GsdParseException(operationId: 'op', path: 'data'): 'parse',
      const GsdSecurityException('m'): 'security',
      const GsdUploadCancelledException(): 'cancelled',
      const GsdServerException(
        internalStatus: '999',
        statusMessage: 's',
        message: 'm',
      ): 'server',
      const GsdSessionInvalidException(
        internalStatus: '201',
        statusMessage: '',
      ): 'server',
      const GsdSessionMissingException(
        internalStatus: '204',
        statusMessage: '',
      ): 'server',
      const GsdInvalidCredentialsException(
        internalStatus: '302',
        statusMessage: '',
      ): 'server',
      const GsdLicenseException(internalStatus: '306', statusMessage: ''):
          'server',
      const GsdTwoFactorRequiredException(
        internalStatus: '340',
        statusMessage: '',
      ): 'server',
      const GsdTwoFactorTokenMissingException(
        internalStatus: '341',
        statusMessage: '',
      ): 'server',
      const GsdTwoFactorTokenInvalidException(
        internalStatus: '342',
        statusMessage: '',
      ): 'server',
    };
    for (final MapEntry(key: error, value: kind) in cases.entries) {
      test('${error.runtimeType} ist $kind', () {
        expect(_kind(error), kind);
      });
    }

    test('GsdParseException ist keine GsdServerException', () {
      expect(
        GsdParseException(operationId: 'op', path: ''),
        isNot(isA<GsdServerException>()),
      );
    });

    test('Untertypen von GsdServerException übernehmen die Felder', () {
      const error = GsdSessionInvalidException(
        internalStatus: '201',
        statusMessage: 'abgelaufen',
      );

      expect(error.message, isEmpty);
      expect(error.internalStatus, '201');
      expect(error.statusMessage, 'abgelaufen');
    });

    test('GsdServerException.toString nennt Status und Nachricht', () {
      expect(
        const GsdLicenseException(
          internalStatus: '306',
          statusMessage: 'abgelaufen',
          message: 'm',
        ).toString(),
        '306: abgelaufen',
      );
    });

    test('GsdParseException nennt Endpunkt und Stelle', () {
      final error = GsdParseException(
        operationId: 'v1.login',
        path: 'data.sessionId',
      );

      expect(error.message, contains('v1.login'));
      expect(error.message, contains('data.sessionId'));
      expect(error.toString(), startsWith('GsdParseException: '));
    });

    test('GsdUploadCancelledException hat eine Standardnachricht', () {
      expect(const GsdUploadCancelledException().message, 'Upload cancelled');
    });
  });
}
