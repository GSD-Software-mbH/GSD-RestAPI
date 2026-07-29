# GSD-RestAPI Example

This example demonstrates both public architectures of the GSD RestAPI
package in the same Flutter interface. Use the selector at the top to switch
between the frozen legacy manager and the new `DOCUframeApi` facade.

## Features Demonstrated

- **Service Connection**: Check if the REST API service is available
- **Authentication**: Login with username and password hash
- **Session Management**: Check session validity and handle session changes
- **Event Handling**: Monitor authentication and session events
- **Error Handling**: Proper error handling for various scenarios
- **Architecture Comparison**: Legacy and new API with isolated clients and sessions
- **New Facade**: Native authentication and service checks through `api.v1`
- **Native V2 API**: All nine model, system, view, and object-data endpoints
- **Raw Escape Hatch**: Controlled access to customer-specific endpoints

## Getting Started

1. Make sure you have Flutter installed
2. Navigate to the example directory
3. Run `flutter pub get`
4. Run the app with `flutter run`
5. Select `Legacy` or `Neue API` and enter the connection data in the form

## Configuration

Before running the example, you need to configure:

1. **Server URL**: Enter your actual server URL in the form
2. **Credentials**: Enter the username, password, and app configuration
3. **SSL Settings**: Set `allowSslError` to `false` for production use

## Legacy Usage

```dart
// Initialize the API manager
final configuration = RestApiDOCUframeConfig(
  appKey: 'YourAppKey',
  userName: 'YourUsername',
  appNames: ['YourAppName'],
  serverUrl: 'https://your-server.com',
  alias: 'database_alias',
  allowSslError: false,
);
final apiManager = RestApiDOCUframeManager(
  config: configuration,
);

// Login
apiManager.setPassword('your_md5_password_hash');
final loginResponse = await apiManager.login('your_md5_password_hash');

if (loginResponse.isOk) {
  print('Login successful!');
}
```

## New API Usage

```dart
import 'package:gsd_restapi/docuframe_api.dart';

final api = DOCUframeApi(configuration: configuration);
final loginResponse = await api.v1.authentication.login(
  'your_md5_password_hash',
);

final service = await api.v1.service.checkService();
final session = await api.v1.authentication.checkSession();
final documents = await api.v1.objects.getObjects('Dokument');

// Keep the request body raw until the V2 DTO contracts are stable.
const payload = '{}';
final structure = await api.v2.model.structure(body: payload);
final versionInfo = await api.v2.system.versionInfo();
final view = await api.v2.view.load(body: payload);
final object = await api.v2.objectData.getById(body: payload);

// Use RawApi only for a customer-specific endpoint without a native group.
final custom = await api.raw.request(
  version: ApiVersion.v2,
  method: ApiHttpMethod.post,
  path: '/customer/action',
  body: '{"value":42}',
);

await api.v1.authentication.logout();
await api.dispose();
```

The new API view contains a **Native V2 Endpoints** panel. It exposes all nine
native V2 methods, accepts an optional JSON body for POST endpoints, and shows
the formatted server response. The controls are enabled after a successful
login. They never fall back to the legacy manager, `RawApi`, or `v1/multi`.

`Check Service` and `Check Session` use their native V1 groups in the new API
view. They do not route through the legacy manager.

## Security Notes

- Never hardcode passwords in production code
- Use proper secure storage for sensitive data
- Set `allowSslError` to `false` in production
- Always validate SSL certificates in production environments

## Troubleshooting

- If you get connection errors, check your server URL and network connectivity
- For SSL errors, verify your SSL certificate configuration
- Check the activity log in the app for detailed error messages
