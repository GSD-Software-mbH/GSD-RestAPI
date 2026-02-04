# GSD-RestAPI Example

This example demonstrates how to use the GSD RestAPI package in a Flutter application.

## Features Demonstrated

- **Service Connection**: Check if the REST API service is available
- **Authentication**: Login with username and password hash
- **Session Management**: Check session validity and handle session changes
- **Event Handling**: Monitor authentication and session events
- **Error Handling**: Proper error handling for various scenarios

## Getting Started

1. Make sure you have Flutter installed
2. Navigate to the example directory
3. Run `flutter pub get`
4. Update the server URL in `lib/main.dart` to point to your REST API server
5. Run the app with `flutter run`

## Configuration

Before running the example, you need to configure:

1. **Server URL**: Replace `'https://demo.example.com'` with your actual server URL
2. **Credentials**: Update the username, password hash, and app configuration
3. **SSL Settings**: Set `allowSslError` to `false` for production use

## Example Usage

```dart
// Initialize the API manager
final apiManager = RestApiDOCUframeManager(
  'YourAppKey',
  'YourUsername', 
  ['YourAppNames'],
  'https://your-server.com',
  'database_alias',
  allowSslError: false, // Set to false in production
);

// Login
apiManager.setPassword('your_md5_password_hash');
final loginResponse = await apiManager.login('your_md5_password_hash');

if (loginResponse.isOk) {
  print('Login successful!');
}
```

## Security Notes

- Never hardcode passwords in production code
- Use proper secure storage for sensitive data
- Set `allowSslError` to `false` in production
- Always validate SSL certificates in production environments

## Troubleshooting

- If you get connection errors, check your server URL and network connectivity
- For SSL errors, verify your SSL certificate configuration
- Check the activity log in the app for detailed error messages
