import 'credentials.dart';

/// An interface for providing AWS credentials instance.
///
/// Method `getCredentials` will be called by `AWS4Signer` class every time
/// it signs a request. Classes implementing this interface can utilize that
/// fact to refresh the credentials if necessary.
///
/// See `AWSStaticCredentialsProvider` for sample implementation.
abstract class AWSCredentialsProvider {
  /// Returns credentials instance or throws an exception.
  AWSCredentials getCredentials();
}

/// Simple provider implementation returning credentials instance
/// set programmatically that never changes.
class AWSStaticCredentialsProvider implements AWSCredentialsProvider {
  /// The AWS access key id part of the credentials.
  final String accessKeyId;

  /// The AWS secret access key part of the credentials.
  final String secretAccessId;

  /// The optional security token (valid only for session credentials).
  final String? sessionToken;

  /// Construct a new AWSStaticCredentialsProvider instance.
  AWSStaticCredentialsProvider(
    this.accessKeyId,
    this.secretAccessId, {
    this.sessionToken,
  });

  @override
  AWSCredentials getCredentials() {
    return AWSCredentials(
      accessKeyId,
      secretAccessId,
      sessionToken: sessionToken,
    );
  }
}
