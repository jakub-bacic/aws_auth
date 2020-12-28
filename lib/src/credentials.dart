/// Holds the credentials required for accessing AWS services.
class AWSCredentials {
  /// The AWS access key id part of the credentials.
  final String accessKeyId;

  /// The AWS secret access key part of the credentials.
  final String secretAccessId;

  /// The optional security token (valid only for session credentials).
  final String sessionToken;

  AWSCredentials(this.accessKeyId, this.secretAccessId, {this.sessionToken});
}
