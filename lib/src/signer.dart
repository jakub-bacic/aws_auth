import 'dart:convert';

import 'package:aws_auth/src/credentials_provider.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

import 'request.dart';
import 'utils.dart';

/// A signer that performs Signature Version 4 signing process.
///
/// Signer signs the requests for the provided [region] and [serviceName] with
/// given [credentialsProvider].
///
/// AWS docs: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
class AWS4Signer {
  static const String _ALGORITHM = 'AWS4-HMAC-SHA256';

  /// Credentials provider used for signing process.
  final AWSCredentialsProvider credentialsProvider;

  /// AWS region (e.g. us-east-1).
  final String region;

  /// AWS service name (e.g. sts).
  final String serviceName;

  /// Construct a new AWS4Signer instance.
  AWS4Signer(
    this.credentialsProvider, {
    required this.region,
    required this.serviceName,
  });

  /// Signs the given request by adding the signature to 'Authorization' header.
  ///
  /// Signing date can be overriden with [overrideDate].
  void sign(
    AWSRequest request, {
    DateTime? overrideDate,
  }) {
    _sign(request, overrideDate, null, true);
  }

  /// Presigns the given request by adding the signature to the URL.
  ///
  /// Time period, for which the generated presigned URL is valid
  /// is specified with [expires]. Minimum value is 1 second and
  /// maximum is 7 days.
  ///
  /// Signing date can be overriden with [overrideDate].
  ///
  /// Signing payload can be disabled by setting [signPayload] to `false`.
  /// It's enabled by default for all services except `s3`, unless implicitly
  /// overriden.
  ///
  /// **IMPORTANT**: Only GET requests can be presigned. In order to presign
  /// POST request with form-encoded body, it must be first transformed into
  /// the corresponding GET request (by moving body to query string).
  void presign(
    AWSRequest request, {
    Duration expires = const Duration(seconds: 60),
    bool? signPayload,
    DateTime? overrideDate,
  }) {
    assert(request.method == 'GET');
    assert(expires >= Duration(seconds: 1));
    assert(expires <= Duration(days: 7));

    signPayload ??= _shouldSignPayload(serviceName);

    _sign(request, overrideDate, expires, signPayload);
  }

  void _sign(
    AWSRequest request,
    DateTime? overrideDate,
    Duration? expires,
    bool signPayload,
  ) {
    var credentials = credentialsProvider.getCredentials();
    var isPresign = expires != null;

    var timestamp = overrideDate ?? DateTime.now().toUtc();
    var credentialsScope = _getCredentialsScope(region, serviceName, timestamp);
    var amzCredential = credentials.accessKeyId + '/' + credentialsScope;

    // add host header if it's missing
    if (!request.headers.containsKey('Host')) {
      request.headers['Host'] = request.url.host;
    }

    if (isPresign) {
      request.queryParameters.addAll({
        'X-Amz-Algorithm': _ALGORITHM,
        'X-Amz-Credential': amzCredential,
        'X-Amz-Date': formatDate(timestamp),
        'X-Amz-Expires': expires!.inSeconds.toString(),
        'X-Amz-SignedHeaders': request.getSignedHeaders(),
      });

      if (credentials.sessionToken != null) {
        request.queryParameters['X-Amz-Security-Token'] =
            credentials.sessionToken!;
      }
    } else {
      request.headers['X-Amz-Date'] = formatDate(timestamp);

      if (credentials.sessionToken != null) {
        request.headers['X-Amz-Security-Token'] = credentials.sessionToken!;
      }
    }

    var canonicalRequest =
        request.getCanonicalRequest(signPayload: signPayload);
    var hashedCanonicalRequest =
        sha256.convert(utf8.encode(canonicalRequest)).toString();
    var signature = _calculateSignature(credentials.secretAccessId,
        hashedCanonicalRequest, region, serviceName, timestamp);

    if (isPresign) {
      request.queryParameters['X-Amz-Signature'] = signature;
    } else {
      var authorizationHeader =
          _createAuthorizationHeader(amzCredential, request, signature);
      request.headers['Authorization'] = authorizationHeader;
    }
  }

  String _createAuthorizationHeader(
    String amzCredential,
    AWSRequest request,
    String signature,
  ) {
    var result = <String>[
      '$_ALGORITHM Credential=$amzCredential',
      'SignedHeaders=${request.getSignedHeaders()}',
      'Signature=$signature',
    ];
    return result.join(', ');
  }

  String _calculateSignature(
    String secretAccessKey,
    String hashedCanonicalRequest,
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    var derivedSigningKey = _deriveSigningKey(
      secretAccessKey,
      region,
      serviceName,
      timestamp,
    );
    var stringToSign = _calculateStringToSign(
      region,
      serviceName,
      hashedCanonicalRequest,
      timestamp,
    );
    var sig = hmac(derivedSigningKey, stringToSign.codeUnits);
    return hex.encode(sig);
  }

  List<int> _deriveSigningKey(
    String secretAccessKey,
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    final date = formatDate(timestamp, includeTime: false);

    final kSecret = 'AWS4' + secretAccessKey;
    final kDate = hmac(kSecret.codeUnits, date.codeUnits);
    final kRegion = hmac(kDate, region.codeUnits);
    final kService = hmac(kRegion, serviceName.codeUnits);
    final kSigning = hmac(kService, 'aws4_request'.codeUnits);

    return kSigning;
  }

  String _calculateStringToSign(
    String region,
    String serviceName,
    String hashedCanonicalRequest,
    DateTime timestamp,
  ) {
    var result = <String>[
      _ALGORITHM,
      formatDate(timestamp),
      _getCredentialsScope(region, serviceName, timestamp),
      hashedCanonicalRequest,
    ];
    return result.join('\n');
  }

  String _getCredentialsScope(
    String region,
    String serviceName,
    DateTime timestamp,
  ) {
    var result = <String>[
      formatDate(timestamp, includeTime: false),
      region,
      serviceName,
      'aws4_request'
    ];
    return result.join('/');
  }

  static bool _shouldSignPayload(String serviceName) {
    final name = serviceName.toLowerCase();
    return !['s3', 's3-object-lambda'].contains(name);
  }
}
