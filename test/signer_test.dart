import 'package:aws_auth/aws_auth.dart';
import 'package:test/test.dart';

void main() {
  group('AWS4Signer', () {
    late AWSCredentials credentials;
    late AWS4Signer signer;
    late DateTime timestamp;

    setUp(() {
      credentials = AWSCredentials(
        'AKIDEXAMPLE',
        'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
      );
      signer = AWS4Signer(
        credentials,
        'us-east-1',
        'sts',
      );
      timestamp = DateTime(2020, 2, 1, 3, 4, 5);
    });

    test('Sign request (without overriding date)', () {
      var request = AWSRequest('https://sts.us-east-1.amazonaws.com');

      signer.sign(request);

      expect(request.headers.containsKey('Authorization'), isTrue);
    });

    test('Sign request', () {
      var request = AWSRequest.formData(
        'https://sts.us-east-1.amazonaws.com/',
        body: {
          'Action': 'GetCallerIdentity',
          'Version': '2011-06-15',
        },
      );

      signer.sign(request, overrideDate: timestamp);

      expect(
        request.headers['Authorization'],
        'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20200201/us-east-1/sts/aws4_request, '
        'SignedHeaders=content-type;host;x-amz-date, '
        'Signature=db2565ab5011184ab912c68a5328f84f8ce1eac33475b91e21922a149df75861',
      );
    });

    test('Presign request (without overriding date)', () {
      var request = AWSRequest('https://sts.us-east-1.amazonaws.com');

      signer.presign(request);

      expect(
          request.url.queryParameters.containsKey('X-Amz-Signature'), isTrue);
    });

    test('Presign request', () {
      var request = AWSRequest(
          'https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15');

      signer.presign(
        request,
        overrideDate: timestamp,
        expires: Duration(
          minutes: 2,
        ),
      );

      var queryParameters = request.url.queryParameters;
      expect(queryParameters['X-Amz-Algorithm'], 'AWS4-HMAC-SHA256');
      expect(queryParameters['X-Amz-Credential'],
          'AKIDEXAMPLE/20200201/us-east-1/sts/aws4_request');
      expect(queryParameters['X-Amz-Expires'], '120');
      expect(queryParameters['X-Amz-SignedHeaders'], 'host');
      expect(queryParameters['X-Amz-Signature'],
          '4cc6c14211d72207cb1bbe4cf6afd3ffbef5dcc1840e33eabc24c8bd0b5f83d8');
    });
  });

  group('AWS4Signer (with session token)', () {
    late AWSCredentials credentials;
    late AWS4Signer signer;
    late DateTime timestamp;

    setUp(() {
      credentials = AWSCredentials(
          'AKIDEXAMPLE', 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
          sessionToken: 'token');
      signer = AWS4Signer(
        credentials,
        'us-east-1',
        'sts',
      );
      timestamp = DateTime(2020, 2, 1, 3, 4, 5);
    });

    test('Sign request (without overriding date)', () {
      var request = AWSRequest('https://sts.us-east-1.amazonaws.com');

      signer.sign(request);

      expect(request.headers.containsKey('Authorization'), isTrue);
    });

    test('Sign request', () {
      var request = AWSRequest.formData(
        'https://sts.us-east-1.amazonaws.com/',
        body: {
          'Action': 'GetCallerIdentity',
          'Version': '2011-06-15',
        },
      );

      signer.sign(request, overrideDate: timestamp);

      expect(
        request.headers['Authorization'],
        'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20200201/us-east-1/sts/aws4_request, '
        'SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, '
        'Signature=166413101b3018b24ee9ab38e628d661bc29cee3e38815f5ec4ef93200e1f217',
      );
      expect(request.headers['X-Amz-Security-Token'], 'token');
    });

    test('Presign request (without overriding date)', () {
      var request = AWSRequest('https://sts.us-east-1.amazonaws.com');

      signer.presign(request);

      expect(
          request.url.queryParameters.containsKey('X-Amz-Signature'), isTrue);
    });

    test('Presign request', () {
      var request = AWSRequest(
          'https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15');

      signer.presign(
        request,
        overrideDate: timestamp,
        expires: Duration(
          minutes: 2,
        ),
      );

      var queryParameters = request.url.queryParameters;
      expect(queryParameters['X-Amz-Algorithm'], 'AWS4-HMAC-SHA256');
      expect(queryParameters['X-Amz-Credential'],
          'AKIDEXAMPLE/20200201/us-east-1/sts/aws4_request');
      expect(queryParameters['X-Amz-Expires'], '120');
      expect(queryParameters['X-Amz-SignedHeaders'], 'host');
      expect(queryParameters['X-Amz-Signature'],
          '5e886dffbc783ba9463cf7e49e15a60598dac5e6a0185264b5322362944d1552');
      expect(queryParameters['X-Amz-Security-Token'], 'token');
    });
  });
}
