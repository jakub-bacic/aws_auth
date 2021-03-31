import 'package:aws_auth/aws_auth.dart';

AWSRequest createPresignGetCallerIdentityRequest(
  AWS4Signer signer,
  Duration expires,
) {
  // create request
  final req = AWSRequest(
    'https://sts.${signer.region}.amazonaws.com/',
    queryParameters: {
      'Action': 'GetCallerIdentity',
      'Version': '2011-06-15',
    },
  );

  // presign the request
  signer.presign(req, expires: expires);

  return req;
}

AWSRequest createGetCallerIdentityRequest(AWS4Signer signer) {
  // create request
  final req = AWSRequest.formData(
    'https://sts.${signer.region}.amazonaws.com/',
    body: {
      'Action': 'GetCallerIdentity',
      'Version': '2011-06-15',
    },
  );

  // sign the request
  signer.sign(req);

  return req;
}

String formatAsCurlCommand(AWSRequest req) {
  var cmd = ['curl', '-v'];

  // set method
  cmd.add('-X ${req.method}');

  // set headers
  req.headers.forEach((key, value) {
    cmd.add("-H '$key: $value'");
  });

  // set body
  if (req.body.isNotEmpty) {
    cmd.add("-d '${req.body}'");
  }

  // set url
  cmd.add(req.url.toString());

  return cmd.join(' ') + '\n';
}

void main() async {
  // provide your AWS config
  final AWS_ACCESS_KEY_ID = 'aws_access_key_id';
  final AWS_SECRET_ACCESS_KEY = 'aws_secret_access_key';
  final AWS_REGION = 'eu-central-1';

  // create credentials object
  final credentialsProvider = AWSStaticCredentialsProvider(
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY,
    sessionToken: null,
  );
  final signer = AWS4Signer(
    credentialsProvider,
    region: AWS_REGION,
    serviceName: 'sts',
  );

  print('SIGNING:');
  final signedReq = createGetCallerIdentityRequest(signer);
  print(formatAsCurlCommand(signedReq));

  print('PRESIGNING:');
  final presignedReq = createPresignGetCallerIdentityRequest(
    signer,
    Duration(minutes: 5),
  );
  print(formatAsCurlCommand(presignedReq));
}
