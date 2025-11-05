import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';
import 'package:pointycastle/src/utils.dart';

void main(List<String> arguments) async {
  final port = _handledParsing(arguments);

  ServerSocket serverSocket = await ServerSocket.bind(
    InternetAddress.anyIPv4,
    port,
  );

  print(
    'Server[🔁]: is running on ${serverSocket.address.address}:${serverSocket.port}',
  );

  await for (var socket in serverSocket) {
    _handleClient(socket);
  }
}

int _handledParsing(List<String> arguments) {
  var parser = ArgParser()
    ..addOption(
      'port',
      abbr: 'p',
      defaultsTo: '8888',
      callback: (value) {
        if (value != null) {
          var port = int.tryParse(value);
          if (port == null || port < 0 || port > 65535) {
            print('Invalid port number: $value');
            exit(64);
          }
        }
      },
      help: 'Port to listen on',
    )
    ..addFlag(
      'help',
      abbr: 'h',
      help: 'Show this help message',
      negatable: false,
    );

  var results = parser.parse(arguments);
  if (results['help'] as bool) {
    print(parser.usage);
    exit(64);
  }

  return int.parse(results['port']);
}

SecureRandom getSecureRandom() {
  final secureRandom = FortunaRandom();

  final seed = Uint8List(32);
  final random = Random.secure();

  for (int i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }

  secureRandom.seed(KeyParameter(Uint8List.fromList(seed)));
  return secureRandom;
}

BigInt _randomExponent(int bits, SecureRandom rng) {
  return rng.nextBigInteger(bits);
}

// handle el professor function
// Convert Bigint into Uint8List using PC function
// Oposite of decodeBigInt function from PC
Uint8List _toFixedLengh(BigInt number, int length) {
  Uint8List bytes = encodeBigInt(number);

  if (bytes.length == length) {
    return bytes;
  }

  if (bytes.length > length) {
    return bytes.sublist(bytes.length - length);
  }

  Uint8List result = Uint8List(length);
  result.setRange(length - bytes.length, length, bytes);
  return result;
}

Uint8List _createX509SPKI(RSAPublicKey publicKey) {
  // Placeholder for X.509 / SubjectPublicKeyInfo DER generation
  //create structure  pkcs1 = SEQUENCE { modulus INTEGER, exponent INTEGER }
  final pkcs1Key = ASN1Sequence()
    ..add(ASN1Integer(publicKey.modulus!))
    ..add(ASN1Integer(publicKey.exponent!));

  //encode pkcs1 to DER
  final pkcs1KeyBytes = pkcs1Key.encode();

  //adding the algorithm identifier for RSA encryption
  final algId = ASN1AlgorithmIdentifier(
    ASN1ObjectIdentifier.fromName("rsaEncryption"),
  );

  //create the SubjectPublicKeyInfo structure
  final spki = ASN1Sequence()
    ..add(algId)
    ..add(ASN1BitString(stringValues: pkcs1KeyBytes));

  return spki.encode();
}

void _handleClient(Socket socket) {
  socket.setOption(SocketOption.tcpNoDelay, true);

  final BigInt G = BigInt.from(2);
  final BigInt P = BigInt.parse(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    radix: 16,
  );
  final salt = Uint8List.fromList('phase3 aead key '.codeUnits);
  final pbkdf2Iterations = 600000;
  final rng = getSecureRandom();

  BigInt prkb = _randomExponent(256, rng);
  final BigInt pkb = G.modPow(prkb, P);
  BigInt? pka;
  BigInt? Z;

  Uint8List? aesKey;
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> pair;

  Uint8List? transcriptHash;
  RSAPublicKey? pubc;


  utf8.decoder
      .bind(socket)
      .transform(const LineSplitter())
      .listen(
        (line) async {
          if (line.contains(':')) {
            var head = line.split(':')[0];
            var body = line.split(':')[1];

            switch (head) {
              case 'A':
                pka = decodeBigInt(base64.decode(body));
                var B = base64.encode(_toFixedLengh(pkb, 256));
                print('Client[🔑 - A]: $body');
                print('Server[🔑 - B]: $B');
                socket.writeln('B:$B');

                Z = pka!.modPow(prkb, P);
                print('Server[🔑 - Z]: $Z');

                print('Server[🔑 - DERIVING KEY]');
                var sha256 = SHA256Digest();
                var list = Uint8List.fromList([
                  ..._toFixedLengh(G, 1),
                  ..._toFixedLengh(P, 256),
                  ..._toFixedLengh(pka!, 256),
                  ..._toFixedLengh(pkb, 256),
                ]);

                transcriptHash = sha256.process(list);
                var password = base64.encode(transcriptHash!);
                print('Server[🔑 - PASSWORD]: $password');

                var pbkdf2 = KeyDerivator('SHA-256/HMAC/PBKDF2')
                  ..init(Pbkdf2Parameters(salt, pbkdf2Iterations, 32));

                print('Server[🔑 - AES_KEY] - Deriving key from password');
                aesKey = pbkdf2.process(utf8.encode(password));

                final rsaGen = RSAKeyGenerator()
                  ..init(
                    ParametersWithRandom(
                      RSAKeyGeneratorParameters(BigInt.from(65537), 2048, 64),
                      rng,
                    ),
                  );

                pair = rsaGen.generateKeyPair();
                final publicKey = pair.publicKey;
                final privateKey = pair.privateKey;

                var pubs = base64.encode(
                  pair.publicKey.modulus.toString().codeUnits,
                );
                print('Server[🔑 - PUBS]: $pubs');

                final nonce = rng.nextBytes(12);
                print('Server[🔑 - NONCE]: ${base64.encode(nonce)}');

                final gcm = GCMBlockCipher(AESEngine())
                  ..init(
                    true,
                    AEADParameters(
                      KeyParameter(aesKey!),
                      128,
                      nonce,
                      transcriptHash!,
                    ),
                  );

                //wanna die, got to generate a X.509 / SubjectPublicKeyInfo DER  from scratch
                final derS = _createX509SPKI(publicKey);
                print('Server[🔑 - SPKI DER]: ${base64.encode(derS)}');

                final nonceAndCt = Uint8List.fromList([
                  ...nonce,
                  ...gcm.process(derS),
                ]);

                print('Server[🔑 - NONCE+CT]: ${base64.encode(nonceAndCt)}');
                socket.writeln('PUBS:${base64.encode(nonceAndCt)}');

              case 'PUBC':
                print('Client[🔑 - PUBC]: $body');
                
                try{
                  final blob = base64.decode(body);
                  if (transcriptHash == null || aesKey == null) {
                    throw Exception('Missing transcript/aes key (send A first)');
                }

                final nonce = blob.sublist(0, 12);
                final ct = blob.sublist(12);

                final gcm = GCMBlockCipher(AESEngine())
                  ..init(
                    false,
                    AEADParameters(
                      KeyParameter(aesKey!),
                      128,
                      nonce,
                      transcriptHash!,
                    ),
                  );

                  final derC = gcm.process(ct);
                  print('Client[🔑 - DERC]: ${base64.encode(derC)}');

                  //Extract modulus and exponent from DER
                  final asn1Parser = ASN1Parser(derC);
                  final spki = asn1Parser.nextObject() as ASN1Sequence;

                  final pkcs1key = spki.elements![1] as ASN1BitString;
                  final pkcs1Parser = ASN1Parser(pkcs1key.stringValues as Uint8List);
                  final pkcs1Seq = pkcs1Parser.nextObject() as ASN1Sequence;
                  print('Client[🔑 - PKCS1SEQ]: $pkcs1Seq');
                  print('Client[🔑 - ELEMENTS 1]: ${(pkcs1Seq.elements![0].encodedBytes).toString()}');                  
                  print('Client[🔑 - ELEMENTS 2]: ${(pkcs1Seq.elements![1].encodedBytes).toString()}');

                  final modulus  = decodeBigInt(pkcs1Seq.elements![0].encodedBytes!);
                  final exponent = decodeBigInt(pkcs1Seq.elements![1].encodedBytes!);

                  print('Client[🔑 - MODULUS]: $modulus');
                  print('Client[🔑 - EXPONENT]: $exponent');

                  pubc = RSAPublicKey(modulus, exponent);
                  

                }catch(e){
                  print('Server[❌ - ERROR]: Failed to process PUBC - $e');
                }

              case _:
                print('Client[❓ - UNKNOWN]: $line');
            }
          }
        },
        onDone: () => print(
          'Server[🛑 - CLOSING]: Connection with ${socket.remoteAddress.address}:${socket.remotePort} closed',
        ),
        onError: (error) => print(
          'Server[❌ - ERROR]: Error occurred with ${socket.remoteAddress.address}:${socket.remotePort} - $error',
        ),
      );
}
