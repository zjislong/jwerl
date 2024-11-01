% @hidden
-module(jwerl_es).
-include_lib("public_key/include/public_key.hrl").

-export([sign/3, verify/4]).

sign(ShaBits, Key, Data) ->
  ECPrivateKeyPem1 = case public_key:pem_decode(Key) of
                       [_, ECPrivateKeyPem] -> ECPrivateKeyPem;
                       [ECPrivateKeyPem] -> ECPrivateKeyPem
                     end,
  ECPrivateKey = public_key:pem_entry_decode(ECPrivateKeyPem1),
  DERSignature = public_key:sign(Data, algo(ShaBits), ECPrivateKey),
  #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DERSignature),
  RBin = int_to_bin(R),
  SBin = int_to_bin(S),
  Size = r_s_size(ShaBits),
  RPad = pad(RBin, Size),
  SPad = pad(SBin, Size),
  <<RPad/binary, SPad/binary>>.

verify(ShaBits, Key, Data, Signature) ->
  case public_key:pem_decode(Key) of
    [{'Certificate',Certificate,_} = SPKI] -> 
        public_key:pkix_decode_cert( Certificate, otp ),
        #'Certificate'{tbsCertificate = #'TBSCertificate'{subjectPublicKeyInfo = RealSPKI}} = public_key:pem_entry_decode(SPKI);
    [{'SubjectPublicKeyInfo',_,_ } = SPKI] -> 
        #'SubjectPublicKeyInfo'{algorithm = Der} = SPKI,
        RealSPKI = public_key:der_decode('SubjectPublicKeyInfo', Der)
  end,
  #'SubjectPublicKeyInfo'{subjectPublicKey = Key0, algorithm = #'AlgorithmIdentifier'{parameters = Params}} = RealSPKI,
  ECCParams = public_key:der_decode('EcpkParameters', Params),
  ECPublicKey = {#'ECPoint'{point = Key0}, ECCParams},
  SignatureLen= byte_size(Signature),
  {RBin, SBin}= split_binary(Signature, SignatureLen div 2),
  R = crypto:bytes_to_integer(RBin),
  S = crypto:bytes_to_integer(SBin),
  DERSignature = public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{r = R, s = S}),
  public_key:verify(Data, algo(ShaBits), DERSignature, ECPublicKey).

algo(256) -> sha256;
algo(384) -> sha384;
algo(512) -> sha512.

r_s_size(256) -> 32;
r_s_size(384) -> 48;
r_s_size(512) -> 66.

int_to_bin(X) when X < 0 -> int_to_bin_neg(X, []);
int_to_bin(X) -> int_to_bin_pos(X, []).

int_to_bin_pos(0, Ds = [_ | _]) ->
    list_to_binary(Ds);
int_to_bin_pos(X, Ds) ->
    int_to_bin_pos(X bsr 8, [(X band 255) | Ds]).

int_to_bin_neg(-1, Ds = [MSB | _]) when MSB >= 16#80 ->
    list_to_binary(Ds);
int_to_bin_neg(X, Ds) ->
    int_to_bin_neg(X bsr 8, [(X band 255) | Ds]).

pad(Bin, Size) when byte_size(Bin) =:= Size ->
    Bin;
pad(Bin, Size) ->
    pad(<<0, Bin/binary>>, Size).
