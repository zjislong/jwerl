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
  DERSignature = public_key:sign(Message, algo(ShaBits), ECPrivateKey),
  #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value', DERSignature),
  RBin = int_to_bin(R),
  SBin = int_to_bin(S),
  Size = ShaBits/8,
  RPad = pad(RBin, Size),
  SPad = pad(SBin, Size),
  Signature = <<RPad/binary, SPad/binary>>.

verify(ShaBits, Key, Data, Signature) ->
  [SPKI] = public_key:pem_decode(Key),
  #'SubjectPublicKeyInfo'{algorithm = Der} = SPKI,
  RealSPKI = public_key:der_decode('SubjectPublicKeyInfo', Der),
  #'SubjectPublicKeyInfo'{
     subjectPublicKey = Octets,
     algorithm = #'AlgorithmIdentifier'{ parameters = Params}
    } = RealSPKI,
  ECPoint = #'ECPoint'{point = Octets},
  EcpkParametersPem = {'EcpkParameters', Params, not_encrypted},
  ECParams = public_key:pem_entry_decode(EcpkParametersPem),
  ECPublicKey = {ECPoint, ECParams},
  public_key:verify(Data, algo(ShaBits), Signature, ECPublicKey).

algo(256) -> sha256;
algo(384) -> sha384;
algo(512) -> sha512.

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
