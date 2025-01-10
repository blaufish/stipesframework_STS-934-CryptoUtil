# Stripes Framework: Weak Encryption STS-934

`net.sourceforge.stripes.util.CryptoUtil` was insecure.

Attacks could length extend existing messages, reorder
blocks, etc. due to Electronic Codebook (`ECB`) mode without strong
integrity check.

Insufficient integrity check consisted of:

* `PKCS5` padding check
* 16-bit non-keyed hash

Integrity check could be bypassed in a few ciphertext messages,
easily automated in seconds.

Impact was application dependent;

* Configuration / code dependent if at all affected.
  Applications not enabling use of this feature was unaffected.
* `PKCS5`, `ECB` and a hash did some limits/restrictions on what
   manipulations were possible.
   Applications with very strict plaintext requirements
   may be less affected.

For an affected real world application, we could bypass a security
control that was built upon `CryptoUtil`.

## About Stripes Framework

Main page [github.com/StripesFramework/stripes](https://github.com/StripesFramework/stripes):

> "Stripes is a Java framework with the goal of making Servlet/JSP
> based web development in Java as easy, intuitive and
> straight-forward as it should be. It's stripey and it doesn't
> suck."

Wikipedia [Stripes (framework)](https://en.wikipedia.org/wiki/Stripes_%28framework%29):
* Initial release: 2005; 20 years ago
* Stable release: 1.6.0 / July 23, 2015; 9 years ago

This issue was fixed in 2015, but initially found in ancient times (2010?).

## Vulnerability

Encryption was generated as follows, pseudo-code:
``` plain
I = input
K = key
H = hash_16bits( I )
N = nonce_16bits( )
P = concat( H, N, I )
C = Encrypt( K, "ECB", "PKCS5Padding", P )
```

Decryption was generated as follows, pseudo-code:
``` plain
P = Decrypt( K, "ECB", "PKCS5Padding", C )
assert( no padding errors )

I = input_from_plaintext( P )
H = hash_from_plaintext( P )
H´ = hash_16bits( I )
assert( H === H´ )
```

## Basic attack

A valid message is obtained by dumb-fuzzing the last 8 byte block
until:

* PKCS5Padding is valid
* Hash is valid

## Block reorder and length extension attacks

Presuming a long message is transmitted, e.g. `AAAAAA...`.
`ECB/PKCS5Padding` encryption should generate blocks:

* `P = [ P0, P1, P2, ... , Pn-2, Pn-1, Pn ]`
* `C = [ C0, C1, C2, ... , Cn-2, Cn-1, Cn ]`, for which `Ci = ECB_Encrypt( Pi )`.
* Block `P0` contains hash, nonce, and `AAAAAA` (six `A` characters)
* Block `C0` is `P0` ECB encrypted.
* Block `P1` to `Pn-1` would be identical, `AAAAAAAA` (eight `A` characters).
* Block `C1` to `Cn-1` would be identical, `AAAAAAAA` ECB encrypted.
* Block `Pn` contains padding (and zero or more `A` characters).
* Block `Cn` contains padding  (and zero or more `A` characters) ECB encrypted.

Attacker can add, remove, reorder `C0`, `C1`, `Cn` blocks with
**predictable** effects to resulting plaintext.

Attacker then needs to perform the basic attack (fuzz last block)
until a new valid message is generated.

## Specific issues

The Stripes Encryption scheme did suffer from a number of issues;

* Electronic Codebook (ECB) mode with `PKCS5` padding.
* Mac-then-Encrypt (MtE) cipher composition
* Short Hash
* Non-keyed Hash
* Short nonce

### Issue: ECB/PKCS5Padding mode

Java cipher mode is not specified, implying default mode `ECB/PKCS5Padding`.

``` java
protected static Cipher getCipher(int mode) {
    try {
        SecretKey key = getSecretKey();
        Cipher cipher = Cipher.getInstance(key.getAlgorithm());
        cipher.init(mode, key);
        return cipher;
```

Electronic Codebook (ECB) mode is a confidentiality only mode, lacking integrity checks.
It should not be used in absence of a strong hash.
Additionally, ECB does not hide patterns, i.e. a long plaintext `AAAAA....` will encrypt to a long string of repeating blocks.

`PKCS5Padding` may be an issue in specific scenarios; this padding is extremely forgiving.

Valid padding for 8-byte `DESede` includes:

``` plain
xx xx xx xx xx xx xx 01
xx xx xx xx xx xx 01 01
...
xx 07 07 07 07 07 07 07
08 08 08 08 08 08 08 08
```

i.e. a random trailing block is very likely to be a valid cipher.

Additionally, `PKCS5Padding` can in other modes (such as CBC) be the source of Padding Oracle / CBC-Reverse attacks.

### Issue: Mac then Encrypt

Stripes Framework STS-934 used the following encryption scheme:

`plaintext = HASH | NONCE | input`

Code:

``` java
byte[] hash = generateHashCode(nonce, inbytes);
int index = cipher.update(hash, 0, HASH_CODE_SIZE, output, 0);
index = cipher.update(nonce, 0, NONCE_SIZE, output, index);
//...
cipher.doFinal(inbytes, 0, inbytes.length, output, index);
```

This is an Mac-Then-Encrypt (MtE) scheme, i.e. you can attack the encryption before you attack the hash.
While MtE may be acceptable in well analyzed cipher compositions, it is generally dissuaded.

Encrypt-Then-Mac (EtM) composition is generally preferred over MtE compositions.

### Issue: Short Hash

The hash function is trivially short;

``` java
private static final int HASH_CODE_SIZE = 2;
```

16 bit hash. I.e. in average it takes **32768** (`2^15`) random attempts to get hash/ciphertext combo to match.

### Issue: non-keyed hash

The hash function was not a HMAC nor any other keyed hash / MAC function.

``` java
protected static byte[] generateHashCode(byte[]... byteses) {
    long hash = HASH_CODE_SEED;
    for (int i = 0; i < byteses.length; i++) {
        byte[] bytes = byteses[i];
        for (int j = 0; j < bytes.length; j++) {
            hash = (((hash << 5) + hash) + bytes[j]);
        }
    }
```

While not necessarily an issue in the code as is, there are some considerations regarding predictable hashes;

* Hash/Message Oracle. If the position of the hash is known or predictable,
  the hash could disclose the cipherstream bytes.
  Alternatively, if the cipherstream bytes are broken, the hash gives a hint of what the message could be.
* Hash manipulation. If the hash can be modified in attacks, attacker may be able to craft valid hashes.

### Issue: Short Random Nonce

Nonce was short random number, 2 bytes (16 bits).

``` java
private static final int NONCE_SIZE = 2;

protected static byte[] nextNonce() {
    byte[] nonce = new byte[NONCE_SIZE];
    CryptoUtil.random.nextBytes(nonce);
    return nonce;
}
```

Random collisions are to be expected after **256** (`2^8`) encryption.

While not necessarily an issue in the code as is, weak nonce are an issue in other schemes.

## Resolution

Issue was mitigated as follows;

* Encrypt-Then-MAC composition.
* Cipher modifier `/CBC/PKCS5Padding`.
* Non-keyed hash replaced with HMAC-SHA256.
* HMAC-SHA256 verification using double HMAC principle, to hide any string compare timing oracles.

Implementation considerations;

* Stripes Framework: old code base, don't touch too much.
* Verify that everything works with the Maven POM.
* HMAC-SHA256 should be safe to add in 2015.
* CBC/PKCS5Padding should be safe to add in 2015.
* `DESede` kept as is.
  Arguably it could have been moved to AES in 2015, but eh, keep it simple stupid.
  Fix the easily exploitable issue for now.

General changes:

``` java
protected static final String CIPHER_MODE_MODIFIER = "/CBC/PKCS5Padding";
protected static final int CIPHER_BLOCK_LENGTH = 8;
private static final String CIPHER_HMAC_ALGORITHM = "HmacSHA256";
private static final int CIPHER_HMAC_LENGTH = 32;

protected static Cipher getCipher(SecretKey key, int mode, byte[] iv, int ivpos, int ivlength) {
    Cipher cipher = Cipher.getInstance(key.getAlgorithm() + CIPHER_MODE_MODIFIER);
    IvParameterSpec ivps = new IvParameterSpec(iv, ivpos, ivlength);
    cipher.init(mode, key, ivps);
    return cipher;
}
```

Encryption pseudo-code:

``` java
// Encryption

byte[] iv = generateInitializationVector();
System.arraycopy(iv, 0, output, 0, CIPHER_BLOCK_LENGTH);

//Encrypt-then-Mac (EtM) pattern, first encrypt plaintext        	
Cipher cipher = getCipher(key, Cipher.ENCRYPT_MODE, iv, 0, CIPHER_BLOCK_LENGTH);
cipher.doFinal(inbytes, 0, inbytes.length, output, CIPHER_BLOCK_LENGTH);

// Encrypt-then-Mac (EtM) pattern, authenticate ciphertext
hmac(key, output, 0, output.length - CIPHER_HMAC_LENGTH, output, output.length - CIPHER_HMAC_LENGTH);
```

Decryption pseudo-code:

``` java
// Decryption

private static boolean hmacEquals(SecretKey key, byte[] mac1, int mac1pos,
			byte[] mac2, int mac2pos) throws Exception {
   hmac(key, mac1, mac1pos, CIPHER_HMAC_LENGTH, mac1, mac1pos);
   hmac(key, mac2, mac2pos, CIPHER_HMAC_LENGTH, mac2, mac2pos);

   for(int i = 0; i < CIPHER_HMAC_LENGTH; i++)
      if (mac1[mac1pos+i] != mac2[mac2pos+i])
         return false;

   return true;
}

byte[] mac = new byte[CIPHER_HMAC_LENGTH];
hmac(key, bytes, 0, bytes.length - CIPHER_HMAC_LENGTH, mac, 0);
validCiphertext = hmacEquals(key, bytes, bytes.length - CIPHER_HMAC_LENGTH, mac, 0);
if (!validCiphertext) {
   log.warn("Input was not encrypted with the current encryption key (bad HMAC): ", input);
   return null;        	
Cipher cipher = getCipher(key, Cipher.DECRYPT_MODE, bytes, 0, CIPHER_BLOCK_LENGTH);}
output = cipher.doFinal(bytes, CIPHER_BLOCK_LENGTH, bytes.length - CIPHER_HMAC_LENGTH - CIPHER_BLOCK_LENGTH);
```

## Timeline

**Ancient time (2010?)**:

* Weak stripes encryption detected in a security penetration test engagement.
* Demonstrate ability to bypass a security check that depended on `CryptUtil`.
* Vulnerability triage identified `CryptoUtil` as source of vulnerability.
* Stripes Framework was contacted on from an anonymous throw-away account,
  and application owners recommended to contact Stripes if no progress.


**Remediation 2015**:

* Contacted by a security audit team with access to old penetration
  test report.
* Unresolved issue highlighted, "please talk to Stripes!"
* Authored JUnit test case demonstrating encryption scheme can be
  bypassed in a few iterations.
* Authored a CBC, HMAC and Encrypt-Then-MAC (EtM) based solution.
* Issue raised in JIRA
  [STS-934](https://stripesframework.atlassian.net/browse/STS-934)
  and
  [pull request 16](https://github.com/StripesFramework/stripes/pull/16).
* Pull request merged, new Stripes version released.

**2025**

* Write-up 10 - 15 years later for the fun of it!
