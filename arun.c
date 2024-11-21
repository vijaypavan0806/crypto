SHA
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class sha {
    public static String hashWithSHA512(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] hashedBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashedBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 algorithm not found!", e);
        }
    }
    public static void main(String[] args) {
        String input = "koushik";
        String sha512Hash = hashWithSHA512(input);
        System.out.println("Input: " + input);
        System.out.println("SHA-512 Hash: " + sha512Hash);
    }
}

DES
import java.util.ArrayList;
import java.util.List;

public class DESKeyGeneration {
    private static final int[] PC1 = {
        57, 49, 41, 33, 25, 17, 9, 
        1, 58, 50, 42, 34, 26, 18, 
        10, 2, 59, 51, 43, 35, 27, 
        19, 11, 3, 60, 52, 44, 36, 
        63, 55, 47, 39, 31, 23, 15, 
        7, 62, 54, 46, 38, 30, 22, 
        14, 6, 61, 53, 45, 37, 29, 
        21, 13, 5, 28, 20, 12, 4
    };

    private static final int[] PC2 = {
        14, 17, 11, 24, 1, 5, 
        3, 28, 15, 6, 21, 10, 
        23, 19, 12, 4, 26, 8, 
        16, 7, 27, 20, 13, 2, 
        41, 52, 31, 37, 47, 55, 
        30, 40, 51, 45, 33, 48, 
        44, 49, 39, 56, 34, 53, 
        46, 42, 50, 36, 29, 32
    };

    private static final int[] SHIFTS = {
        1, 1, 2, 2, 2, 2, 2, 2, 
        1, 2, 2, 2, 2, 2, 2, 1
    };

    private static String leftCircularShift(String input, int shift) {
        return input.substring(shift) + input.substring(0, shift);
    }

    private static String permute(String input, int[] table) {
        StringBuilder output = new StringBuilder();
        for (int index : table) {
            output.append(input.charAt(index - 1));
        }
        return output.toString();
    }

    public static List<String> generateKeys(String key64Bit) {
        String permutedKey = permute(key64Bit, PC1);
        String left = permutedKey.substring(0, 28);
        String right = permutedKey.substring(28);
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            left = leftCircularShift(left, SHIFTS[i]);
            right = leftCircularShift(right, SHIFTS[i]);
            String combinedKey = left + right;
            String roundKey = permute(combinedKey, PC2);
            keys.add(roundKey);
        }
        return keys;
    }

    public static void main(String[] args) {
        String keyHex = "133457799BBCDFF1";
        String key64Bit = new java.math.BigInteger(keyHex, 16).toString(2);
        key64Bit = String.format("%64s", key64Bit).replace(' ', '0');
        List<String> keys = generateKeys(key64Bit);
        for (int i = 0; i < keys.size(); i++) {
            System.out.printf("Round %2d Key: %s%n", i + 1, keys.get(i));
        }
    }
}



DSA
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

public class DigitalSignatureGenerator {
    public static void main(String[] args) {
        try {
            Scanner userInputScanner = new Scanner(System.in);
            System.out.print("Enter input: ");
            String userMessage = userInputScanner.nextLine();

            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
            keyGenerator.initialize(1024);
            KeyPair keyPair = keyGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            byte[] digitalSignature = generateSignature(userMessage, privateKey);
            System.out.println("Digital Signature: " + bytesToHexadecimal(digitalSignature));

            boolean isSignatureVerified = verifyDigitalSignature(userMessage, digitalSignature, publicKey);
            System.out.println("Signature Verified: " + isSignatureVerified);

            userInputScanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] generateSignature(String data, PrivateKey privateKey) throws Exception {
        Signature signatureGenerator = Signature.getInstance("SHA1withDSA");
        signatureGenerator.initSign(privateKey);
        signatureGenerator.update(data.getBytes());
        return signatureGenerator.sign();
    }

    public static boolean verifyDigitalSignature(String data, byte[] signature, PublicKey publicKey) throws Exception {
        Signature signatureVerifier = Signature.getInstance("SHA1withDSA");
        signatureVerifier.initVerify(publicKey);
        signatureVerifier.update(data.getBytes());
        return signatureVerifier.verify(signature);
    }

    public static String bytesToHexadecimal(byte[] bytes) {
        StringBuilder hexadecimalString = new StringBuilder();
        for (byte b : bytes) {
            String hexadecimal = Integer.toHexString(0xff & b);
            if (hexadecimal.length() == 1) hexadecimalString.append('0');
            hexadecimalString.append(hexadecimal);
        }
        return hexadecimalString.toString();
    }
}






MD5
import java.nio.charset.StandardCharsets;

public class MD5Algorithm {
    private static final int[] SHIFT_AMOUNTS = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };

    private static final int[] TABLE_T = new int[64];

    static {
        for (int i = 0; i < 64; i++) {
            TABLE_T[i] = (int) (long) ((1L << 32) * Math.abs(Math.sin(i + 1)));
        }
    }

    private static int leftRotate(int x, int amount) {
        return (x << amount) | (x >>> (32 - amount));
    }

    private static byte[] padMessage(byte[] message) {
        int messageLength = message.length;
        int remainder = messageLength % 64;
        int paddingLength = (remainder < 56) ? (56 - remainder) : (64 + 56 - remainder);
        byte[] paddedMessage = new byte[messageLength + paddingLength + 8];
        System.arraycopy(message, 0, paddedMessage, 0, messageLength);
        paddedMessage[messageLength] = (byte) 0x80;
        long messageBitsLength = (long) messageLength * 8;
        for (int i = 0; i < 8; i++) {
            paddedMessage[paddedMessage.length - 8 + i] = (byte) (messageBitsLength >>> (8 * i));
        }
        return paddedMessage;
    }

    public static String computeMD5(String input) {
        byte[] message = padMessage(input.getBytes(StandardCharsets.UTF_8));
        int[] h = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

        for (int i = 0; i < message.length / 64; i++) {
            int[] block = new int[16];
            for (int j = 0; j < 16; j++) {
                block[j] = ((message[i * 64 + j * 4] & 0xff)) |
                           ((message[i * 64 + j * 4 + 1] & 0xff) << 8) |
                           ((message[i * 64 + j * 4 + 2] & 0xff) << 16) |
                           ((message[i * 64 + j * 4 + 3] & 0xff) << 24);
            }

            int a = h[0], b = h[1], c = h[2], d = h[3];
            for (int j = 0; j < 64; j++) {
                int f, g;
                if (j < 16) {
                    f = (b & c) | (~b & d);
                    g = j;
                } else if (j < 32) {
                    f = (d & b) | (~d & c);
                    g = (5 * j + 1) % 16;
                } else if (j < 48) {
                    f = b ^ c ^ d;
                    g = (3 * j + 5) % 16;
                } else {
                    f = c ^ (b | ~d);
                    g = (7 * j) % 16;
                }
                int temp = d;
                d = c;
                c = b;
                b = b + leftRotate(a + f + block[g] + TABLE_T[j], SHIFT_AMOUNTS[j]);
                a = temp;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
        }

        StringBuilder md5 = new StringBuilder();
        for (int value : h) {
            for (int i = 0; i < 4; i++) {
                md5.append(String.format("%02x", (value >>> (i * 8)) & 0xff));
            }
        }
        return md5.toString();
    }

    public static void main(String[] args) {
        String input = "hello world";
        System.out.println("Input: " + input);
        System.out.println("MD5: " + computeMD5(input));
    }
}
























HILL:
#include #include
#define SIZE 3 // Key matrix size (3x3)

// Function to calculate modulo 26
int mod26(int n) {
return (n % 26 + 26) % 26;
}

// Function to multiply matrices (for encryption)
void matrixMultiply(int key[SIZE][SIZE], int text[], int result[]) {
for (int i = 0; i < SIZE; i++) {
result[i] = 0;
for (int j = 0; j < SIZE; j++) {
result[i] += key[i][j] * text[j];
}
result[i] = mod26(result[i]);
}
}

// Function to find the determinant of a 3x3 matrix
int determinant(int matrix[SIZE][SIZE]) {
return matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]);
}

// Function to calculate the inverse of a 3x3 matrix modulo 26
void inverseMatrix(int key[SIZE][SIZE], int inverse[SIZE][SIZE], int detInverse) {
int temp[SIZE][SIZE];
for (int i = 0; i < SIZE; i++) {
for (int j = 0; j < SIZE; j++) {
temp[j][i] = (key[(i + 1) % SIZE][(j + 1) % SIZE] * key[(i + 2) % SIZE][(j + 2) % SIZE] -
key[(i + 1) % SIZE][(j + 2) % SIZE] * key[(i + 2) % SIZE][(j + 1) % SIZE]);
inverse[j][i] = mod26(temp[j][i] * detInverse);
}
}
}

// Function to calculate the modular multiplicative inverse
int modInverse(int a, int m) {
a = mod26(a);
for (int x = 1; x < m; x++) {
if ((a * x) % m == 1) {
return x;
}
}
return -1; // No modular inverse
}

int main() {
int key[SIZE][SIZE] = {{6, 24, 1}, {13, 16, 10}, {20, 17, 15}};
int inverseKey[SIZE][SIZE];
char plaintext[SIZE + 1];
char ciphertext[SIZE + 1];
int det = determinant(key);
int detInverse = modInverse(det, 26);

if (detInverse == -1) {
printf("Key matrix is not invertible under modulo 26.\n");
return 1;
}

printf("Enter plaintext (3 characters): ");
scanf("%s", plaintext);

// Padding plaintext if necessary
while (strlen(plaintext) < SIZE) {
strcat(plaintext, "X");
}

// Convert plaintext to numerical form
int textVector[SIZE];
for (int i = 0; i < SIZE; i++) {
textVector[i] = plaintext[i] - 'A';
}

// Encryption
int encryptedVector[SIZE];
matrixMultiply(key, textVector, encryptedVector);
for (int i = 0; i < SIZE; i++) {
ciphertext[i] = encryptedVector[i] + 'A';
}
ciphertext[SIZE] = '\0';
printf("Ciphertext: %s\n", ciphertext);

// Calculate inverse key matrix
inverseMatrix(key, inverseKey, detInverse);

// Decryption
int decryptedVector[SIZE];
matrixMultiply(inverseKey, encryptedVector, decryptedVector);
char decryptedText[SIZE + 1];
for (int i = 0; i < SIZE; i++) {
decryptedText[i] = decryptedVector[i] + 'A';
}
decryptedText[SIZE] = '\0';
printf("Decrypted text: %s\n", decryptedText);

return 0;
}

Vignere:
#include #include #include
// Function to encrypt the plaintext using the Vigenère Cipher
void encrypt(char *plaintext, char *key, char *ciphertext) {
int textLen = strlen(plaintext);
int keyLen = strlen(key);

for (int i = 0, j = 0; i < textLen; i++) {
if (isalpha(plaintext[i])) {
// Adjust for A=0, B=1, ..., Z=25
char base = isupper(plaintext[i]) ? 'A' : 'a';
ciphertext[i] = (plaintext[i] - base + (toupper(key[j]) - 'A')) % 26 + base;
j = (j + 1) % keyLen; // Move to the next key character
} else {
ciphertext[i] = plaintext[i]; // Keep non-alphabet characters unchanged
}
}
ciphertext[textLen] = '\0'; // Null-terminate the ciphertext
}

// Function to decrypt the ciphertext using the Vigenère Cipher
void decrypt(char *ciphertext, char *key, char *plaintext) {
int textLen = strlen(ciphertext);
int keyLen = strlen(key);

for (int i = 0, j = 0; i < textLen; i++) {
if (isalpha(ciphertext[i])) {
// Adjust for A=0, B=1, ..., Z=25
char base = isupper(ciphertext[i]) ? 'A' : 'a';
plaintext[i] = (ciphertext[i] - base - (toupper(key[j]) - 'A') + 26) % 26 + base;
j = (j + 1) % keyLen; // Move to the next key character
} else {
plaintext[i] = ciphertext[i]; // Keep non-alphabet characters unchanged
}
}
plaintext[textLen] = '\0'; // Null-terminate the plaintext
}

int main() {
char plaintext[100], key[100], ciphertext[100], decryptedText[100];

// Input plaintext
printf("Enter the plaintext: ");
fgets(plaintext, sizeof(plaintext), stdin);
plaintext[strcspn(plaintext, "\n")] = '\0'; // Remove newline character

// Input key
printf("Enter the key: ");
fgets(key, sizeof(key), stdin);
key[strcspn(key, "\n")] = '\0'; // Remove newline character

// Encrypt the plaintext
encrypt(plaintext, key, ciphertext);
printf("Ciphertext: %s\n", ciphertext);

// Decrypt the ciphertext
decrypt(ciphertext, key, decryptedText);
printf("Decrypted Text: %s\n", decryptedText);

return 0;
}

DES:

#include void permute(int *input, int *output, int *perm, int size) {
for (int i = 0; i < size; i++) {
output[i] = input[perm[i] - 1];
}
}
void leftShift(int *key, int shifts) {
int temp[10];
for (int i = 0; i < 10; i++) {
temp[i] = key[(i + shifts) % 10];
}
for (int i = 0; i < 10; i++) {
key[i] = temp[i];
}
}
void generateKeys(int *key, int *k1, int *k2) {
int p10[10] = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
int p8[8] = {6, 7, 8, 5, 4, 3, 2, 1};
int temp[10];
permute(key, temp, p10, 10);
leftShift(temp, 1);
permute(temp, k1, p8, 8);
leftShift(temp, 2);
permute(temp, k2, p8, 8);
}
int main() {
int key[10];
int k1[8], k2[8];
printf("Enter a 10-bit key (binary digits only): ");
for (int i = 0; i < 10; i++) {
scanf("%1d", &key[i]);
}
generateKeys(key, k1, k2);
printf("Key K1: ");
for (int i = 0; i < 8; i++) printf("%d", k1[i]);
printf("\nKey K2: ");
for (int i = 0; i < 8; i++) printf("%d", k2[i]);
printf("\n"); // To add a newline at the end
return 0;
}

DSA:


import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Scanner;

public class DigitalSignatureGenerator {

public static void main(String[] args) {
try {
Scanner userInputScanner = new Scanner(System.in);
System.out.print("Enter input: ");
String userMessage = userInputScanner.nextLine();

// Generate DSA key pair
KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("DSA");
keyGenerator.initialize(1024);
KeyPair keyPair = keyGenerator.generateKeyPair();
PrivateKey privateKey = keyPair.getPrivate();
PublicKey publicKey = keyPair.getPublic();

// Print the private and public keys in hexadecimal format
System.out.println("Private Key (Hex): " + bytesToHexadecimal(privateKey.getEncoded()));
System.out.println("Public Key (Hex): " + bytesToHexadecimal(publicKey.getEncoded()));

// Generate digital signature
byte[] digitalSignature = generateSignature(userMessage, privateKey);
System.out.println("Digital Signature: " + bytesToHexadecimal(digitalSignature));

// Verify digital signature
boolean isSignatureVerified = verifyDigitalSignature(userMessage, digitalSignature, publicKey);
System.out.println("Signature Verified: " + isSignatureVerified);

userInputScanner.close();
} catch (Exception e) {
e.printStackTrace();
}
}

// Method to generate digital signature
public static byte[] generateSignature(String data, PrivateKey privateKey) throws Exception {
Signature signatureGenerator = Signature.getInstance("SHA1withDSA");
signatureGenerator.initSign(privateKey);
signatureGenerator.update(data.getBytes());
return signatureGenerator.sign();
}

// Method to verify digital signature
public static boolean verifyDigitalSignature(String data, byte[] signature, PublicKey publicKey) throws Exception {
Signature signatureVerifier = Signature.getInstance("SHA1withDSA");
signatureVerifier.initVerify(publicKey);
signatureVerifier.update(data.getBytes());
return signatureVerifier.verify(signature);
}

// Method to convert byte array to hexadecimal string
public static String bytesToHexadecimal(byte[] bytes) {
StringBuilder hexadecimalString = new StringBuilder();
for (byte b : bytes) {
String hexadecimal = Integer.toHexString(0xff & b);
if (hexadecimal.length() == 1) hexadecimalString.append('0');
hexadecimalString.append(hexadecimal);
}
return hexadecimalString.toString();
}
}


RSA:

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {

private BigInteger n, d, e;
private int bitlen = 1024;

public RSA() {
generateKeys();
}

// Generate RSA keys (public and private)
private void generateKeys() {
// Generate two large prime numbers p and q
BigInteger p = BigInteger.probablePrime(bitlen / 2, new Random());
BigInteger q = BigInteger.probablePrime(bitlen / 2, new Random());

// Calculate n = p * q
n = p.multiply(q);

// Calculate Euler's Totient Function: φ(n) = (p - 1)(q - 1)
BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

// Choose e (public exponent), typically small prime, coprime with φ(n)
e = BigInteger.valueOf(65537); // Commonly used value for e

// Calculate d (private exponent), which is the modular inverse of e mod φ(n)
d = e.modInverse(phi);
}

// Encrypt message using public key (e, n)
public BigInteger encrypt(BigInteger message) {
return message.modPow(e, n);
}

// Decrypt message using private key (d, n)
public BigInteger decrypt(BigInteger encryptedMessage) {
return encryptedMessage.modPow(d, n);
}

// Getters for the public and private keys
public BigInteger getPublicKey() {
return e;
}

public BigInteger getPrivateKey() {
return d;
}

public BigInteger getN() {
return n;
}

public static void main(String[] args) {
RSA rsa = new RSA();

// Public Key (e, n)
System.out.println("Public Key (e, n):");
System.out.println("e = " + rsa.getPublicKey());
System.out.println("n = " + rsa.getN());

// Private Key (d, n)
System.out.println("\nPrivate Key (d, n):");
System.out.println("d = " + rsa.getPrivateKey());
System.out.println("n = " + rsa.getN());

// Create scanner object to take user input
Scanner scanner = new Scanner(System.in);

// Ask for user input message
System.out.print("\nEnter a message to encrypt: ");
String message = scanner.nextLine();

// Convert the message to a BigInteger
BigInteger messageBigInt = new BigInteger(message.getBytes());

System.out.println("\nOriginal message: " + message);

// Encrypt the message
BigInteger encryptedMessage = rsa.encrypt(messageBigInt);
System.out.println("Encrypted message: " + encryptedMessage);

// Decrypt the message
BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
System.out.println("Decrypted message: " + new String(decryptedMessage.toByteArray()));

scanner.close();
}
}


SHA512:

SHA 512 import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
public class SHA512 {
public static void main(String[] args) {
Scanner inputScanner = new Scanner(System.in);
System.out.print("Enter input: ");
String userInput = inputScanner.nextLine();
String sha512Hash = generateSHA512Hash(userInput);
System.out.println("SHA-512 hash of \"" + userInput + "\": " + sha512Hash);
inputScanner.close();
}
public static String generateSHA512Hash(String userInput) {
try {
MessageDigest sha512Digest = MessageDigest.getInstance("SHA-512");
byte[] hashBytes = sha512Digest.digest(userInput.getBytes());
StringBuilder hexString = new StringBuilder();
for (byte b : hashBytes) {
String hex = Integer.toHexString(0xff & b);
if (hex.length() == 1) hexString.append('0');
hexString.append(hex);
}
return hexString.toString();
} catch (NoSuchAlgorithmException e) {
throw new RuntimeException(e);
}
}
}

Diffie:
package DigitalSignatureGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class DiffieHelman {
public static void main(String[] args) {
Scanner sc = new Scanner(System.in);

// Public parameters
System.out.print("Enter a large prime number (p): ");
BigInteger p = sc.nextBigInteger(); // Prime number
System.out.print("Enter a primitive root modulo p (g): ");
BigInteger g = sc.nextBigInteger(); // Primitive root

// Private keys (chosen randomly)
SecureRandom random = new SecureRandom();
BigInteger a = new BigInteger(p.bitLength() - 1, random); // Alice's private key
BigInteger b = new BigInteger(p.bitLength() - 1, random); // Bob's private key

// Public keys
BigInteger A = g.modPow(a, p); // Alice's public key
BigInteger B = g.modPow(b, p); // Bob's public key

System.out.println("Alice's Public Key (A): " + A);
System.out.println("Bob's Public Key (B): " + B);

// Shared secret
BigInteger sharedSecretAlice = B.modPow(a, p); // Alice's calculation
BigInteger sharedSecretBob = A.modPow(b, p); // Bob's calculation

System.out.println("Shared Secret (calculated by Alice): " + sharedSecretAlice);
System.out.println("Shared Secret (calculated by Bob): " + sharedSecretBob);

sc.close();
}
}

ElGamal:

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

public class ElGamal{
public static void main(String[] args) {
Scanner sc = new Scanner(System.in);

// Step 1: Key Generation
System.out.print("Enter a large prime number (p): ");
BigInteger p = sc.nextBigInteger();

System.out.print("Enter a primitive root modulo p (g): ");
BigInteger g = sc.nextBigInteger();

System.out.print("Enter private key (x, such that 1 < x < p-1): ");
BigInteger x = sc.nextBigInteger();

// Compute public key
BigInteger y = g.modPow(x, p); // y = g^x mod p
System.out.println("Public Key (p, g, y): (" + p + ", " + g + ", " + y + ")");
System.out.println("Private Key (x): " + x);

// Step 2: Encryption
System.out.print("Enter the message to encrypt (m): ");
BigInteger m = sc.nextBigInteger();

System.out.print("Enter a random key (k, such that 1 < k < p-1): ");
BigInteger k = sc.nextBigInteger();

BigInteger c1 = g.modPow(k, p); // c1 = g^k mod p
BigInteger c2 = (m.multiply(y.modPow(k, p))).mod(p); // c2 = m * y^k mod p
System.out.println("Ciphertext (c1, c2): (" + c1 + ", " + c2 + ")");

// Step 3: Decryption
BigInteger s = c1.modPow(x, p); // s = c1^x mod p
BigInteger sInv = s.modInverse(p); // Modular inverse of s
BigInteger decryptedMessage = (c2.multiply(sInv)).mod(p); // m = c2 * s^(-1) mod p

System.out.println("Decrypted Message: " + decryptedMessage);
sc.close();
}
}

MD5:

import java.security.MessageDigest;
import java.util.Scanner;

public class MD5 {
public static void main(String[] args) {
Scanner sc = new Scanner(System.in);

System.out.print("Enter the input message: ");
String message = sc.nextLine();

try {
// Create MD5 MessageDigest instance
MessageDigest md = MessageDigest.getInstance("MD5");

// Compute hash
byte[] hashBytes = md.digest(message.getBytes());

// Convert hash bytes to hexadecimal
StringBuilder hexString = new StringBuilder();
for (byte b : hashBytes) {
String hex = Integer.toHexString(0xff & b);
if (hex.length() == 1) hexString.append('0');
hexString.append(hex);
}

System.out.println("MD5 Hash: " + hexString.toString());

} catch (Exception e) {
System.out.println("Error computing MD5 hash: " + e.getMessage());
}
sc.close();
}
}
