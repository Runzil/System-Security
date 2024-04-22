#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <string.h> // for comparing strings
#include <stdlib.h> // for converting strings to integers

// a structure to hold public and private keys

typedef struct {
    mpz_t component1; // n component
    mpz_t component2; // e or d component
} RSAKeyComponentPair;

// Function to encode a string into an mpz_t integer
void encodeStringToMpz(const char* inputString, mpz_t result) {
    // Convert string to bytes with UTF-8 encoding
    const char* string = inputString;
    unsigned char bytes_data[256]; 

    size_t string_length = strlen(string); // Get the length of the input string
    for (size_t i = 0; i < string_length; i++) {
        bytes_data[i] = (unsigned char)string[i]; // Convert characters to bytes and store them in the array
    }

    // Convert bytes to an integer (big-endian)
    mpz_init(result);
    mpz_import(result, string_length, 1, 1, 0, 0, bytes_data);

}

// Function to decode an mpz_t integer into a string
void decodeMpzToString(const mpz_t inputInteger, char* outputString, size_t maxStringLength) {
    // Ensure the output string is null-terminated
    outputString[maxStringLength] = '\0';

    // Convert integer to bytes (big-endian) and then to a string with UTF-8 encoding
    mpz_export(outputString, NULL, 1, 1, 0, 0, inputInteger);

    // The length of the decoded string may be less than maxStringLength
    size_t actualStringLength = strlen(outputString);
    if (actualStringLength < maxStringLength) {
        outputString[actualStringLength] = '\0'; // Ensure null-termination within the specified maximum length
    }
    
}

void generate_prime_e(mpz_t e, const mpz_t lambda) {
    gmp_randstate_t state;

    // Initialize variables
    mpz_t gcd_result; // Declare gcd_result here
    mpz_inits(gcd_result, NULL);

    gmp_randinit_default(state);

    // Seed the random number generator
    unsigned long int seed = time(NULL);
    gmp_randseed_ui(state, seed);

    do {
        // Generate a random number for e
        mpz_urandomm(e, state, lambda);
        mpz_add_ui(e, e, 2); // Ensure e is greater than 1

        // Check if e meets the conditions: (e % λ(n) != 0) and (gcd(e, λ(n)) == 1)
        mpz_t gcd_result;
        mpz_init(gcd_result);

        mpz_gcd(gcd_result, e, lambda);

        if (mpz_cmp_ui(gcd_result, 1) == 0 && mpz_cmp_ui(e, 1) != 0 && mpz_cmp_ui(lambda, 0) != 0) {
            break; // Found a suitable e
        }
    } while (1);

    // Clean up
    mpz_clear(gcd_result);
    gmp_randclear(state);
}

void encryptRSA(mpz_t cipher, mpz_t message, mpz_t publicKey, mpz_t n) {
    // doing encryption: we calculate cipher = (message^publicKey) % n
    mpz_powm(cipher, message, publicKey, n);
}

void decryptRSA(mpz_t message, mpz_t cipher, mpz_t privateKey, mpz_t n) {
    // doing decryption: we calculate message = (cipher^privateKey) % n
    mpz_powm(message, cipher, privateKey, n);
}

void generateRSAKeyPair(RSAKeyComponentPair *publicKey, RSAKeyComponentPair *privateKey, int keyLength) {
    // preparing GMP variables
    mpz_t p, q, n, lambda, e, d;
    mpz_inits(p, q, n, lambda, e, d, NULL);

    // setting up a random number generator using the current time as a seed
    gmp_randstate_t rand_state;
    gmp_randinit_default(rand_state);
    gmp_randseed_ui(rand_state, time(NULL));

    // creating two random prime numbers p and q
    mpz_urandomb(p, rand_state, keyLength / 2);
    mpz_nextprime(p, p);
    mpz_urandomb(q, rand_state, keyLength / 2);
    mpz_nextprime(q, q);

    // calculating n = p * q
    mpz_mul(n, p, q);

    // calculating lambda(n) = lcm(p-1, q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);


    // Generate a suitable prime number e
    generate_prime_e(e, lambda);


    // calculating the modular multiplicative inverse of e modulo lambda
    mpz_invert(d, e, lambda);

    // setting up the public key (n, e) and private key (n, d)
    mpz_init_set(publicKey->component1, n);
    mpz_init_set(publicKey->component2, e);

    mpz_init_set(privateKey->component1, n);
    mpz_init_set(privateKey->component2, d);

    // cleaning up
    mpz_clears(p, q, n, lambda, e, d, NULL);
    gmp_randclear(rand_state);
}

void performEncryption(char *inputFile, char *outputFile, char *publicKeyFile) {
    RSAKeyComponentPair publicKey;
    mpz_t message, cipher;
    mpz_inits(publicKey.component1, publicKey.component2, message, cipher, NULL);

    // reading the public key components from publicKeyFile
    FILE *publicFile = fopen(publicKeyFile, "r");
    if (publicFile == NULL) {
        // handling a file open error
        printf("Public key file not found.");
        return;  // return early on error.
    }

    // reading the first integer (publicKey.component1)
    mpz_inp_str(publicKey.component1, publicFile, 10);
    

    // skipping the newline character
    int ch = fgetc(publicFile);
    if (ch != '\n') {
        // handling an unexpected format (no newline character)
        printf("the key components are not separated by a newline character.");
        return;  // return early on error.
    }

    // reading the second integer (publicKey.component2)
    mpz_inp_str(publicKey.component2, publicFile, 10);
   

    fclose(publicFile);

    // reading the plaintext from inputFile
    FILE *plainFile = fopen(inputFile, "r");
    if (plainFile == NULL) {
        printf("Input file not found.");
        return;  // return early on error.
    }

    // Read the plaintext as a string
    char plaintextString[4096];  // Adjust the buffer size as needed
    if (fgets(plaintextString, sizeof(plaintextString), plainFile) == NULL) {
        fprintf(stderr, "Failed to read from the input file.\n");
        fclose(plainFile);
        return;
    }
    fclose(plainFile);

    // Encode the plaintext string into an mpz_t integer
    encodeStringToMpz(plaintextString, message);

    // encrypting the data
    encryptRSA(cipher, message, publicKey.component2, publicKey.component1);

    // storing the ciphertext in outputFile
    FILE *outputFilePtr = fopen(outputFile, "w");
    mpz_out_str(outputFilePtr, 10, cipher);

    fclose(outputFilePtr);

    // cleaning up
    mpz_clears(publicKey.component1, publicKey.component2, message, cipher, NULL);
}

void performDecryption(char *inputFile, char *outputFile, char *privateKeyFile) {
    RSAKeyComponentPair privateKeyPair;
    mpz_t cipher, decrypted;

    mpz_inits(privateKeyPair.component1, privateKeyPair.component2, cipher, decrypted, NULL);

    // reading the private key components from privateKeyFile
    FILE *privateFile = fopen(privateKeyFile, "r");
    if (privateFile == NULL) {
        // handling a file open error
        printf("Private key file not found.");
        return;  // return early on error.
    }

    // reading the first integer (privateKeyPair.component1)
    mpz_inp_str(privateKeyPair.component1, privateFile, 10);

    // skipping the newline character
    int ch = fgetc(privateFile);
    if (ch != '\n') {
        // handling an unexpected format (no newline character)
        printf("the key components are not separated by a newline character.");
        return;  // return early on error.
    }

    // reading the second integer (privateKeyPair.component2)
    mpz_inp_str(privateKeyPair.component2, privateFile, 10);

    fclose(privateFile);

    // reading the ciphertext from inputFile
    FILE *cipherFile = fopen(inputFile, "r");
    if (cipherFile == NULL) {
        // handling a file open error
        printf("Input file not found.");
        return;  // return early on error.
    }


    // reading the ciphertext
    mpz_inp_str(cipher, cipherFile, 10);

    fclose(cipherFile);

    // decrypting the data
    decryptRSA(decrypted, cipher, privateKeyPair.component2, privateKeyPair.component1);

    // Convert the decrypted message to a string
    char decryptedString[4096];  // Adjust the buffer size as needed
    decodeMpzToString(decrypted, decryptedString, sizeof(decryptedString));

    // Write the decrypted message to outputFile
    FILE *outputFilePtr = fopen(outputFile, "w");
    fprintf(outputFilePtr, "%s", decryptedString);

    fclose(outputFilePtr);

    // cleaning up
    mpz_clears(privateKeyPair.component1, privateKeyPair.component2, cipher, decrypted, NULL);
}

int main(int argc, char *argv[]) {
	// Check the command line arguments and validate the input
    if (argc < 2 || (argc > 3 && argc<8) ) {
        printf("usage: %s <options>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-g") == 0) {
		// Generate an RSA key pair
        if (argc != 3) {
            printf("usage: %s -g <key_length>\n", argv[0]);
            return 1;
        }
		
		// Generate and save RSA key pair
        int keyLength = atoi(argv[2]);
        RSAKeyComponentPair publicKey, privateKey;
        mpz_inits(publicKey.component1, publicKey.component2, privateKey.component1, privateKey.component2, NULL);
        generateRSAKeyPair(&publicKey, &privateKey, keyLength);

        // saving the key pair to files with appropriate names
        char publicFileName[50], privateFileName[50];
        snprintf(publicFileName, sizeof(publicFileName), "public_%d.key", keyLength);
        snprintf(privateFileName, sizeof(privateFileName), "private_%d.key", keyLength);
        
		// Open the public and private key files for writing
        FILE *publicFile = fopen(publicFileName, "w");
        FILE *privateFile = fopen(privateFileName, "w");

		// Write the components of the public key to the public key file
        mpz_out_str(publicFile, 10, publicKey.component1);
        fprintf(publicFile, "\n");  // adding a newline between the key components
        mpz_out_str(publicFile, 10, publicKey.component2);

		// Write the components of the private key to the private key file
        mpz_out_str(privateFile, 10, privateKey.component1);
        fprintf(privateFile, "\n");  // adding a newline between the key components
        mpz_out_str(privateFile, 10, privateKey.component2);

		// Close the public and private key files
        fclose(publicFile);
        fclose(privateFile);

        mpz_clears(publicKey.component1, publicKey.component2, privateKey.component1, privateKey.component2, NULL);
    } 
    else if (strcmp(argv[7], "-e") == 0) {
		// Perform encryption
        if (argc != 8 || strcmp(argv[1], "-i") != 0 || strcmp(argv[3], "-o") != 0 || strcmp(argv[5], "-k") != 0) {
            printf("Usage: %s -i <inputFile> -o <outputFile> -k <publicKeyFile> -e\n", argv[0]);
            return 1;
        }
		
        char *inputFile = argv[2];
        char *outputFile = argv[4];
        char *publicKeyFile = argv[6];
		// Encrypt using a public key
        performEncryption(inputFile, outputFile, publicKeyFile);
    } 
    else if (strcmp(argv[7], "-d") == 0) {
		// Perform decryption
        if (argc != 8 || strcmp(argv[1], "-i") != 0 || strcmp(argv[3], "-o") != 0 || strcmp(argv[5], "-k") != 0) {
            printf("Usage: %s -i <inputFile> -o <outputFile> -k <privateKeyFile> -e\n", argv[0]);
            return 1;
        }
		// Decrypt using a private key
        char *inputFile = argv[2];
        char *outputFile = argv[4];
        char *privateKeyFile = argv[6];
        performDecryption(inputFile, outputFile, privateKeyFile);
    } 
    else if (strcmp(argv[1], "-a") == 0) {
		// Measure performance
        if (argc != 3) {
            printf("usage: %s -a <performanceFile>\n", argv[0]);
            return 1;
        }
		// Measure RSA encryption and decryption performance
        char *performanceFile = argv[2];
        FILE *perfFile = fopen(performanceFile, "w");


        int keyLengths[] = {1024, 2048, 4096};
        for (int i = 0; i < 3; i++) {
            RSAKeyComponentPair publicKey, privateKey;
            mpz_inits(publicKey.component1, publicKey.component2, NULL);
            mpz_inits(privateKey.component1, privateKey.component2, NULL);
            mpz_t message, cipher, decrypted;
            mpz_inits(message, cipher, decrypted, NULL);

            generateRSAKeyPair(&publicKey, &privateKey, keyLengths[i]);

            // Save the generated keys here
            char publicFileName[50], privateFileName[50];
            snprintf(publicFileName, sizeof(publicFileName), "public_%d.key", keyLengths[i]);
            snprintf(privateFileName, sizeof(privateFileName), "private_%d.key", keyLengths[i]);

			// Open the public and private key files
            FILE *publicFile = fopen(publicFileName, "w");
            FILE *privateFile = fopen(privateFileName, "w");

			// Save the components of the public key to the public key file
            mpz_out_str(publicFile, 10, publicKey.component1); // Write the first component
            fprintf(publicFile, "\n");  // adding a newline between the key components
            mpz_out_str(publicFile, 10, publicKey.component2); // Write the second component

			// Save the components of the private key to the private key file
            mpz_out_str(privateFile, 10, privateKey.component1); // Write the first component
            fprintf(privateFile, "\n");  // adding a newline between the key components
            mpz_out_str(privateFile, 10, privateKey.component2); // Write the second component

			// Close the public and private key files
            fclose(publicFile);
            fclose(privateFile);

			// Open the "plaintext.txt" file for reading
            FILE *file = fopen("plaintext.txt", "r");
			// Check if the file was opened successfully
            if (file == NULL) {
                // handling a file open error
                printf("Plaintext.txt file not found.");
                return 1;  // return early on error.
            }

			// Read the content from the file into a buffer
            char buffer[4096]; // Adjust the buffer size as needed
            if (fgets(buffer, sizeof(buffer), file) == NULL) {
                fprintf(stderr, "Failed to read from the plaintext.txt file.\n");
                fclose(file); // Close the file
                return 1;
            }

            // Close the file
            fclose(file);

            // encode string to mpz_t
            encodeStringToMpz(buffer,message);

            // measuring encryption time
            clock_t start = clock();
            encryptRSA(cipher, message, publicKey.component2, publicKey.component1);
            clock_t end = clock();
            double encryptTime = (double)(end - start) / CLOCKS_PER_SEC;

            // measuring decryption time
            start = clock();
            decryptRSA(decrypted, cipher, privateKey.component2, privateKey.component1);
            end = clock();
            double decryptTime = (double)(end - start) / CLOCKS_PER_SEC;

            char decrypted_string[4096];

            // decode mpz_t to string
            decodeMpzToString(decrypted,decrypted_string, sizeof(decrypted_string));

            // printing results and saving to performanceFile
            gmp_fprintf(perfFile, "key length: %d bits\n", keyLengths[i]);
            gmp_fprintf(perfFile, "original message: %s\n", buffer);
            gmp_fprintf(perfFile, "ciphertext: %Zd\n", cipher);
            gmp_fprintf(perfFile, "decrypted message: %s\n", decrypted_string);
            fprintf(perfFile, "encryption time: %f seconds\n", encryptTime);
            fprintf(perfFile, "decryption time: %f seconds\n\n", decryptTime);

            mpz_clears(publicKey.component1, publicKey.component2, privateKey.component1, privateKey.component2, NULL);
            mpz_clears(message, cipher, decrypted, NULL);
        }

        fclose(perfFile);
    } 
    else {
        printf("invalid option: %s\n", argv[1]);
        return 1;
    }

    return 0;
}

