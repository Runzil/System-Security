#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>
#include <gmp.h> 

int main(int argc, char *argv[]) {
    FILE *output_file = NULL;
    mpz_t p, g, a, b, public_key_a, public_key_b, shared_secret_a, shared_secret_b;
    mpz_inits(p, g, a, b, public_key_a, public_key_b, shared_secret_a, shared_secret_b, NULL);

    int opt;
    while ((opt = getopt(argc, argv, "o:p:g:a:b:h")) != -1) {
        switch (opt) {
            case 'o':
                output_file = fopen(optarg, "w");
                if (output_file == NULL) {
                    perror("can't open output file");
                    return 1;
                }
                break;
            case 'p':
                mpz_set_str(p,optarg, 10);
                break;
            case 'g':
                mpz_set_str(g,optarg, 10);
                break;
            case 'a':
                mpz_set_str(a,optarg, 10);
                break;
            case 'b':
                mpz_set_str(b,optarg, 10);
                break;
            case 'h':
                printf("Options:\n");
                printf("-o path   Path to output file\n");
                printf("-p number Prime number\n");
                printf("-g number Primitive Root for previous prime number\n");
                printf("-a number Private key A\n");
                printf("-b number Private key B\n");
                printf("-h        This help message\n");
                if (output_file) fclose(output_file);
                return 0;
            default:
                fprintf(stderr, "Usage: %s -o output_file -p prime -g generator -a private_A -b private_B\n", argv[0]);
                if (output_file) {
                	fclose(output_file);
                }
                return 1;
        }
    }
    

    if (p == 0 || g == 0 || a == 0 || b == 0) {
        fprintf(stderr, "All options -p, -g, -a, and -b must be specified.\n");
        if (output_file){ 
        	fclose(output_file);
        }
        return 1;
    }


    //calculating keys
    mpz_powm(public_key_a,g,a,p);
    mpz_powm(public_key_b,g,b,p);
    mpz_powm(shared_secret_a, public_key_b, a, p);


    if (output_file) {
        gmp_fprintf(output_file, "%Zd, %Zd, %Zd\n", public_key_a, public_key_b, shared_secret_a);
        fclose(output_file);
    } else {
        gmp_printf("Public Key A: %Zd\n", public_key_a);
        gmp_printf("Public Key B: %Zd\n", public_key_b);
        gmp_printf("Shared Secret: %Zd\n", shared_secret_a);
    }


    mpz_clears(p, g, a, b, public_key_a, public_key_b, shared_secret_a, shared_secret_b, NULL);
    return 0;
}
