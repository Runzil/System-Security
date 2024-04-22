#define _GNU_SOURCE


// include necessary headers
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

// function to recover the filename from a FILE pointer
char *recover_filename(FILE *f) {
    int fd;
    char fd_path[255];
    char *filename = malloc(255);
    ssize_t n;

    fd = fileno(f);
    sprintf(fd_path, "/proc/self/fd/%d", fd);
    n = readlink(fd_path, filename, 255);
    
    if (n < 0)
        return NULL;

    filename[n] = '\0';
    return filename;
}

// function to convert a byte array to a hexadecimal string
char *hexstring(const unsigned char *input, size_t len) {
    char *output = malloc(len * 2 + 1);
    
    for (size_t i = 0; i < len; i++) {
        sprintf(output + (i * 2), "%02x", input[i]);
    }

    return output;
}

// custom fopen function to log file accesses
FILE *fopen(const char *path, const char *mode) {
    // declare variables and retrieve original fopen function
    FILE *original_fopen_ret;
    FILE *(*original_fopen)(const char *, const char *);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    // get user ID and current time
    int uid = getuid();

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    int year, month, day, hour, min, sec;

    year = tm.tm_year + 1900;
    month = tm.tm_mon + 1;
    day = tm.tm_mday;
    hour = tm.tm_hour;
    min = tm.tm_min;
    sec = tm.tm_sec;

    int access_type = 1;
    int action_flag = 0;

    // check if file exists
    if (access(path, 0) == -1)
        access_type = 0;

    if (access_type == 1) {
        // check read permission only
        if (access(path, R_OK) == -1) {
            action_flag = 1;
            char fingerprint = '0';

            // open log file and write log entry
            FILE *log_ptr = (*original_fopen)("file_logging.log", "a+");
            fprintf(log_ptr, "%d|%s|%02d/%02d/%d|%02d:%02d:%02d|%d|%d|%c\n", uid, realpath(path,NULL), day, month, year, hour, min, sec, access_type, action_flag, fingerprint);
            fclose(log_ptr);

            return NULL;
        }
    }

    // variables for MD5 calculation
    unsigned char *string = NULL;
    unsigned char *fingerprint = NULL;

    if (access_type == 1) {
        // read file content and calculate MD5 fingerprint
        FILE *ptr1 = (*original_fopen)(path, "r+");
        fseek(ptr1, 0, SEEK_END);
        long fsize = ftell(ptr1);
        fseek(ptr1, 0, SEEK_SET);
        string = (unsigned char *)malloc(fsize + 1);
        fread(string, 1, fsize, ptr1);
        fclose(ptr1);
        fingerprint = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
        MD5(string, fsize, fingerprint);
    }

    // call the original fopen function
    original_fopen_ret = (*original_fopen)(path, mode);

    // retrieve filename and open log file
    char *path_name = recover_filename(original_fopen_ret);

    FILE *log_ptr = (*original_fopen)("file_logging.log", "a+");

    if (access_type == 1) {
        // log entry with MD5 fingerprint
        char *hex_fingerprint = hexstring(fingerprint, MD5_DIGEST_LENGTH);
        fprintf(log_ptr, "%d|%s|%02d/%02d/%d|%02d:%02d:%02d|%d|%d|%s\n", uid, path_name, day, month, year, hour, min, sec, access_type, action_flag, hex_fingerprint);
        free(hex_fingerprint);
    } else {
        // log entry for empty file or non-existing file
        fprintf(log_ptr, "%d|%s|%02d/%02d/%d|%02d:%02d:%02d|%d|%d|%s\n", uid, path_name, day, month, year, hour, min, sec, access_type, action_flag, "d41d8cd98f00b204e9800998ecf8427e");
    }

    // close log file and free allocated memory
    fclose(log_ptr);
    free(string);
    free(fingerprint);

    return original_fopen_ret;
}

// custom fwrite function to log file writes
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    // declare variables and retrieve original fwrite and fopen functions
    size_t (*original_fwrite)(const void *, size_t, size_t, FILE *);
    original_fwrite = dlsym(RTLD_NEXT, "fwrite");

    FILE *(*original_fopen)(const char *, const char *);
    original_fopen = dlsym(RTLD_NEXT, "fopen");

    // get user ID and current time
    int uid = getuid();

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    int year, month, day, hour, min, sec;

    year = tm.tm_year + 1900;
    month = tm.tm_mon + 1;
    day = tm.tm_mday;
    hour = tm.tm_hour;
    min = tm.tm_min;
    sec = tm.tm_sec;

    // retrieve filename and open log file
    char *path_name = recover_filename(stream);

    int access_type = 2;
    int action_flag = 0;

    // check if file exists
    if (access(path_name, 0) == -1)
        access_type = 0;

    if (access_type == 2) {
        // check write permissions
        if (access(path_name, W_OK) == -1) {
            action_flag = 1;

            char fingerprint = '0';

            // open log file and write log entry
            FILE *log_ptr = (*original_fopen)("file_logging.log", "a+");
            fprintf(log_ptr, "%d|%s|%02d/%02d/%d|%02d:%02d:%02d|%d|%d|%c\n", uid, path_name, day, month, year, hour, min, sec, access_type, action_flag, fingerprint);
            fclose(log_ptr);

            return 0;
        }
    }

    // variables for MD5 calculation
    long file_size = ftell(stream);
    long empty_flag = 0;

    if (file_size == 0) {
        empty_flag = 1;
        // printf("empty file\n");  // print statement for an empty file
    }

    // save the original file position
    long original_position = ftell(stream);

    // call the original fwrite function
    size_t original_fwrite_ret = original_fwrite(ptr, size, nmemb, stream);

    unsigned char *fingerprint = (unsigned char *)malloc(MD5_DIGEST_LENGTH);

    // case of writing to existing file content (appending content)
    if (empty_flag == 0){
        // calculate the MD5 fingerprint after the fwrite operation
        fseek(stream, 0, SEEK_END);
        file_size = ftell(stream);
        fseek(stream, 0, SEEK_SET);

        unsigned char *file_content = (unsigned char *)malloc(file_size);
        fread(file_content, 1, file_size, stream);

        // print ptr as a string
        // printf("Content: %.*s\n", (int)file_size, file_content);

        MD5(file_content, file_size, fingerprint);

        // restore the original file position
        fseek(stream, original_position, SEEK_SET);
        free(file_content);
    }

    // case of writing to file with empty content or erased content (rewriting content)
    else {
        // restore the original file position
        fseek(stream, original_position, SEEK_SET);

        // print ptr as a string
        // printf("Content: %.*s\n", (int)(size * nmemb), (const char *)ptr);

        MD5(ptr, size * nmemb, fingerprint);
    }

    // open log file and write log entry
    FILE *log_ptr = (*original_fopen)("file_logging.log", "a+");
    char *hex_fingerprint = hexstring(fingerprint, MD5_DIGEST_LENGTH);
    // printf("%s", hex_fingerprint);
    fprintf(log_ptr, "%d|%s|%02d/%02d/%d|%02d:%02d:%02d|%d|%d|%s\n", uid, path_name, day, month, year, hour, min, sec, access_type, action_flag, hex_fingerprint);
    fclose(log_ptr);

    // free allocated memory
    free(fingerprint);

    return original_fwrite_ret;
}
