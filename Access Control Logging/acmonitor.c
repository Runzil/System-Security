#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define MAX_LINE_LENGTH 1024
#define MAX_FILENAME_LENGTH 256
#define MAX_HASH_LENGTH 33
#define MAX_USERS 1000
#define MAX_user_array 1000

struct LogEntry {
    int log_id;
    char file_path[MAX_FILENAME_LENGTH];
    char date[11];
    char time[9];
    int user_id;
    int action_denied;
    char hash[MAX_HASH_LENGTH];
};



// function to identify and print users who made more than 7 unauthorized accesses
void print_malUsers(struct LogEntry entries[], size_t len) {
    // define the maximum number of users

    // initialize variables to track user information
    int user_count = 0;
    int user_array[MAX_user_array] = {0};   // Array to store unique user IDs
    int un_action[MAX_user_array] = {0};    // Array to store the count of unauthorized actions for each user

    // iterate through the log entries
    for (size_t i = 0; i < len; ++i) {
        int uid = entries[i].log_id;         // Extract user ID from the log entry
        int action_denied = entries[i].action_denied;  // Extract the flag indicating unauthorized access

        // check if the user ID is already in the user_array
        int count = 0;
        while (count < user_count && user_array[count] != uid) {
            ++count;
        }

        // if the user is not in the array, add them
        if (count == user_count) {
            user_array[user_count] = uid;
            ++user_count;
        }

        // update the count of unauthorized actions for the user
        un_action[count] += action_denied;
    }

    // Print users with 7 un_accesses or more
    for (int i = 0; i < user_count; ++i) {
        if (un_action[i] >= 7) {
            printf("User with UID %d made more than 7 unauthorized accesses\n", user_array[i]);
        }
    }

}



void readLogFile(const char *filename, struct LogEntry logs[], size_t *log_count) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_LINE_LENGTH];

    while (fgets(line, sizeof(line), file) != NULL) {
        struct LogEntry entry;

        // tokenize the line
        char *token = strtok(line, "|");
        if (token == NULL) {
            // Handle invalid lines
            continue;
        }

        // parse and store data in the struct
        entry.log_id = atoi(token);

        token = strtok(NULL, "|");
        strncpy(entry.file_path, token, sizeof(entry.file_path));

        token = strtok(NULL, "|");
        strncpy(entry.date, token, sizeof(entry.date));

        token = strtok(NULL, "|");
        strncpy(entry.time, token, sizeof(entry.time));

        token = strtok(NULL, "|");
        entry.user_id = atoi(token);

        token = strtok(NULL, "|");
        entry.action_denied = atoi(token);

        token = strtok(NULL, "|");
        size_t hash_length = strcspn(token, "\n");
        token[hash_length] = '\0';
        strncpy(entry.hash, token, sizeof(entry.hash));

        // Add the entry to the logs array
        logs[(*log_count)++] = entry;

        // Check for array overflow
        if (*log_count >= MAX_USERS) {
            fprintf(stderr, "Warning: Maximum number of users reached.\n");
            break;
        }
    }

    fclose(file);
}


void print_fileMods(struct LogEntry entries[], size_t len, const char *filename) {

    struct FileAccess {
        int uid;
        int modification_count;
    };

    struct FileAccess fileAccesses[MAX_USERS] = {0};

    for (size_t i = 0; i < len; ++i) {
        if (strcmp(entries[i].file_path, filename) == 0) {
            int uid = entries[i].log_id;

            // check if user has accessed the file before
            bool userExists = false;
            for (int j = 0; j < MAX_USERS; ++j) {
                if (fileAccesses[j].uid == uid) {
                    userExists = true;

                    // Check if the hash value has changed and not equal to 0
                    if (i > 0 && strcmp(entries[i].hash, entries[i - 1].hash) != 0 && strcmp(entries[i].hash, "0") != 0) {
                        ++fileAccesses[j].modification_count;
                    }

                    break;
                }
            }

            // if user is accessing the file for the first time, record it
            if (!userExists) {
                for (int j = 0; j < MAX_USERS; ++j) {
                    if (fileAccesses[j].uid == 0) {
                        fileAccesses[j].uid = uid;

                        // Check if the hash value has changed and not equal to 0
                        if (i > 0 && strcmp(entries[i].hash, entries[i - 1].hash) != 0 && strcmp(entries[i].hash, "0") != 0) {
                            ++fileAccesses[j].modification_count;
                        }

                        break;
                    }
                }
            }
        }
    }

    // Print the table of users and modification counts
    printf("User ID\tModifications\n");
    for (int i = 0; i < MAX_USERS && fileAccesses[i].uid != 0; ++i) {
        printf("%d\t%d\n", fileAccesses[i].uid, fileAccesses[i].modification_count);
    }
}

int main(int argc, char *argv[]) {
    struct LogEntry logs[MAX_USERS];
    size_t log_count = 0;

    // Provide the correct file path
    const char *filePath = "file_logging.log";

    FILE *file = fopen(filePath, "r");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    readLogFile(filePath, logs, &log_count);

    if (argc < 2) {
        printf("Usage: %s <options>\n", argv[0]);
        printf("-m\tPrint malicious users\n");
        printf("-i <filename>\tPrint table of users that modified the file given and the number of modifications\n");
        printf("-h\tHelp message\n");
        return 1;
    }

    if (strcmp(argv[1], "-m") == 0) {
        print_malUsers(logs, log_count);
    } 




    else if (strcmp(argv[1], "-i") == 0 && argc == 3) {
        const char *filename = argv[2];
        print_fileMods(logs, log_count, filename);




    } else if (strcmp(argv[1], "-h") == 0) {
        printf("Help message:\n");
        printf("-m\tPrint malicious users\n");
        printf("-i <filename>\tPrint table of users that modified the file given and the number of modifications\n");
        printf("-h\tHelp message\n");
    } else {
        printf("Invalid option. Use -h for help.\n");
        return 1;
    }

    return 0;
}
