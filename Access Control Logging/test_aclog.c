#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

void create_write_file(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (file != NULL) {
        fwrite(content, 1, strlen(content), file);
        fclose(file);
    } else {
        printf("Error creating file: %s\n", filename);
    }
}

void openAndWriteFile(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (file != NULL) {
        fwrite(content, 1, strlen(content), file);
        fclose(file);
    } else {
        printf("Error opening file: %s(Propably access denied)\n", filename);
    }
}

void modify_file(const char *filename, const char *additionalContent) {
    FILE *file = fopen(filename, "r+");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);  // Move to the end to append content
        fwrite(additionalContent, 1, strlen(additionalContent), file);
        fclose(file);
    } else {
        printf("Error modifying file: %s(Propably access denied)\n", filename);
    }
}

void changeFilePermissions(const char *filename, mode_t permissions) {
    if (chmod(filename, permissions) == -1) {
        printf("Error changing permissions for file: %s\n", filename);
    }
}

int main() {
    const char *filenames[5] = {"file_1", "file_2", "file_3", "file_4","file_5"};

    /* File Creation and Writing */
    for (int i = 0; i < 5; i++) {
        create_write_file(filenames[i], "Initial content/");
    }

    /* File Modification */
    modify_file(filenames[0], "Modified content/");
    modify_file(filenames[4], "Modified content/");


    changeFilePermissions(filenames[1], 0444);  // read-only permissions
    changeFilePermissions(filenames[2], 0222);  // write-only permissions
    changeFilePermissions(filenames[3], 0000);  // no read or write permissions

    /* File Modifications */
    for (int i = 0; i < 5; i++) {
        modify_file(filenames[i], "Modified again/");
    }

    /* File Modifications */
    for (int i = 0; i < 5; i++) {
        modify_file(filenames[i], "Modified again2/");
    }

    // modify_file("file_1","Modified again2/ ")
    
    modify_file(filenames[0],"Last modification/");


    /* File Reading */
    for (int i = 0; i < 5; i++) {
        FILE *file = fopen(filenames[i], "r");
        if (file != NULL) {
            fclose(file);
        }
    }

    /* File Modifications */
    for (int i = 0; i < 5; i++) {
        openAndWriteFile(filenames[i], "test");
    }

    return 0;
}
