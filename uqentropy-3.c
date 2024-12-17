#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <getopt.h>
// Defining the maximum size for the password that needs to be read from the
// Input stream
#define MAX_BUFFER_SIZE 100 // maximum input buffer size
#define MAX_PASSWORD_LENGTH 100 // maximum password buffer size
const int commandLineExitStatus = 13; // exit status for the Command Line
const int noStrongExitStatus
        = 15; // exit status for the no strong password condition
const int fileCheckExitStatus = 19; // exit status for the file check

// This funciton is to check the command line validity of the program.
// REF: It is inspired from the code at:
// REF:https://www.gnu.org/software/libc/manual/html_node
// REF: /Getopt-Long-Option-Example.html
void support_commandline_check(char** commands, const int* opt, int* checkCase,
        int* isError, int* leet, int* digitAppend, int* doubles,
        int* digitToAppend)
{
    const int upper = 8;
    const int lower = 1;
    switch (*opt) {
    case 'c':
        if (strcmp(commands[optind - 1], "--checkcase") == 0) {
            *checkCase += 1;
        } else {
            *isError = 1;
        }
        break;
    case 'l':
        if (strcmp(commands[optind - 1], "--leet") == 0) {
            *leet += 1;
        } else {
            *isError = 1;
        }
        break;
    case 'd':
        if (strcmp(commands[optind - 2], "--digit-append") == 0) {
            *digitAppend += 1;
            if ((atoi(optarg) < lower) || (atoi(optarg) > upper)) {
                *isError = 1; // if the number is not within the range it
                              // sets the error vvariable to 1
            } else {
                *digitToAppend = atoi(optarg);
            }
        }
        break;
    case 'x':
        if (strcmp(commands[optind - 1], "--double") == 0) {
            *doubles += 1;
        } else {
            *isError = 1;
        }
        break;
    case ':':
        *isError = 1;
        break;
    case '?':
        *isError = 1;
        break;
    default:
        *isError = 1;
        break;
    }
}

/*The function determine_command_validity() determines the validity of the
 * command line arguments. arg1 : number of command line arguments arg2: command
 * line argumemts. arg3-arg4: flags for required command line arguments. arg5:
 * flag variable for checking whether an error has occured. arg6: location of
 * the first filename in the command line arguments.
 */
void determine_commandline_validity(int numCommands, char** commands,
        int* checkCase, int* digitAppend, int* doubles, int* leet, int* isError,
        int* firstFile, int* digitToAppend)
{
    int opt;
    int isFile;
    int optIndex = 0;
    // REF: The following code is inspired from the code at:
    // REF: https://www.gnu.org/software/libc/manual/html_node
    // REF: /Getopt-Long-Option-Example.html
    static struct option longOptions[] = {{"checkcase", no_argument, 0, 'c'},
            {"leet", no_argument, 0, 'l'},
            {"digit-append", required_argument, 0, 'd'},
            {"double", no_argument, 0, 'x'}, {0, 0, 0, 0}};
    // getopt_long_only function to handle the command line arguments
    // for each command line arguments that have been found, we increment the
    // corresponding flag variable
    while ((opt = getopt_long_only(
                    numCommands, commands, "+:", longOptions, &optIndex))
            != -1) {
        support_commandline_check(commands, &opt, checkCase, isError, leet,
                digitAppend, doubles, digitToAppend);
        // to check whether a valid command line arguments is provided more than
        // once.
        if (*checkCase > 1 || *digitAppend > 1 || *doubles > 1 || *leet > 1) {
            *isError = 1;
            return;
        }
    }
    // below if block for geting the first file location.
    if (optind < numCommands && strcmp(commands[optind], "") != 0) {
        isFile = 1;
        *firstFile = optind;
    } else {
        *isError = 1;
    }
    // to check whether the file name is provided if other valid command line
    // arguments are provided
    if ((checkCase || doubles || leet || digitAppend) && !isFile) {
        *isError = 1;
    }
}

/*The function is_valid_password() is to check the validity of user
 * entered password.
 * arg1: the password user have entered
 * returns 0: if the length of the password is 0, contains a space character and
 * contains non printable characters.
 * return 1: if it is a valid password
 */
int is_valid_password(char* password)
{
    // checking the string has atleast one character
    if (strlen(password) == 0) {
        return 0;
    }
    for (int i = 0; password[i] != '\0'; ++i) {
        // checking if password contains white spces
        if (isspace(password[i])) {
            return 0;
        }
        // checking if it contains any non printable characters

        if (!isprint(password[i])) {
            return 0;
        }
    }
    return 1;
}

/* The function file_checking() is to check the validity of the files and the
 * passwords in those. It also loads the passwords into a char** array for
 * further processing and calculation of entropy2. arg1(argc): no of command
 * line arguments. arg2:argc- represents the command line arguments. arg3:
 * firstFileLoc- represents the first file location in the command line. arg4:
 * firleError- flag vaiarble for checking file Error.
 */
char** file_checking(int argc, char** argv, const int* firstFileLoc,
        int* fileError, int* totalPasswords)
{
    char** passwords = malloc(1 * sizeof(char*)); // buffer for the passwords
    for (int i = *firstFileLoc; i < argc; i++) {
        FILE* fread = fopen(argv[i], "r");
        if (!fread) {
            *fileError = 1;
            fprintf(stderr, "uqentropy: can't read from password file \"%s\"\n",
                    argv[i]);
            continue;
        }
        int ch; // for each character of the each passwords.
        int pos = 0;
        int numPasswords = 0;
        char buffer[MAX_PASSWORD_LENGTH];
        while ((ch = fgetc(fread)) != EOF) {
            if (isspace(ch)) { // checking whether the character is a space.
                if (pos > 0) {
                    buffer[pos] = '\0';
                    passwords = realloc(passwords,
                            (*totalPasswords + numPasswords + 1)
                                    * sizeof(char*));
                    passwords[numPasswords + (*totalPasswords)]
                            = strdup(buffer);
                    numPasswords++;
                    pos = 0;
                }
            } else {
                if (pos < MAX_PASSWORD_LENGTH) {
                    if (!isprint(ch)) { // to check if it is printable
                        *fileError = 1;
                        fprintf(stderr,
                                "uqentropy: invalid character found in file "
                                "\"%s\"\n",
                                argv[i]);
                        break;
                    }
                    buffer[pos++] = ch;
                }
            }
        }
        if (numPasswords == 0 && !*fileError) {
            *fileError = 1;
            fprintf(stderr, "uqentropy: no valid passwords in file \"%s\"\n",
                    argv[i]);
            continue;
        }
        *totalPasswords += numPasswords;
        fclose(fread);
    }
    return passwords;
}

/* The function determine_character_set() is to determine the total character
 * set used in tha password.
 * arg1: the password entered by the user.
 * return: the total character set of the password.
 * The function checks if a character is digit, lower character, upper character
 * or special character. If it finds one it will add the corresponding set size
 * to the setSize variable and changes the corresponding variable to determine
 * if a particular set have been visited or not to 1. This ensures each
 * set is added once.
 * If all the character set in the passwordare visited atleast once the function
 * returns the total set size.
 */
int determine_character_set(const char* password)
{
    int digits = 0;
    int lowerChar = 0;
    int upperChar = 0;
    int specialChar = 0;
    int setSize = 0;
    const int digitSet = 10;
    const int alphSet = 26;
    const int specialSet = 32;
    for (int i = 0; password[i] != '\0'; ++i) {
        if (isdigit(password[i]) && digits == 0) {
            setSize += digitSet;
            digits = 1;

        } else if (islower(password[i]) && lowerChar == 0) {
            setSize += alphSet;
            lowerChar = 1;

        } else if (isupper(password[i]) && upperChar == 0) {
            setSize += alphSet;
            upperChar = 1;

        } else if (!isalnum(password[i]) && specialChar == 0) {
            setSize += specialSet;
            specialChar = 1;
        }
    }
    return setSize;
}

// The function calcualtes the first entropy of the password
double calc_first_entropy(int setSize, int passLength)
{
    const int floorHelper = 10;
    return floor((passLength * (log2(setSize))) * floorHelper) / floorHelper;
}

// The function calc_second_entropy() calculates the sentropy e2
double calc_second_entropy(int matchNumber)
{
    const int floorHelper = 10;
    return floor(log2(2 * matchNumber) * floorHelper) / floorHelper;
}

// The fucntion find_passwords_from_file() check whether the user entered
// password is present in any of the files specified in the command line
// arguments.
// arg1: passwords read from the file(s) provided in command line.
// arg2: user entered password.
// arg3: total passwords that have read from files.
// arg5: match number which tracks the number of comparisons made.
// returns 1 is a match is found otherwise returns 0.
int find_passwords_from_file(char** passwords, char* userPassword,
        int totalPasswords, unsigned long* matchNumber)
{
    for (int i = 0; i < totalPasswords; ++i) {
        (*matchNumber)++;
        if (strcmp(passwords[i], userPassword) == 0) {
            return 1;
        }
    }
    return 0;
}

// The fucntion find_passwords_from_file() check whether the user entered
//  password is present in any of the files specified in the command line
//  arguments.
//  arg1: passwords read from the file(s) provided in command line.
//  arg2: user entered password.
//  arg3: total passwords that have read from files.
//  arg4: match number which tracks the number of comparisons made.
//  returns 1 is a match is found otherwise returns 0.
int case_check(char** passwords, char* userPassword, int totalPasswords,
        unsigned long* matchNumber)
{
    int j;
    int noAlpha;
    for (int i = 0; i < totalPasswords; ++i) {
        j = 0;
        noAlpha = 0;
        while ((passwords[i][j] != '\0')) {
            if (isalpha(passwords[i][j])) {
                noAlpha++;
            }
            j++;
        }

        *matchNumber += pow(2, noAlpha) - 1;
        if (strcasecmp(passwords[i], userPassword) == 0) {
            return 1;
        }
    }
    return 0;
}

/* The function digit_append_check() check whether a password match can be found
 * using the digit passed through the command line argument.
 * arg1: passwords read from the file.
 * arg2: user entered password arg3: total passwords that have read from
 * the file.
 * arg4: macth Numner which tracks the number of comparisons made.
 * arg5: digit passed through the command line.
 * return 1: if a password match have been found, otherwise 0.
 */
int digit_append_check(char** passwords, char* userPassword, int totalPasswords,
        unsigned long* matchNumber, const int* appendDigit)
{
    const int base = 10; // base constant for calculating power.
    const int incrementor = 11; // constant for incrementing matchNumber
    int j = strlen(userPassword) - 1;
    int userDigitStartPos = 0; // starting position of the digits at the end in
                               // the user password
    while (isdigit(userPassword[j]) && j >= 0) {
        j--;
    }
    userDigitStartPos = j + 1;
    // loop until we iterate every passwords
    for (int i = 0; i < totalPasswords; i++) {
        // comapre passwords without a number at the end from the files.
        if ((!isdigit(passwords[i][strlen(passwords[i]) - 1]))) {
            if (strlen(passwords[i])
                            + (strlen(userPassword) - userDigitStartPos)
                    == strlen(userPassword)) {
                if (strncmp(passwords[i], userPassword,
                            (strlen(userPassword) - *appendDigit))
                        == 0) {
                    if (strlen(userPassword + j + 1) < 2) {
                        *matchNumber += atoi(userPassword + j + 1);
                        *matchNumber += 1;
                        return 1;
                    }
                    *matchNumber += atoi(userPassword + j + 1);
                    *matchNumber += incrementor;
                    return 1;
                }
            }
            // if a match is not found we increment the matchNumber by the
            // following method
            for (int k = 1; k <= *appendDigit; k++) {
                *matchNumber += pow(base, k);
            }
        }
    }
    return 0;
}

/* The function double_check() check whether a password match can be found
 * using the --double passed through the command line argument.
 * arg1: passwords read from the file.
 * arg2: user entered password
 * arg3: total passwords that
 * have read from the file.
 * arg4: macth Numner which tracks the number of comparisons made.
 * return 1: if a password match have been found, otherwise 0.
 */
int double_check(char** passwords, char* userPassword, int totalPasswords,
        unsigned long* matchNumber)
{
    for (int i = 0; i < totalPasswords; ++i) {
        // check whether the length of entry in the password file is less than
        // the length of the user entered password.
        if (strlen(passwords[i]) <= strlen(userPassword)) {
            // check whether the password entry and user entered password are
            // same using the strncmp() function with length of the password
            // from the files
            if (strncmp(passwords[i], userPassword, strlen(passwords[i]))
                    == 0) {
                for (int j = 0; j < totalPasswords; ++j) {
                    // if the comparison is successfull it will compare the
                    // remaining part of the user entered password with each
                    // entry of the password file.
                    if (strcmp(passwords[j],
                                userPassword + strlen(passwords[i]))
                            == 0) {
                        *matchNumber
                                = (*matchNumber) + (i * totalPasswords) + j + 1;
                        return 1;
                    }
                }
            }
        }
    }
    // If no match has been found incremen the match number by n*n
    *matchNumber = *matchNumber + (totalPasswords * totalPasswords);
    return 0;
}

// The function check_char_by_replacing() finds the orginal characters in the
// user entered password
int check_char_by_replacing(char userp, char entryp)
{
    if (userp == '@' || userp == '4') {
        return (tolower(entryp) == 'a');
    }
    if (userp == '6') {
        return (tolower(entryp) == 'b' || tolower(entryp) == 'g');
    }
    if (userp == '8') {
        return toupper(entryp) == 'B';
    }
    if (userp == '3') {
        return tolower(entryp) == 'e';
    }
    if (userp == '9') {
        return tolower(entryp) == 'g';
    }
    if (userp == '1' || userp == '!') {
        return (tolower(entryp) == 'i' || tolower(entryp) == 'l');
    }
    if (userp == '0') {
        return tolower(entryp) == 'o';
    }
    if (userp == '5' || userp == '$') {
        return tolower(entryp) == 's';
    }
    if (userp == '7' || userp == '+') {
        return tolower(entryp) == 't';
    }
    if (userp == '%') {
        return tolower(entryp) == 'x';
    }
    if (userp == '1' || userp == '!') {
        return tolower(entryp) == 'z';
    }
    return 0;
}

/*The function leet_check() performs the functionality for --leet argument.
 */
int leet_check(char** passwords, char* userPassword, int totalPasswords,
        unsigned long* matchNumber)
{
    int isChar = 0;
    int noSingleChar; // for no of letters that can be replaced by one
                      // character.
    int noDoubleChar; // for keeping track of no of letters that can be
                      // substitued by two values
    int charEquality = 0;
    const int baseForDoubleChar = 3;
    for (int i = 0; i < totalPasswords; i++) {
        noSingleChar = 0;
        noDoubleChar = 0;
        for (int k = 0; k < (int)strlen(passwords[i]); k++) {
            char c = tolower(passwords[i][k]);
            // if any of the characters 'a','b','g','i','s','t' is present in an
            // entry of the password file it increments the noDoubleChar by one.
            if (c == 'a' || c == 'b' || c == 'g' || c == 'i' || c == 's'
                    || c == 't') {
                noDoubleChar += 1;
            } else if (c == 'e' || c == 'l' || c == 'o' || c == 'x'
                    || c == 'z') {
                noSingleChar += 1;
            }
        }
        // increementing the matchNumber for reach entries in the files.
        *matchNumber = (*matchNumber)
                + (pow(2, noSingleChar) * pow(baseForDoubleChar, noDoubleChar))
                - 1;
        if (strlen(passwords[i]) == strlen(userPassword)) {
            charEquality = 0;
            for (int j = 0; j < (int)strlen(passwords[i]); ++j) {
                if (passwords[i][j] == userPassword[j]) {
                    charEquality++;
                    continue;
                }
                isChar = check_char_by_replacing(
                        userPassword[j], passwords[i][j]);
                if (!isChar) {
                    break;
                }
                charEquality++;
            }
            if (charEquality == (int)strlen(passwords[i])) {
                return 1;
            }
        }
    }
    return 0;
}

/*The function determine_password_strength() determines the password strength
 * using the calculated entropy.
 * arg1: entropy of the password
 * returns 0: if it has weak and very weak passwords.
 * returns 1: otherwise
 */
int determine_password_strength(int entropy)
{
    const int weak = 60;
    const int veryWeak = 35;
    const int strong = 120;
    if (entropy < veryWeak) {
        fprintf(stdout, "Password strength rating: very weak\n");
        return 0;
    }
    if (entropy >= veryWeak && entropy < weak) {
        fprintf(stdout, "Password strength rating: weak\n");
        return 0;
    }
    if (entropy >= weak && entropy < strong) {
        fprintf(stdout, "Password strength rating: strong\n");
        return 1;
    }
    fprintf(stdout, "Password strength rating: very strong\n");
    return 1;
}

/*The function calculate_overall_entropy() helps in calculating the overall
 * entropy of the password.
 */
double calculate_overall_entropy(int checkCaseFlag, int digitAppendFlag,
        int doubleFlag, int leetFlag, int totalPasswords, int digitToAppend,
        char** passwords, int firstFileLoc, double entropy1, double entropy2,
        int totalSetSize, int entropy2Flag, int passwordFound, char* password)
{
    unsigned long matchNumber = 0;
    // finding the total set size
    totalSetSize = determine_character_set(password);
    // calculating entropy 1
    entropy1 = calc_first_entropy(totalSetSize, strlen(password));
    passwordFound = find_passwords_from_file(
            passwords, password, totalPasswords, &matchNumber);
    if (!passwordFound && checkCaseFlag) {
        passwordFound
                = case_check(passwords, password, totalPasswords, &matchNumber);
    }
    if (!passwordFound && digitAppendFlag) {
        passwordFound = digit_append_check(passwords, password, totalPasswords,
                &matchNumber, &digitToAppend);
    }
    if (!passwordFound && doubleFlag) {
        passwordFound = double_check(
                passwords, password, totalPasswords, &matchNumber);
    }
    if (!passwordFound && leetFlag) {
        passwordFound
                = leet_check(passwords, password, totalPasswords, &matchNumber);
    }
    // if there is a password found calculate the second entropy.
    if (matchNumber >= 1 && passwordFound) {
        entropy2Flag = 1;
        entropy2 = calc_second_entropy(matchNumber);
        fprintf(stdout,
                "Candidate password would be matched on guess number "
                "%ld\n",
                matchNumber);
    }
    if (!passwordFound && firstFileLoc) {
        fprintf(stdout, "No match found after checking %ld passwords\n",
                matchNumber);
    }
    if (!entropy2Flag) {
        entropy2 = entropy1;
    }
    return (entropy1 < entropy2) ? entropy1 : entropy2;
}

void support_main(int checkCaseFlag, int digitAppendFlag, int doubleFlag,
        int leetFlag, int totalPasswords, int digitToAppend, char** passwords,
        int firstFileLoc)
{
    char buffer[MAX_BUFFER_SIZE];
    int totalSetSize = 0, entropy2Flag = 0, strongPasswords = 0;
    double entropy1 = 0.0, entropy2 = 0.0, finalEntropy = 0.0;
    fprintf(stdout, "Welcome to UQEntropy!\n");
    fprintf(stdout, "Written by s4851488.\n");
    fprintf(stdout, "Enter possible passwords to check their strength.\n");
    // Reading the user input from stdin
    char* password = fgets(buffer, MAX_BUFFER_SIZE, stdin);
    while (password != NULL) {
        entropy1 = 0.0, entropy2 = 0.0, finalEntropy = 0.0, entropy2Flag = 0.0;
        int passwordFound = 0;
        password[strlen(password) - 1] = '\0';
        if (is_valid_password(password) == 1) {
            finalEntropy = calculate_overall_entropy(checkCaseFlag,
                    digitAppendFlag, doubleFlag, leetFlag, totalPasswords,
                    digitToAppend, passwords, firstFileLoc, entropy1, entropy2,
                    totalSetSize, entropy2Flag, passwordFound, password);
            fprintf(stdout, "Password entropy calculated to be %.1f\n",
                    finalEntropy);
            if (determine_password_strength(finalEntropy)) {
                strongPasswords = 1;
            }
        } else {
            fprintf(stderr, "Invalid password\n");
        }
        password = fgets(buffer, MAX_BUFFER_SIZE, stdin);
    }
    free(password);
    for (int i = 0; i < totalPasswords; i++) {
        free(passwords[i]);
    }
    free(passwords);
    if (!strongPasswords) {
        fprintf(stdout, "No strong password(s) entered\n");
        exit(noStrongExitStatus);
    }
}

// Main controller function of the entropy program;
int main(int argc, char** argv)
{
    int checkCaseFlag = 0;
    int digitAppendFlag = 0;
    int doubleFlag = 0;
    int leetFlag = 0;
    int firstFileLoc = 0;
    int errorFlag = 0;
    int fileError = 0;
    int totalPasswords = 0;
    int digitToAppend = 0;
    char** passwords = NULL;
    // checking the command line validity.
    if (argc > 1) {
        determine_commandline_validity(argc, argv, &checkCaseFlag,
                &digitAppendFlag, &doubleFlag, &leetFlag, &errorFlag,
                &firstFileLoc, &digitToAppend);
        if (errorFlag && argc > 1) {
            fprintf(stderr,
                    "Usage: ./uqentropy [--digit-append 1..8] [--checkcase] "
                    "[--double] [--leet] [filename ...]\n");
            exit(commandLineExitStatus);
        }
        // file validity checking
        passwords = file_checking(
                argc, argv, &firstFileLoc, &fileError, &totalPasswords);
        if (fileError) {
            exit(fileCheckExitStatus);
        }
    }
    support_main(checkCaseFlag, digitAppendFlag, doubleFlag, leetFlag,
            totalPasswords, digitToAppend, passwords, firstFileLoc);
    exit(0);
}
