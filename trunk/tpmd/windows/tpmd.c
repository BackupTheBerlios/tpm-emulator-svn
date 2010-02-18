/* Software-based Trusted Platform Module (TPM) Emulator
 * Copyright (C) 2004-2010 Mario Strasser <mast@gmx.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * $Id: tpmd.c 389 2010-02-18 09:52:11Z mast $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <windows.h>
#include <wincrypt.h>
#include "config.h"
#include "tpm/tpm_emulator.h"

#define SERVICE_NAME "tpmd"

static volatile int stopflag = 0;
static int is_service = 0;
static int opt_debug = 0;
static int opt_foreground = 0;
static const char *opt_pipe_name = TPM_DEVICE_NAME;
static const char *opt_storage_file = TPM_STORAGE_NAME;
static const char *opt_log_file = TPM_LOG_FILE;
static int tpm_startup = 2;
static uint32_t tpm_config = 0;
static HCRYPTPROV rand_ch;
static SERVICE_STATUS_HANDLE status_handle;
static DWORD current_status;

void *tpm_malloc(size_t size)
{
  return malloc(size);
}

void tpm_free(/*const*/ void *ptr)
{
  if (ptr != NULL) free((void*)ptr);
}

void tpm_log(int priority, const char *fmt, ...)
{
    FILE *file;
    va_list ap, bp;
    va_start(ap, fmt);
    va_copy(bp, ap);
    file = fopen(opt_log_file, "a");
    if (file != NULL) {
        vfprintf(file, fmt, ap);
        fclose(file);
    }
    va_end(ap);
    if (!is_service && (priority != TPM_LOG_DEBUG || opt_debug)) {
        vprintf(fmt, bp);
    }
    va_end(bp);
}

void tpm_get_extern_random_bytes(void *buf, size_t nbytes)
{
  CryptGenRandom(rand_ch, nbytes, (BYTE*)buf);
}

uint64_t tpm_get_ticks(void)
{
    static uint64_t old_t = 0;
    uint64_t new_t, res_t;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    new_t = (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
    res_t = (old_t > 0) ? new_t - old_t : 0;
    old_t = new_t;
    return res_t;
}

int tpm_write_to_storage(uint8_t *data, size_t data_length)
{
    int fh;
    ssize_t res;
    fh = open(opt_storage_file, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY,
              S_IRUSR | S_IWUSR);
    if (fh < 0) return -1;
    while (data_length > 0) {
        res = write(fh, data, data_length);
        if (res < 0) {
            close(fh);
            return -1;
        }
        data_length -= res; 
        data += res;
    }
    close(fh);
    return 0;
}

int tpm_read_from_storage(uint8_t **data, size_t *data_length)
{
    int fh;
    ssize_t res;
    size_t total_length;
    fh = open(opt_storage_file, O_RDONLY | O_BINARY);
    if (fh < 0) return -1;
    total_length = lseek(fh, 0, SEEK_END);
    lseek(fh, 0, SEEK_SET);
    *data = tpm_malloc(total_length);
    if (*data == NULL) {
        close(fh);
        return -1;
    }
    *data_length = 0;
    while (total_length > 0) {
        res = read(fh, &(*data)[*data_length], total_length);
        if (res < 0) {
            close(fh);
            tpm_free(*data);
            return -1;
        }
        if (res == 0) break;
        *data_length += res;
        total_length -= res;
    }
    close(fh);
    return 0;
}

static void print_usage(char *name)
{
    printf("usage: %s [-d] [-f] [-s storage file] [-u windows pipe name] "
           "[-l log file] [-h] [startup mode]\n", name);
    printf("  d : enable debug mode\n");
    printf("  f : forces the application to run in the foreground\n");
    printf("  s : storage file to use (default: %s)\n", opt_storage_file);
    printf("  u : windows named pipe name to use (default: %s)\n", opt_pipe_name);
    printf("  l : name of the log file (default: %s)\n", opt_log_file);
    printf("  h : print this help message\n");
    printf("  startup mode : must be 'clear', "
           "'save' (default) or 'deactivated\n");
}

static int parse_options(int argc, char **argv)
{
    char c;
    info("parsing options");
    while ((c = getopt (argc, argv, "dfs:u:o:g:c:h")) != -1) {
        debug("handling option '-%c'", c);
        switch (c) {
            case 'd':
                opt_debug = 1;
                debug("debug mode enabled");
                break;
            case 'f':
                debug("application is forced to run in foreground");
                opt_foreground = 1;
                break;
            case 's':
                opt_storage_file = optarg;
                debug("using storage file '%s'", opt_storage_file);
                break;
            case 'u':
                opt_pipe_name = optarg;
                debug("using named pipe '%s'", opt_pipe_name);
                break;
            case 'l':
                opt_log_file = optarg;
                debug("using log file '%s'", opt_log_file);
                break;
            case 'c':
                tpm_config = strtol(optarg, NULL, 0);
                break;
            case '?':
                error("unknown option '-%c'", optopt);
                print_usage(argv[0]);
                return -1;
            case 'h':
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    if (optind < argc) {
        debug("startup mode = '%s'", argv[optind]);
        if (!strcmp(argv[optind], "clear")) {
            tpm_startup = 1;
        } else if (!strcmp(argv[optind], "save")) {
            tpm_startup = 2;
        } else if (!strcmp(argv[optind], "deactivated")) {
            tpm_startup = 3;
        } else {
            error("invalid startup mode '%s'; must be 'clear', "
                  "'save' (default) or 'deactivated", argv[optind]);
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        }
    } else {
        /* if no startup mode is given assume save if a configuration
           file is available, clear otherwise */
        int fh = open(opt_storage_file, O_RDONLY);
        if (fh < 0) {
            tpm_startup = 1;
            info("no startup mode was specified; asuming 'clear'");
        } else {
            tpm_startup = 2;
            close(fh);
        }
    }
    return 0;
}

static const char *get_error(void)
{
    static char buf[512];
    memset(buf, 0, sizeof(buf));
    FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM,
                  "", GetLastError(), 0, buf, sizeof(buf), NULL);
    return buf;
}

static int init_random(void)
{
    info("initializing crypto context for RNG");
    BOOL res = CryptAcquireContext(&rand_ch, NULL, NULL,
                                   PROV_RSA_FULL, CRYPT_SILENT);
    if (!res) {
        /* try it again with CRYPT_NEWKEYSET enabled */
        res = CryptAcquireContext(&rand_ch, NULL, NULL,
                                  PROV_RSA_FULL, CRYPT_SILENT | CRYPT_NEWKEYSET);
    }
    if (!res) {
        error("CryptAcquireContext() failed: %s", get_error());
        return -1;
    }
    return 0;
}

BOOL signal_handler(DWORD event)
{
    info("signal received: %d", event);
    stopflag = 1;
    /* unblock ConnectNamedPipe() */
    HANDLE ph = CreateFile(opt_pipe_name, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (ph != INVALID_HANDLE_VALUE) CloseHandle(ph);
    return TRUE;
}

static int init_signal_handler(void)
{
    info("installing signal handler");
    if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)signal_handler,TRUE)) {
        error("SetConsoleCtrlHandler() failed: %s", get_error());
        return -1;
    }
    return 0;
}

static int mkdirs(const char *path)
{
    char *copy = strdup(path);
    char *p = strchr(copy + 1, '/');
    while (p != NULL) {
        *p = '\0';
        if ((mkdir(copy) == -1) && (errno != EEXIST)) {
            free(copy);
            return errno;
        }
        *p = '/';
        p = strchr(p + 1, '/');
    }
    free(copy);
    return 0;
}

static void main_loop(void)
{
    HANDLE ph;
    DWORD in_len;
    uint32_t out_len;
    BYTE in[TPM_CMD_BUF_SIZE];
    uint8_t *out;

    info("staring main loop");
    /* open named pipe */
    ph = CreateNamedPipe(opt_pipe_name, PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES, TPM_CMD_BUF_SIZE,
      TPM_CMD_BUF_SIZE, 0, NULL);
    if (ph == INVALID_HANDLE_VALUE) {
         error("CreateNamedPipe() failed: %s", get_error());
         return;
    }
    /* init tpm emulator */
    mkdirs(opt_storage_file);
    debug("initializing TPM emulator");
    tpm_emulator_init(tpm_startup, tpm_config);
    /* start command processing */
    while (!stopflag) {
        /* wait for incomming connections */
        debug("waiting for connections...");
        if (!ConnectNamedPipe(ph, NULL)) {
            error("ConnectNamedPipe() failed: %s", get_error());
            break;
        }
        if (stopflag) break;
        /* receive and handle commands */
        in_len = 0;
        do {
            if (!ReadFile(ph, in, sizeof(in), &in_len, NULL)) {
                error("ReadFile() failed: %s", get_error());
            }
            if (in_len > 0) {
                debug("received %d bytes", in_len);
                out = NULL;
                if (tpm_handle_command(in, in_len, &out, &out_len) != 0) {
                    error("tpm_handle_command() failed");
                } else {
                    debug("sending %d bytes", out_len);
                    DWORD res, len = 0;
                    while (len < out_len) {
                        if (!WriteFile(ph, out, out_len, &res, NULL)) {
                            error("WriteFile(%d) failed: %s",
                                  out_len - len, strerror(errno));
                            break;
                        }
                        len += res;
                    }
                    tpm_free(out);
                }
            }
        } while (in_len > 0 && !stopflag);
        DisconnectNamedPipe(ph);
    }
    /* shutdown tpm emulator */
    tpm_emulator_shutdown();
    /* close socket */
    CloseHandle(ph);
    info("main loop stopped");
}

BOOL updateServiceStatus(DWORD currentState, DWORD winExitCode,
                         DWORD exitCode, DWORD checkPoint, DWORD waitHint)
{ 
   SERVICE_STATUS status;
  
   /* if this is a service update the status, otherwise return success */
   if (!is_service) return TRUE;
   current_status = currentState;
   status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
   status.dwCurrentState = currentState;
   /* once the service is up and running, it accepts
      the events stop and shutdown */
   if (currentState == SERVICE_START_PENDING) {
      status.dwControlsAccepted = 0;
   } else {
      status.dwControlsAccepted = SERVICE_ACCEPT_STOP 
                                  | SERVICE_ACCEPT_SHUTDOWN;
   }
   status.dwWin32ExitCode = winExitCode;
   status.dwServiceSpecificExitCode = exitCode;
   status.dwCheckPoint = checkPoint;
   status.dwWaitHint = waitHint;
   return SetServiceStatus(status_handle, &status);
}

void serviceCtrlHandler(DWORD code)
{
    switch (code) {
        /* stop service if told so or in the case of a system shutdown */
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            updateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 1, 5000);
            signal_handler(CTRL_CLOSE_EVENT);
            break;
        /* report the current status of the service to the SCM */
        case SERVICE_CONTROL_INTERROGATE:
            updateServiceStatus(current_status, NO_ERROR, 0, 0, 0);
            break;
    }
}

void serviceMain(int argc, char **argv)
{
    info("starting TPM Emulator daemon (1.2.%d.%d-%d)",
         VERSION_MAJOR, VERSION_MINOR, VERSION_BUILD);
    if (argc > 0 && parse_options(argc, argv) != 0) {
        updateServiceStatus(SERVICE_STOPPED,
                            ERROR_SERVICE_SPECIFIC_ERROR, 1, 0, 0);
        return;
    }
    /* init logging */
    mkdirs(opt_log_file);
    /* init signal handler */
    if (init_signal_handler() != 0) {
        updateServiceStatus(SERVICE_STOPPED,
                            ERROR_SERVICE_SPECIFIC_ERROR, 1, 0, 0);
        return;
    }
    /* init random number generator */
    if (init_random() != 0) {
        updateServiceStatus(SERVICE_STOPPED,
                            ERROR_SERVICE_SPECIFIC_ERROR, 1, 0, 0);
        return;
    }
    /* start main processing loop */
    main_loop();
    info("stopping TPM Emulator daemon");
    CryptReleaseContext(rand_ch, 0);
    updateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);
}

int main(int argc, char **argv)
{
    if (parse_options(argc, argv) != 0) return EXIT_FAILURE;
    if (opt_foreground) {
        is_service = 0;
        serviceMain(0, NULL);
        return EXIT_SUCCESS;
    } else {
        SERVICE_TABLE_ENTRY service_table[] = {
            { (LPTSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)serviceMain },
            { NULL, NULL } };
        is_service = 1;
        StartServiceCtrlDispatcher(service_table);
        return GetLastError();
    }
}

