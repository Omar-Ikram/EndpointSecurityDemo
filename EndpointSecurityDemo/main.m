//
//  main.m
//  EndpointSecurityDemo
//
//  Created by Omar Ikram on 17/06/2019 - macOS Catalina 10.15 Beta 1 (19A471t)
//  Updated by Omar Ikram on 15/08/2019 - macOS Catalina 10.15 Beta 5 (19A526h)
//  Updated by Omar Ikram on 01/12/2019 - macOS Catalina 10.15 (19A583)
//  Updated by Omar Ikram on 31/01/2021 - macOS Big Sur 11.1 (20C69)
//  Updated by Omar Ikram on 07/05/2021 - macOS Big Sur 11.3.1 (20E241)
//  Updated by Omar Ikram on 04/07/2021 - macOS Monterey 12 Beta 2 (21A5268h)
//  Updated by Omar Ikram on 08/01/2022 - macOS Monterey 12.1 (21C52)
//  Updated by Omar Ikram on 15/02/2022 - macOS Monterey 12.2.1 (21D62)
//

/*
 
 A demo of using Apple's EndpointSecurity framework - tested on macOS Monterey 12.2.1 (21D62).
 
 Minimum supported version: macOS Catalina 10.15
 
 This demo is an update of previous demos, which has been updated to support the latest API changes
 Apple has made for macOS Monterey 12.
 
 The demo has also been expanded significantly to include more detail and cover more of the API.
 
 The code, hopefully, should be self explanatory. Important details are marked by a comment
 starting with "Note:".
 
 Disclaimer:
 This code is provided as is and is only intended to be used for illustration purposes. This code is
 not production-ready and is not meant to be used in a production environment. Use it at your own risk!
 
 Setup:
 1. Build with Xcode 13 (tested with Version 13.2.1 (13C100)), having the macOS deployment target set
    to 10.15 (or later) and the Hardened Runtime capability enabled.

 2. Link with libraries:
    - libEndpointSecurity.tbd (Endpoint Security functions)
    - libbsm.tbd (Audit Token functions)
    - UniformTypeIdentifiers.framework (UTI functions, which is not available on macOS Catalina 10.15
      , so it needs to be optinally linked - e.g. with the '-weak_framework' linker option)

 3. Codesign with entitlement 'com.apple.developer.endpoint-security.client'.
 
 If your Apple Developer account has been granted the entitlement from Apple, then the program needs
 to be compiled as an App (i.e. Application Bundle). This will allow you to assign a Provisioning
 Profile to the program, which you need to have associated the entitlement to it.
 
 If you have not been granted the entitlement. You can still build the program (as an App or Command
 Line Tool), but it will only be able to run on a machine which has SIP disabled (best to use a VM).
 
 Runtime:
 1. Test environment should be a macOS 10.15+ machine.
 2. Run the demo binary in a terminal as root (e.g. with sudo).
    i)   Running with no arguments will display a simple usage message.
    ii)  Running with the 'serial' argument will run the demo using
         the example serial event message handler.
    iii) Running with the 'asynchronous' argument will run the demo using
         the example asynchronous event message handler.
    iv) Adding the 'verbose' argument at the end will turn on verbose logging.
 3. Terminal will display messages related to subscribed events.
 4. The demo will demonstrate processing Endpoint Security event messages
    serially or asynchronously (depending on the selected command line argument given).
    
    The demo will also demonstrate using Endpoint Security Auth events to make the
    following Auth based decisions:
       i)  Block the 'top' binary and 'Calculator' app bundle from running.
       ii) Block 'vim' binary from reading plain text files.
 5. CTL-C to exit.
 
 */

#import <Foundation/Foundation.h>
#import <EndpointSecurity/EndpointSecurity.h>
#import <bsm/libbsm.h>
#import <signal.h>
#import <mach/mach_time.h>
#import <Kernel/kern/cs_blobs.h>
#import <UniformTypeIdentifiers/UniformTypeIdentifiers.h>
#import <Appkit/AppKit.h>
#import <libproc.h>

#pragma mark Globals

es_client_t *g_client = nil;
NSSet *g_blocked_paths = nil;
NSDateFormatter *g_date_formater = nil;

// Endpoint Security event handler selected at startup from the command line
es_handler_block_t g_handler = nil;

// Used to detect if any events have been dropped by the kernel
uint64_t g_global_seq_num = 0;
NSMutableDictionary *g_seq_nums = nil;

// Set to true if want to cache the results of an auth event response
bool g_cache_auth_results = false;

// Logs can become quite busy, especially when subscribing to ES_EVENT_TYPE_AUTH_OPEN events.
// Only log all event messages when the flag is enabled;
// otherwise only denied Auth event messages will be logged.
bool g_verbose_logging = false;

#pragma mark Helpers - Mach Absolute Time

// This could be running on either Apple Silicon or Intel based CPUs.
// We will need to apply timebase information when converting Mach absolute time to nanoseconds:
// https://developer.apple.com/documentation/apple_silicon/addressing_architectural_differences_in_your_macos_code#3616875
//
// Note: Running x86_64 code running under Rosetta 2 will have timebase information for Intel CPUs.
// This will cause discrepancies when converting Mach absolute time values from Endpoint Security Messages.
// The best option would be to compile your client as a universal binary:
// https://developer.apple.com/documentation/xcode/building_a_universal_macos_binary
uint64_t MachTimeToNanoseconds(uint64_t machTime) {
    uint64_t nanoseconds = 0;
    static mach_timebase_info_data_t sTimebase;
    if(sTimebase.denom == 0)
        (void)mach_timebase_info(&sTimebase);
        
    nanoseconds = ((machTime * sTimebase.numer) / sTimebase.denom);
        
    return nanoseconds;
}

uint64_t MachTimeToSeconds(uint64_t machTime) {
    return MachTimeToNanoseconds(machTime) / NSEC_PER_SEC;
}

#pragma mark Helpers - Code Signing

typedef struct {
    const NSString* name;
    int value;
} CSFlag;

#define CSFLAG(flag) {@#flag, flag}

// Code signing flags defined in cs_blobs.h
const CSFlag g_csFlags[] = {
    CSFLAG(CS_VALID),               CSFLAG(CS_ADHOC),           CSFLAG(CS_GET_TASK_ALLOW),
    CSFLAG(CS_INSTALLER),           CSFLAG(CS_FORCED_LV),       CSFLAG(CS_INVALID_ALLOWED),
    CSFLAG(CS_HARD),                CSFLAG(CS_KILL),            CSFLAG(CS_CHECK_EXPIRATION),
    CSFLAG(CS_RESTRICT),            CSFLAG(CS_ENFORCEMENT),     CSFLAG(CS_REQUIRE_LV),
    CSFLAG(CS_ENTITLEMENTS_VALIDATED),                          CSFLAG(CS_NVRAM_UNRESTRICTED),
    CSFLAG(CS_RUNTIME),             CSFLAG(CS_LINKER_SIGNED),   CSFLAG(CS_ALLOWED_MACHO),
    CSFLAG(CS_EXEC_SET_HARD),       CSFLAG(CS_EXEC_SET_KILL),   CSFLAG(CS_EXEC_SET_ENFORCEMENT),
    CSFLAG(CS_EXEC_INHERIT_SIP),    CSFLAG(CS_KILLED),          CSFLAG(CS_DYLD_PLATFORM),
    CSFLAG(CS_PLATFORM_BINARY),     CSFLAG(CS_PLATFORM_PATH),   CSFLAG(CS_DEBUGGED),
    CSFLAG(CS_SIGNED),              CSFLAG(CS_DEV_CODE)
};

NSString* codesigning_flags_str(const uint32_t codesigning_flags) {
    NSMutableArray *match_flags = [NSMutableArray new];
    
    // Test which code signing flags have been set and add the matched ones to an array
    for(uint32_t i = 0; i < (sizeof g_csFlags / sizeof *g_csFlags); i++) {
        if((codesigning_flags & g_csFlags[i].value) == g_csFlags[i].value) {
            [match_flags addObject:g_csFlags[i].name];
        }
    }
    
    return [match_flags componentsJoinedByString:@","];
}

#pragma mark Helpers - Endpoint Security

NSString* esstring_to_nsstring(const es_string_token_t es_string_token) {
    if(es_string_token.data && es_string_token.length > 0) {
        // es_string_token.data is a pointer to a null-terminated string
        return [NSString stringWithUTF8String:es_string_token.data];
    } else {
        return @"";
    }
}

const NSString* event_type_str(const es_event_type_t event_type) {
    static const NSString *names[] = {
        // The following events are available beginning in macOS 10.15
        @"AUTH_EXEC", @"AUTH_OPEN", @"AUTH_KEXTLOAD", @"AUTH_MMAP", @"AUTH_MPROTECT",
        @"AUTH_MOUNT", @"AUTH_RENAME", @"AUTH_SIGNAL", @"AUTH_UNLINK", @"NOTIFY_EXEC",
        @"NOTIFY_OPEN", @"NOTIFY_FORK", @"NOTIFY_CLOSE", @"NOTIFY_CREATE", @"NOTIFY_EXCHANGEDATA",
        @"NOTIFY_EXIT", @"NOTIFY_GET_TASK", @"NOTIFY_KEXTLOAD", @"NOTIFY_KEXTUNLOAD", @"NOTIFY_LINK",
        @"NOTIFY_MMAP", @"NOTIFY_MPROTECT", @"NOTIFY_MOUNT", @"NOTIFY_UNMOUNT", @"NOTIFY_IOKIT_OPEN",
        @"NOTIFY_RENAME", @"NOTIFY_SETATTRLIST", @"NOTIFY_SETEXTATTR", @"NOTIFY_SETFLAGS", @"NOTIFY_SETMODE",
        @"NOTIFY_SETOWNER", @"NOTIFY_SIGNAL", @"NOTIFY_UNLINK", @"NOTIFY_WRITE", @"AUTH_FILE_PROVIDER_MATERIALIZE",
        @"NOTIFY_FILE_PROVIDER_MATERIALIZE", @"AUTH_FILE_PROVIDER_UPDATE", @"NOTIFY_FILE_PROVIDER_UPDATE",
        @"AUTH_READLINK", @"NOTIFY_READLINK", @"AUTH_TRUNCATE", @"NOTIFY_TRUNCATE", @"AUTH_LINK", @"NOTIFY_LOOKUP",
        @"AUTH_CREATE", @"AUTH_SETATTRLIST", @"AUTH_SETEXTATTR", @"AUTH_SETFLAGS", @"AUTH_SETMODE", @"AUTH_SETOWNER",
        
        // The following events are available beginning in macOS 10.15.1
        @"AUTH_CHDIR", @"NOTIFY_CHDIR", @"AUTH_GETATTRLIST", @"NOTIFY_GETATTRLIST", @"NOTIFY_STAT", @"NOTIFY_ACCESS",
        @"AUTH_CHROOT", @"NOTIFY_CHROOT", @"AUTH_UTIMES", @"NOTIFY_UTIMES", @"AUTH_CLONE", @"NOTIFY_CLONE",
        @"NOTIFY_FCNTL", @"AUTH_GETEXTATTR", @"NOTIFY_GETEXTATTR", @"AUTH_LISTEXTATTR", @"NOTIFY_LISTEXTATTR",
        @"AUTH_READDIR", @"NOTIFY_READDIR", @"AUTH_DELETEEXTATTR", @"NOTIFY_DELETEEXTATTR", @"AUTH_FSGETPATH",
        @"NOTIFY_FSGETPATH", @"NOTIFY_DUP", @"AUTH_SETTIME", @"NOTIFY_SETTIME", @"NOTIFY_UIPC_BIND", @"AUTH_UIPC_BIND",
        @"NOTIFY_UIPC_CONNECT", @"AUTH_UIPC_CONNECT", @"AUTH_EXCHANGEDATA", @"AUTH_SETACL", @"NOTIFY_SETACL",
        
        // The following events are available beginning in macOS 10.15.4
        @"NOTIFY_PTY_GRANT", @"NOTIFY_PTY_CLOSE", @"AUTH_PROC_CHECK", @"NOTIFY_PROC_CHECK", @"AUTH_GET_TASK",
        
        // The following events are available beginning in macOS 11.0
        @"AUTH_SEARCHFS", @"NOTIFY_SEARCHFS", @"AUTH_FCNTL", @"AUTH_IOKIT_OPEN", @"AUTH_PROC_SUSPEND_RESUME",
        @"NOTIFY_PROC_SUSPEND_RESUME", @"NOTIFY_CS_INVALIDATED", @"NOTIFY_GET_TASK_NAME",
        @"NOTIFY_TRACE", @"NOTIFY_REMOTE_THREAD_CREATE", @"AUTH_REMOUNT", @"NOTIFY_REMOUNT",
        
        // The following events are available beginning in macOS 11.3
        @"AUTH_GET_TASK_READ", @"NOTIFY_GET_TASK_READ", @"NOTIFY_GET_TASK_INSPECT",
        
        // The following events are available beginning in macOS 12.0
        @"NOTIFY_SETUID", @"NOTIFY_SETGID", @"NOTIFY_SETEUID", @"NOTIFY_SETEGID", @"NOTIFY_SETREUID",
        @"NOTIFY_SETREGID", @"AUTH_COPYFILE", @"NOTIFY_COPYFILE"
    };
    
    if(event_type >= ES_EVENT_TYPE_LAST) {
        return [NSString stringWithFormat:@"Unknown/Unsupported event type: %d", event_type];
    }
    
    return names[event_type];
}

NSString* events_str(size_t count, const es_event_type_t* events) {
    NSMutableArray *arr = [NSMutableArray new];
    
    for(size_t i = 0; i < count; i++) {
        [arr addObject:event_type_str(events[i])];
    }
    
    return [arr componentsJoinedByString:@", "];
}

// On macOS Big Sur 11, Apple have deprecated es_copy_message in favour of es_retain_message
es_message_t * copy_message(const es_message_t * msg) {
    if(@available(macOS 11.0, *)) {
        es_retain_message(msg);
        // simulate a copy
        return (es_message_t*) msg;
    } else {
        return es_copy_message(msg);
    }
}

// On macOS Big Sur 11, Apple have deprecated es_free_message in favour of es_release_message
void free_message(es_message_t * _Nonnull msg) {
    if(@available(macOS 11.0, *)) {
        es_release_message(msg);
    } else {
        es_free_message(msg);
    }
}

#pragma mark Helpers - Misc

NSString* fdtype_str(const uint32_t fdtype) {
    switch(fdtype) {
        case PROX_FDTYPE_ATALK: return @"ATALK";
        case PROX_FDTYPE_VNODE: return @"VNODE";
        case PROX_FDTYPE_SOCKET: return @"SOCKET";
        case PROX_FDTYPE_PSHM: return @"PSHM";
        case PROX_FDTYPE_PSEM: return @"PSEM";
        case PROX_FDTYPE_KQUEUE: return @"KQUEUE";
        case PROX_FDTYPE_PIPE: return @"PIPE";
        case PROX_FDTYPE_FSEVENTS: return @"FSEVENTS";
        case PROX_FDTYPE_NETPOLICY: return @"NETPOLICY";
        default: return [NSString stringWithFormat:@"Unknown/Unsupported fdtype: %d",
                         fdtype];
    }
}

void init_date_formater(void) {
    // Display dates in RFC 3339 date and time format: https://www.ietf.org/rfc/rfc3339.txt
    g_date_formater = [NSDateFormatter new];
    g_date_formater.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    g_date_formater.dateFormat = @"yyyy-MM-dd'T'HH:mm:ssZZZZZ";
    g_date_formater.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];
}

NSString* formatted_date_str(__darwin_time_t secs_since_1970) {
    NSDate *date = [NSDate dateWithTimeIntervalSince1970:secs_since_1970];
    return [g_date_formater stringFromDate:date];
}

bool is_system_file(const NSString* path) {
    // For the purpose of this demo. A system file is a file that is under these directories:
    for(NSString* prefix in @[@"/System/", @"/usr/share/"]) {
        if([path hasPrefix:prefix]) {
            return true;
        }
    }
    
    return false;
}

bool is_plain_text_file(const NSString* path) {
    if(@available(macOS 11.0, *)) {
        UTType* utt = [UTType typeWithFilenameExtension:[path pathExtension]];
        return [utt conformsToType:UTTypePlainText];
    } else {
        return [[NSWorkspace sharedWorkspace]
                filenameExtension:[path pathExtension]
                isValidForType:@"public.plain-text"];
    }
}

char* filetype_str(const mode_t st_mode) {
    switch(((st_mode) & S_IFMT)) {
        case S_IFBLK: return "BLK";
        case S_IFCHR: return "CHR";
        case S_IFDIR: return "DIR";
        case S_IFIFO: return "FIFO";
        case S_IFREG: return "REG";
        case S_IFLNK: return "LINK";
        case S_IFSOCK: return "SOCK";
        default: return "";
    }
}

#pragma mark - Logging

#define BOOL_VALUE(x) x ? "Yes" : "No"

int g_log_indent = 0;
#define LOG_INDENT_INC() {g_log_indent += 2;}
#define LOG_INDENT_DEC() {g_log_indent -= 2;}

#define LOG_IMPORTANT_INFO(fmt, ...) NSLog(@"*** " @#fmt @" ***", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) NSLog(@"%*s" @#fmt, g_log_indent, "", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) NSLog(@"ERROR: " @#fmt, ##__VA_ARGS__)

#define LOG_VERBOSE_EVENT_MESSAGE(msg) {        \
    if(g_verbose_logging) {                     \
        log_event_message(msg);                 \
    }                                           \
}

#define LOG_NON_VERBOSE_EVENT_MESSAGE(msg) {    \
    if(!g_verbose_logging) {                    \
        log_event_message(msg);                 \
    }                                           \
}

void log_audit_token(const NSString* header, const audit_token_t audit_token) {
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    LOG_INFO("pid: %d", audit_token_to_pid(audit_token));
    LOG_INFO("ruid: %d", audit_token_to_ruid(audit_token));
    LOG_INFO("euid: %d", audit_token_to_euid(audit_token));
    LOG_INFO("rgid: %d", audit_token_to_rgid(audit_token));
    LOG_INFO("egid: %d", audit_token_to_egid(audit_token));
    LOG_INDENT_DEC();
}

API_AVAILABLE(macos(12.0))
bool log_muted_paths_events(void) {
    es_muted_paths_t *muted_paths = NULL;
    es_return_t result = es_muted_paths_events(g_client, &muted_paths);
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("es_muted_paths_events: ES_RETURN_ERROR");
        return false;
    }
    
    if(NULL == muted_paths) {
        // There are no muted paths
        return true;
    }
    
    LOG_IMPORTANT_INFO("Muted Paths");
    for(size_t i = 0; i < muted_paths->count; i++) {
        es_muted_path_t muted_path = muted_paths->paths[i];
        LOG_INFO("muted_path[%ld]: %@", i, esstring_to_nsstring(muted_path.path));
        
        if(g_verbose_logging) {
            LOG_INDENT_INC();
            LOG_INFO("type: %s", (muted_path.type == ES_MUTE_PATH_TYPE_PREFIX) ? "Prefix" : "Literal");
            LOG_INFO("event_count: %ld", muted_path.event_count);
            LOG_INFO("events: %@", events_str(muted_path.event_count, muted_path.events));
            LOG_INDENT_DEC();
        }
    }
    
    es_release_muted_paths(muted_paths);
    return true;
}

bool log_subscribed_events(void) {
    // Log the subscribed events
    size_t count = 0;
    es_event_type_t *events = NULL;
    es_return_t result = es_subscriptions(g_client, &count, &events);
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("es_subscriptions: ES_RETURN_ERROR");
        return false;
    }
    
    LOG_IMPORTANT_INFO("Subscribed Events: %@", events_str(count, events));
    
    free(events);
    return true;
}

void log_file(const NSString* header, const es_file_t* file) {
    if(!file) {
        LOG_INFO("%@: (null)", header);
        return;
    }
    
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    LOG_INFO("path: %@", esstring_to_nsstring(file->path));
    LOG_INFO("path_truncated: %s", BOOL_VALUE(file->path_truncated));
    
    LOG_INFO("stat.st_dev: %d", file->stat.st_dev);
    LOG_INFO("stat.st_ino: %llu", file->stat.st_ino);
    LOG_INFO("stat.st_mode: %u (%s)", file->stat.st_mode, filetype_str(file->stat.st_mode));
    LOG_INFO("stat.st_nlink: %u", file->stat.st_nlink);
    
    LOG_INFO("stat.st_uid: %u", file->stat.st_uid);
    LOG_INFO("stat.st_gid: %u", file->stat.st_gid);
    
    LOG_INFO("stat.st_atime: %@", formatted_date_str(file->stat.st_atime));
    LOG_INFO("stat.st_mtime: %@", formatted_date_str(file->stat.st_mtime));
    LOG_INFO("stat.st_ctime: %@", formatted_date_str(file->stat.st_ctime));
    LOG_INFO("stat.st_birthtime: %@", formatted_date_str(file->stat.st_birthtime));
    
    LOG_INFO("stat.st_size: %lld", file->stat.st_size);
    LOG_INFO("stat.st_blocks: %lld", file->stat.st_blocks);
    LOG_INFO("stat.st_blksize: %d", file->stat.st_blksize);
    LOG_INFO("stat.st_flags: %u", file->stat.st_flags);
    LOG_INFO("stat.st_gen: %u", file->stat.st_gen);
    LOG_INDENT_DEC();
}

void log_proc(uint32_t msg_version, const NSString* header, const es_process_t* proc) {
    if(!proc) {
        LOG_INFO("%@: (null)", header);
        return;
    }
    
    LOG_INFO("%@:", header);
    LOG_INDENT_INC();
    log_audit_token(@"proc.audit_token", proc->audit_token);
    LOG_INFO("proc.ppid: %d", proc->ppid);
    LOG_INFO("proc.original_ppid: %d", proc->original_ppid);
    
    if(msg_version >= 4) {
        log_audit_token(@"proc.responsible_audit_token", proc->responsible_audit_token);
        log_audit_token(@"proc.parent_audit_token", proc->parent_audit_token);
    }
    
    LOG_INFO("proc.group_id: %d", proc->group_id);
    LOG_INFO("proc.session_id: %d", proc->session_id);
    LOG_INFO("proc.is_platform_binary: %s", BOOL_VALUE(proc->is_platform_binary));
    LOG_INFO("proc.is_es_client: %s", BOOL_VALUE(proc->is_es_client));
    LOG_INFO("proc.signing_id: %@", esstring_to_nsstring(proc->signing_id));
    LOG_INFO("proc.team_id: %@", esstring_to_nsstring(proc->team_id));
    
    if(msg_version >= 3) {
        LOG_INFO("proc.start_time: %@", formatted_date_str(proc->start_time.tv_sec));
    }
    
    LOG_INFO("proc.codesigning_flags: %x (%@)",
             proc->codesigning_flags, codesigning_flags_str(proc->codesigning_flags));
    
    // proc.cdhash
    NSMutableString *hash = [NSMutableString string];
    for(uint32_t i = 0; i < CS_CDHASH_LEN; i++) {
        [hash appendFormat:@"%02x", proc->cdhash[i]];
    }
    LOG_INFO("proc.cdhash: %@", hash);
    
    log_file(@"proc.executable", proc->executable);
    
    if(msg_version >= 2 && proc->tty) {
        log_file(@"proc.tty", proc->tty);
    }
    
    LOG_INDENT_DEC();
}

void log_command_line_arguments(const es_event_exec_t* exec) {
    uint32_t arg_count = es_exec_arg_count(exec);
    LOG_INFO("event.exec.arg_count: %u", arg_count);
    LOG_INDENT_INC();
    
    // Extract each argument and log it out
    for(uint32_t i = 0; i < arg_count; i++) {
        es_string_token_t arg = es_exec_arg(exec, i);
        LOG_INFO("arg[%d]: %@", i, esstring_to_nsstring(arg));
    }
    
    LOG_INDENT_DEC();
}

void log_environment_variable(const es_event_exec_t* exec) {
    uint32_t env_count = es_exec_env_count(exec);
    LOG_INFO("event.exec.env_count: %u", env_count);
    LOG_INDENT_INC();
    
    // Extract each env and log it out
    for(uint32_t i = 0; i < env_count; i++) {
        es_string_token_t arg = es_exec_env(exec, i);
        LOG_INFO("env[%d]: %@", i, esstring_to_nsstring(arg));
    }
    
    LOG_INDENT_DEC();
}

void log_file_descriptors(const es_event_exec_t* exec) {
    if(@available(macOS 11.0, *)) {
        uint32_t fd_count = es_exec_fd_count(exec);
        LOG_INFO("event.exec.fd_count: %u", fd_count);
        LOG_INDENT_INC();
        
        // Extract each fd and log it out
        for(uint32_t i = 0; i < fd_count; i++) {
            // Pointer must not outlive event
            const es_fd_t *arg = es_exec_fd(exec, i);
            
            LOG_INFO("fd[%d].fd: %d", i, arg->fd);
            LOG_INFO("fd[%d].fdtype: %@", i, fdtype_str(arg->fdtype));
            
            if(PROX_FDTYPE_PIPE == arg->fdtype) {
                LOG_INFO("fd[%d].fd: %llu", i, arg->pipe.pipe_id);
            }
        }
        
        LOG_INDENT_DEC();
    }
}

void log_event_exec(uint32_t msg_version, const es_event_exec_t* exec) {
    log_proc(msg_version, @"event.exec.target", exec->target);
    log_command_line_arguments(exec);
    log_environment_variable(exec);
    log_file_descriptors(exec);
    
    if(msg_version >= 2 && exec->script) {
        log_file(@"event.exec.script", exec->script);
    }
    
    if(msg_version >= 3) {
        log_file(@"event.exec.cwd", exec->cwd);
    }
    
    if(msg_version >= 4) {
        LOG_INFO("event.exec.last_fd: %d", exec->last_fd);
    }
}

void log_event_open(const es_event_open_t* open) {
    NSMutableArray *match_flags = [NSMutableArray new];
    
    if((open->fflag & FREAD) == FREAD) {
        [match_flags addObject:@"FREAD"];
    }
    
    if((open->fflag & FWRITE) == FWRITE) {
        [match_flags addObject:@"FWRITE"];
    }
    
    LOG_INFO("event.open.fflag: %d (%@)",
             open->fflag, [match_flags componentsJoinedByString:@", "]);
    log_file(@"event.open.file", open->file);
}

// Logs the top level datatype sent by Endpoint Security subsystem to its clients
void log_event_message(const es_message_t *msg) {
    LOG_INFO("--- EVENT MESSAGE ----");
    LOG_INFO("event_type: %@ (%d)", event_type_str(msg->event_type), msg->event_type);
    
    // Note: Apple have designed the Endpoint Security structures to support additional fields
    // in the future. Always check the version of the message before using a field, in the message
    // or sub-structure, which has been added to a later version of Endpoint Security.
    // Only new fields are added. Existing fields should be available in future revisions.
    uint32_t version = msg->version;
    LOG_INFO("version: %u", version);
    
    LOG_INFO("time: %@", formatted_date_str(msg->time.tv_sec));
    LOG_INFO("mach_time: %lld", msg->mach_time);
   
    // Note: It's very important that an auth event is processed within the deadline:
    // https://developer.apple.com/documentation/endpointsecurity/es_message_t/3334985-deadline
    // From an Apple Security Engineer:
    //  "You must respond by the deadline.
    //  It is not configurable.
    //  It won't get longer, but it will get shorter."
    // https://developer.apple.com/forums/thread/649552?answerId=615802022#615802022
    LOG_INFO("deadline: %llu", msg->deadline);
    
    uint64_t deadlineInterval = msg->deadline;
    
    if(deadlineInterval > 0) {
        deadlineInterval -= msg->mach_time;
    }
    
    LOG_INFO("deadline interval: %llu (%llu seconds)",
             deadlineInterval, MachTimeToSeconds(deadlineInterval));
    
    // Note: You can use the seq_num field to detect if the kernel had to drop any event messages,
    // for an event type, to the client.
    if(version >= 2) {
        LOG_INFO("seq_num: %lld", msg->seq_num);
    }
    
    // Note: You can use the global_seq_num field to detect if the kernel had to drop any event
    // messages to the client.
    if(version >= 4) {
        LOG_INFO("global_seq_num: %lld", msg->global_seq_num);
    }
    
    if(version >= 4 && msg->thread) {
        LOG_INFO("thread_id: %lld", msg->thread->thread_id);
    }
    
    LOG_INFO("action_type: %s", (msg->action_type == ES_ACTION_TYPE_AUTH) ? "Auth" : "Notify");
    log_proc(version, @"process", msg->process);
    
    // Event specific logging
    switch(msg->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC: {
            log_event_exec(version, &msg->event.exec);
        }
            break;
            
        case ES_EVENT_TYPE_AUTH_OPEN: {
            log_event_open(&msg->event.open);
        }
            break;
            
        case ES_EVENT_TYPE_NOTIFY_FORK: {
            log_proc(version, @"event.fork.child", msg->event.fork.child);
        }
            break;
            
        case ES_EVENT_TYPE_LAST:
        default: {
            // Not interested
        }
    }
    
    LOG_INFO("");
}

// Demonstrates detecting dropped event messages from the kernel, by either
// using the using the seq_num or global_seq_num fields in an event message
void detect_and_log_dropped_events(const es_message_t *msg) {
    uint32_t version = msg->version;
    
    // Note: You can use the seq_num field to detect if the kernel had to
    // drop any event messages, for an event type, to the client.
    if(version >= 2) {
        uint64_t seq_num = msg->seq_num;
        
        const NSString *type = event_type_str(msg->event_type);
        NSNumber *last_seq_num = [g_seq_nums objectForKey:type];
        
        if(last_seq_num != nil) {
            uint64_t expected_seq_num = [last_seq_num unsignedLongLongValue] + 1;
            
            if(seq_num > expected_seq_num) {
                LOG_ERROR("EVENTS DROPPED! seq_num is ahead by: %llu",
                          (seq_num - expected_seq_num));
            }
        }
        
        [g_seq_nums setObject:[NSNumber numberWithUnsignedLong:seq_num] forKey:type];
    }
    
    // Note: You can use the global_seq_num field to detect if the kernel had to
    // drop any event messages to the client.
    if(version >= 4) {
        uint64_t global_seq_num = msg->global_seq_num;
        
        if(global_seq_num > ++g_global_seq_num) {
            LOG_ERROR("EVENTS DROPPED! global_seq_num is ahead by: %llu",
                      (global_seq_num - g_global_seq_num));
            g_global_seq_num = global_seq_num;
        }
    }
}

#pragma mark - Endpoint Secuirty Demo

// Clean-up before exiting
void sig_handler(int sig) {
    LOG_IMPORTANT_INFO("Tidying Up");
    
    if(g_client) {
        es_unsubscribe_all(g_client);
        es_delete_client(g_client);
    }
    
    LOG_IMPORTANT_INFO("Exiting");
    exit(EXIT_SUCCESS);
}

void print_usage(const char *name) {
    printf("Usage: %s (serial | asynchronous) (verbose)\n", name);
    printf("Arguments:\n");
    printf("\tserial\t\tUse serial message handler\n");
    printf("\tasynchronous\tUse asynchronous message handler\n");
    printf("\tverbose\t\tTurns on verbose logging\n");
}

// An example handler to make auth (allow or block) decisions.
// Returns either an ES_AUTH_RESULT_ALLOW or ES_AUTH_RESULT_DENY.
es_auth_result_t auth_event_handler(const es_message_t *msg) {
    // NOTE: You should ignore events from other ES Clients;
    // otherwise you may trigger more events causing a potentially infinite cycle.
    if(msg->process->is_es_client) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Ignore events from root processes
    if(0 == audit_token_to_ruid(msg->process->audit_token)) {
        return ES_AUTH_RESULT_ALLOW;
    }
    
    // Block exec if path of process is in our blocked paths list
    if(ES_EVENT_TYPE_AUTH_EXEC == msg->event_type) {
        NSString *path = esstring_to_nsstring(msg->event.exec.target->executable->path);
        
        if(![g_blocked_paths containsObject:path]) {
            return ES_AUTH_RESULT_ALLOW;
        }
        
        // Process is in our blocked list
        LOG_IMPORTANT_INFO("BLOCKING EXEC: %@", path);
        return ES_AUTH_RESULT_DENY;
    }
    
    // Block vim from accessing plain text files
    if(ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {
        NSString *processPath = esstring_to_nsstring(msg->process->executable->path);
        
        if(![processPath isEqualToString:@"/usr/bin/vim"]) {
            // Not vim
            return ES_AUTH_RESULT_ALLOW;
        }
        
        NSString *filePath = esstring_to_nsstring(msg->event.open.file->path);
        
        if(is_system_file(filePath)) {
            // Ignore System files
            return ES_AUTH_RESULT_ALLOW;
        }
        
        if(!is_plain_text_file(filePath)) {
            // Not a text file
            return ES_AUTH_RESULT_ALLOW;
        }
        
        // Process is vim trying to access a text file
        LOG_IMPORTANT_INFO("BLOCKING OPEN: %@", filePath);
        return ES_AUTH_RESULT_DENY;
    }
    
    // All good
    return ES_AUTH_RESULT_ALLOW;
}

// Sends a response back to Endpoint Security for an auth event
// Note: You must always send a response back before the deadline expires.
void respond_to_auth_event(es_client_t *clt, const es_message_t *msg, es_auth_result_t result) {
    // Only log ES_AUTH_RESULT_DENY results when verbose logging is disabled
    if(ES_AUTH_RESULT_DENY == result) {
        LOG_NON_VERBOSE_EVENT_MESSAGE(msg);
    }
    
    // Note: You use es_respond_auth_result() to respond to auth events,
    // except for ES_EVENT_TYPE_AUTH_OPEN events, which require a response
    // using es_respond_flags_result() instead.
    if(ES_EVENT_TYPE_AUTH_OPEN == msg->event_type) {
        uint32_t authorized_flags = 0;
        
        if(ES_AUTH_RESULT_ALLOW == result) {
            authorized_flags = msg->event.open.fflag;
        }
        
        es_respond_result_t res =
            es_respond_flags_result(clt, msg, authorized_flags, g_cache_auth_results);
        
        if(ES_RESPOND_RESULT_SUCCESS != res) {
            LOG_ERROR("es_respond_flags_result: %d", res);
        }
        
    } else {
        es_respond_result_t res =
            es_respond_auth_result(clt, msg, result, g_cache_auth_results);
        
        if(ES_RESPOND_RESULT_SUCCESS != res) {
            LOG_ERROR("es_respond_auth_result: %d", res);
        }
    }
}

// Example of an event message handler to process event messages serially from Endpoint Security.
es_handler_block_t serial_message_handler = ^(es_client_t *clt, const es_message_t *msg) {
    // Endpoint Security, by default, calls a event message handler serially for each message.
    
    LOG_VERBOSE_EVENT_MESSAGE(msg);
    
    // NOTE: It is important to process events in a timely manner.
    // The kernel will start to drop events for the client if they are not responded to in time.
    detect_and_log_dropped_events(msg);
    
    // Auth events require a response sent back before the deadline expires
    if(ES_ACTION_TYPE_AUTH == msg->action_type) {
        respond_to_auth_event(clt, msg, auth_event_handler(msg));
    }
};

// Example of an event message handler to process event messages asynchronously from Endpoint Security
es_handler_block_t asynchronous_message_handler = ^(es_client_t *clt, const es_message_t *msg) {
    // Endpoint Security, by default, calls a event message handler serially for each message.
    // We copy/retain the message so that we can process and respond to auth events asynchronously.
    
    LOG_VERBOSE_EVENT_MESSAGE(msg);
    
    // NOTE: It is important to process events in a timely manner.
    // The kernel will start to drop events for the client if they are not responded to in time.
    detect_and_log_dropped_events(msg);
    
    // Copy/Retain the event message so that we process the event asynchronously
    es_message_t *copied_msg = copy_message(msg);
    
    if(!copied_msg) {
        LOG_ERROR("Failed to copy message");
        return;
    }
    
    // Demonstrates handling events out of order, by processing 'ES_ACTION_TYPE_AUTH' events on
    // a separate thread. Sleep for 20s for 'ES_EVENT_TYPE_AUTH_EXEC' events if the result
    // is an ES_AUTH_RESULT_DENY.
    if(ES_ACTION_TYPE_AUTH == copied_msg->action_type) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^(void){
            es_auth_result_t result = auth_event_handler(copied_msg);
            
            if(ES_AUTH_RESULT_DENY == result &&
               ES_EVENT_TYPE_AUTH_EXEC == copied_msg->event_type) {
                [NSThread sleepForTimeInterval:20.0];
            }
            
            // Auth events require a response sent back before the deadline expires
            respond_to_auth_event(clt, copied_msg, result);
            free_message(copied_msg);
        });
        
        return;
    }
    
    // Free/release the message
    free_message(copied_msg);
};

es_handler_block_t get_message_handler_from_commandline_args(int argc, const char * argv[]) {
    if(argc < 2) {
        // No command line argument was given
        return nil;
    }
    
    // check if verbose logging argument was given
    if(argc > 2) {
        NSString *verbose = [[NSString stringWithUTF8String:argv[2]] lowercaseString];
        g_verbose_logging = [verbose isEqualToString:@"verbose"];
    }
    
    // Try and find an event message handler that matches the first command line argument
    NSString *arg = [[NSString stringWithUTF8String:argv[1]] lowercaseString];
    
    NSDictionary *handlers = @{
        @"serial" : serial_message_handler,
        @"asynchronous" : asynchronous_message_handler
    };
    
    return [handlers objectForKey:arg];
}

// On macOS Monterey 12, Apple have deprecated es_mute_path_literal in favour of es_mute_path
bool mute_path(const char* path)
{
    es_return_t result = ES_RETURN_ERROR;
    
    if(@available(macOS 12.0, *)) {
        result = es_mute_path(g_client, path, ES_MUTE_PATH_TYPE_LITERAL);
    } else {
        result = es_mute_path_literal(g_client, path);
    }
    
    if(ES_RETURN_SUCCESS != result) {
        LOG_ERROR("mute_path: ES_RETURN_ERROR");
        return false;
    }
    
    return true;
}

// Note: This function shows the boilerplate code required to setup a connection to Endpoint Security
// and subscribe to events.
bool setup_endpoint_security(void) {
    // Create a new client with an associated event message handler.
    // Requires 'com.apple.developer.endpoint-security.client' entitlement.
    es_new_client_result_t res = es_new_client(&g_client, g_handler);
    
    if(ES_NEW_CLIENT_RESULT_SUCCESS != res) {
        switch(res) {
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                LOG_ERROR("Application requires 'com.apple.developer.endpoint-security.client' entitlement");
                break;

            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                LOG_ERROR("Application lacks Transparency, Consent, and Control (TCC) approval "
                          "from the user. This can be resolved by granting 'Full Disk Access' from "
                          "the 'Security & Privacy' tab of System Preferences.");
                break;

            case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
                LOG_ERROR("Application needs to be run as root");
                break;

            default:
                LOG_ERROR("es_new_client: %d", res);
        }
        
        return false;
    }
    
    // Explicitly clear the cache of previous cached results from this demo or other ES Clients
    es_clear_cache_result_t resCache = es_clear_cache(g_client);
    if(ES_CLEAR_CACHE_RESULT_SUCCESS != resCache) {
        LOG_ERROR("es_clear_cache: %d", resCache);
        return false;
    }
    
    // Subscribe to the events we're interested in
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC
      , ES_EVENT_TYPE_AUTH_OPEN
      , ES_EVENT_TYPE_NOTIFY_FORK
    };
    
    es_return_t subscribed = es_subscribe(g_client, events, sizeof events / sizeof *events);
    
    if(ES_RETURN_ERROR == subscribed) {
        LOG_ERROR("es_subscribe: ES_RETURN_ERROR");
        return false;
    }
    
    // All good
    return log_subscribed_events();
}

int main(int argc, const char * argv[]) {
    signal(SIGINT, &sig_handler);
    
    @autoreleasepool {
        // Init global vars
        g_handler = get_message_handler_from_commandline_args(argc, argv);
        
        if(!g_handler) {
            print_usage(argv[0]);
            return 1;
        }
        
        init_date_formater();
        g_seq_nums = [NSMutableDictionary new];
        
        // List of paths to be blocked.
        // For this demo we will block the top binary and Calculator app bundle.
        g_blocked_paths = [NSSet setWithObjects:
                          @"/usr/bin/top",
                          @"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
                          nil];
        
        if(!setup_endpoint_security()) {
            return 1;
        }
        
        // Note: Endpoint Security have a set of es_mute* functions to suppress events for a process.
        // Uncomment the 'mute_path' line below to stop receiving events from the 'vim' binary.
        // This program will then stop receiving 'ES_EVENT_TYPE_AUTH_OPEN' events for vim and will no
        // longer be able to block vim from opening plain text files.
        // mute_path("/usr/bin/vim");
        
        if(@available(macOS 12.0, *)) {
            // Note: Endpoint Security for performance reasons will automatically mute a set of paths
            // on creation of new clients ('es_new_client').
            // macOS Monterey 12 now has the 'es_muted_paths_events' function, which can be used to
            // inspect the muted paths. It is possible to unmute these paths (e.g. by using
            // 'es_release_muted_paths'), but Apple advises against this.
            log_muted_paths_events();
        } else {
            // ES on macOS Monterey 12 implicitly mutes events from cfprefsd. We need to explicitly do
            // this on older versions of macOS to prevent deadlocks in this program. This is because
            // UTType and NSDate objects, used in parts of this program, may implicitly
            // make NSUserDefaults calls which will generate ES events for cfprefsd.
            mute_path("/usr/sbin/cfprefsd");
        }
        
        // Start handling events from Endpoint Security
        dispatch_main();
    }
    
    return 0;
}
