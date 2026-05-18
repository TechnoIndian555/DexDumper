#include "test_framework.h"
#include "sha1.h"
#include "dex_detector.h"
#include "signal_handler.h"
#include "file_utils.h"
#include "config_manager.h"
#include "memory_scanner.h"
#include "registry_manager.h"

int g_tests_run = 0;
int g_tests_failed = 0;
int g_assertions = 0;
jmp_buf g_test_jmp;

/* ==================== SHA1 TESTS ==================== */

TEST(sha1_empty) {
    uint8_t digest[20];
    const uint8_t expected[20] = {
        0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,
        0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09
    };
    compute_sha1_checksum("", 0, digest);
    ASSERT_MEM_EQ(digest, expected, 20, "SHA1 empty");
}

TEST(sha1_abc) {
    uint8_t digest[20];
    const uint8_t expected[20] = {
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
        0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d
    };
    compute_sha1_checksum("abc", 3, digest);
    ASSERT_MEM_EQ(digest, expected, 20, "SHA1 abc");
}

TEST(sha1_fox) {
    uint8_t digest[20];
    const uint8_t expected[20] = {
        0x2f,0xd4,0xe1,0xc6,0x7a,0x2d,0x28,0xfc,0xed,0x84,
        0x9e,0xe1,0xbb,0x76,0xe7,0x39,0x1b,0x93,0xeb,0x12
    };
    compute_sha1_checksum("The quick brown fox jumps over the lazy dog", 43, digest);
    ASSERT_MEM_EQ(digest, expected, 20, "SHA1 fox");
}

TEST(sha1_compare_equal) {
    uint8_t a[20]={0}, b[20]={0}; a[0]=0xAB; b[0]=0xAB;
    ASSERT(compare_sha1_digests(a, b), "equal digests");
}

TEST(sha1_compare_diff) {
    uint8_t a[20]={0}, b[20]={0}; a[0]=0xAB; b[0]=0xCD;
    ASSERT(!compare_sha1_digests(a, b), "different digests");
}

TEST(sha1_hex) {
    uint8_t d[20]={0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09};
    char hex[41];
    sha1_to_hex_string(d, hex, sizeof(hex));
    ASSERT_STR_EQ(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709", "hex conversion");
}

TEST(sha1_hex_small_buffer) {
    uint8_t d[20]={0}; char hex[5];
    sha1_to_hex_string(d, hex, sizeof(hex));
}

TEST(sha1_streaming) {
    sha1_context ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)"The quick brown fox ", 20);
    sha1_update(&ctx, (const uint8_t*)"jumps over the lazy dog", 23);
    uint8_t digest[20];
    sha1_final(&ctx, digest);
    const uint8_t expected[20] = {0x2f,0xd4,0xe1,0xc6,0x7a,0x2d,0x28,0xfc,0xed,0x84,0x9e,0xe1,0xbb,0x76,0xe7,0x39,0x1b,0x93,0xeb,0x12};
    ASSERT_MEM_EQ(digest, expected, 20, "SHA1 streaming");
}

TEST(sha1_large) {
    uint8_t digest[20];
    char large[10000];
    memset(large, 'A', sizeof(large));
    compute_sha1_checksum(large, sizeof(large), digest);
    const uint8_t expected[20] = {0xbf,0x6d,0xb7,0x11,0x2b,0x56,0x81,0x27,0x02,0xe9,0x9d,0x48,0xa7,0xb1,0xda,0xb6,0x2d,0x09,0xb3,0xf6};
    ASSERT_MEM_EQ(digest, expected, 20, "SHA1 10000xA");
}

/* ==================== SIGNAL HANDLER TESTS ==================== */

static int sig_installed = 0;

TEST(sig_install) {
    install_memory_signal_handlers();
    sig_installed = 1;
}

TEST(sig_null_ptr) {
    ASSERT(validate_memory_access(NULL, 100) == 0, "NULL rejected");
}

TEST(sig_low_addr) {
    ASSERT(validate_memory_access((void*)0x500, 16) == 0, "low addr rejected");
}

TEST(sig_heap) {
    if (!sig_installed) install_memory_signal_handlers();
    void* buf = malloc(4096);
    ASSERT(buf, "alloc");
    int r = validate_memory_access(buf, 4096);
    free(buf);
    ASSERT(r != 0, "heap readable");
}

TEST(sig_read_heap) {
    if (!sig_installed) install_memory_signal_handlers();
    void* src = malloc(256);
    ASSERT(src, "alloc");
    memset(src, 0xAB, 256);
    uint8_t dst[256] = {0};
    int r = read_memory_safely(src, dst, 256);
    free(src);
    ASSERT(r, "read ok");
    ASSERT(dst[0] == 0xAB && dst[255] == 0xAB, "content verified");
}

TEST(sig_read_null) {
    uint8_t dst[16] = {0};
    ASSERT(read_memory_safely(NULL, dst, 16) == 0, "NULL src fail");
}

TEST(sig_read_zero) {
    ASSERT(read_memory_safely((void*)0x10000, (void*)0x20000, 0) == 0, "zero size fail");
}

/* ==================== DEX DETECTOR TESTS ==================== */

static uint8_t* make_dex_buf(uint32_t file_size) {
    uint8_t* buf = calloc(1, file_size);
    if (!buf) return NULL;
    memcpy(buf, "dex\n035\0", 8);
    uint32_t v = file_size;  memcpy(buf+0x20, &v, 4);
    v = 0x70;                memcpy(buf+0x24, &v, 4);
    v = 0x12345678;          memcpy(buf+0x28, &v, 4);
    v = 1;                   memcpy(buf+0x38, &v, 4);
    v = file_size - 100;     memcpy(buf+0x3C, &v, 4);
    return buf;
}

TEST(dex_valid_header) {
    uint8_t* buf = make_dex_buf(0x1000);
    ASSERT(buf, "alloc");
    int r = validate_dex_header_structure(buf, 0x1000, 0);
    free(buf);
    ASSERT(r != 0, "valid DEX header");
}

TEST(dex_invalid_magic) {
    uint8_t buf[0x100] = {0};
    memcpy(buf, "DEB\n035\0", 8);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "wrong magic");
}

TEST(dex_size_too_small) {
    uint8_t buf[0x100] = {0};
    memcpy(buf, "dex\n035\0", 8);
    uint32_t v=100; memcpy(buf+0x20,&v,4); v=0x70; memcpy(buf+0x24,&v,4); v=0x12345678; memcpy(buf+0x28,&v,4);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "size<MIN");
}

TEST(dex_size_exceeds_buf) {
    uint8_t* buf = make_dex_buf(0x1000);
    ASSERT(buf, "alloc");
    uint32_t big = 0x200000; memcpy(buf+0x20, &big, 4);
    int r = validate_dex_header_structure(buf, 0x1000, 0);
    free(buf);
    ASSERT(r == 0, "size>buffer");
}

TEST(dex_bad_header_size) {
    uint8_t buf[0x1000] = {0};
    memcpy(buf, "dex\n035\0", 8);
    uint32_t v=0x1000; memcpy(buf+0x20,&v,4); v=0x80; memcpy(buf+0x24,&v,4); v=0x12345678; memcpy(buf+0x28,&v,4);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "header sz!=0x70");
}

TEST(dex_bad_endian) {
    uint8_t buf[0x1000] = {0};
    memcpy(buf, "dex\n035\0", 8);
    uint32_t v=0x1000; memcpy(buf+0x20,&v,4); v=0x70; memcpy(buf+0x24,&v,4); v=0x78563412; memcpy(buf+0x28,&v,4);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "wrong endian");
}

TEST(dex_string_table_oob) {
    uint8_t buf[0x1000] = {0};
    memcpy(buf, "dex\n035\0", 8);
    uint32_t v=0x1000; memcpy(buf+0x20,&v,4); v=0x70; memcpy(buf+0x24,&v,4); v=0x12345678; memcpy(buf+0x28,&v,4);
    v=100; memcpy(buf+0x38,&v,4); v=0xFF000; memcpy(buf+0x3C,&v,4);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "string table OOB");
}

TEST(dex_buf_too_small) {
    uint8_t buf[0x60] = {0};
    memcpy(buf, "dex\n035\0", 8);
    ASSERT(validate_dex_header_structure(buf, sizeof(buf), 0) == 0, "buf<header");
}

TEST(dex_scan_signature) {
    uint8_t buf[0x1000] = {0};
    memcpy(buf, "dex\n038\0", 8);
    uint32_t v=0x1000; memcpy(buf+0x20,&v,4); v=0x70; memcpy(buf+0x24,&v,4); v=0x12345678; memcpy(buf+0x28,&v,4);
    DexDetectionResult res = {0};
    ASSERT(scan_region_for_dex_files(buf, sizeof(buf), &res), "scan found");
    ASSERT(res.dex_address == buf, "addr correct");
    ASSERT_EQ(res.dex_size, 0x1000, "size correct");
}

TEST(dex_non_dex_memory) {
    uint8_t buf[0x1000]; memset(buf, 0xFF, sizeof(buf));
    DexDetectionResult res = {0};
    ASSERT(scan_region_for_dex_files(buf, sizeof(buf), &res) == 0, "random not DEX");
}

TEST(dex_oat_container) {
    uint8_t buf[0x10000]; memset(buf, 0, sizeof(buf));
    memcpy(buf, "oat\n\0\0\0\0", 8);
    memcpy(buf+0x2000, "dex\n035\0", 8);
    uint32_t v=0x1000; memcpy(buf+0x2020,&v,4); v=0x70; memcpy(buf+0x2024,&v,4); v=0x12345678; memcpy(buf+0x2028,&v,4);
    v=1; memcpy(buf+0x2038,&v,4); v=0x100-100;  memcpy(buf+0x203C,&v,4);
    DexDetectionResult res = {0};
    ASSERT(perform_comprehensive_dex_detection(buf, sizeof(buf), &res), "OAT+DEX");
}

/* ==================== ALIGNMENT BUG TEST ==================== */

static int scan_dex_at_offset(const void* buf, size_t total_size, size_t dex_offset) {
    uint8_t hdr[0x70];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr, "dex\n035\0", 8);
    uint32_t v = 0x1000; memcpy(hdr+0x20, &v, 4);
    v = 0x70;           memcpy(hdr+0x24, &v, 4);
    v = 0x12345678;     memcpy(hdr+0x28, &v, 4);
    v = 1;              memcpy(hdr+0x38, &v, 4);
    v = 0x1000 - 100;   memcpy(hdr+0x3C, &v, 4);

    memcpy((uint8_t*)buf + dex_offset, hdr, sizeof(hdr));

    DexDetectionResult res = {0};
    return scan_region_for_dex_files(buf, total_size, &res);
}

TEST(dex_align_offset_0) {
    install_memory_signal_handlers();
    uint8_t buf[0x2000]; memset(buf, 0xFF, sizeof(buf));
    ASSERT(scan_dex_at_offset(buf, sizeof(buf), 0), "DEX at offset 0");
}

TEST(dex_align_offset_4) {
    uint8_t buf[0x2000]; memset(buf, 0xFF, sizeof(buf));
    ASSERT(scan_dex_at_offset(buf, sizeof(buf), 4), "DEX at offset 4");
}

TEST(dex_align_offset_1) {
    uint8_t buf[0x2000]; memset(buf, 0xFF, sizeof(buf));
    ASSERT(scan_dex_at_offset(buf, sizeof(buf), 1), "DEX at offset 1");
}

TEST(dex_align_offset_2) {
    uint8_t buf[0x2000]; memset(buf, 0xFF, sizeof(buf));
    ASSERT(scan_dex_at_offset(buf, sizeof(buf), 2), "DEX at offset 2");
}

TEST(dex_align_offset_3) {
    uint8_t buf[0x2000]; memset(buf, 0xFF, sizeof(buf));
    ASSERT(scan_dex_at_offset(buf, sizeof(buf), 3), "DEX at offset 3");
}

/* ==================== MEMORY SCANNER TESTS ==================== */

TEST(region_parse_maps) {
    MemoryRegion* regions = NULL;
    int count = parse_memory_regions(&regions);
    ASSERT(count > 0, "should find regions in /proc/self/maps");
    ASSERT(regions != NULL, "regions allocated");
    for (int i = 0; i < count && i < 5; i++) {
        ASSERT(regions[i].start_address < regions[i].end_address, "valid region bounds");
    }
    free(regions);
}

TEST(region_potential_anonymous) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    r.path_name[0] = '\0';
    ASSERT(is_potential_dex_region(&r), "anonymous region is potential");
}

TEST(region_potential_dex_path) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.path_name, "/data/app/foo/base.apk");
    ASSERT(is_potential_dex_region(&r), "APK path is potential");
}

TEST(region_potential_oat) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.path_name, "/data/dalvik-cache/arm64/system@[email]");
    ASSERT(is_potential_dex_region(&r), "dalvik-cache is potential");
}

TEST(region_potential_app_data) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.path_name, "/data/data/com.example.app/files");
    ASSERT(is_potential_dex_region(&r), "app data is potential");
}

TEST(region_potential_classes) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.path_name, "/data/app/foo/classes2.dex");
    ASSERT(is_potential_dex_region(&r), "classes.dex is potential");
}

TEST(region_not_potential_system) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.path_name, "/dev/ashmem/dalvik-jit-code-cache");
    ASSERT(!is_potential_dex_region(&r), "ashmem not potential");
}

TEST(region_should_scan_valid) {
    install_memory_signal_handlers();
    size_t sz = 0x10000;
    void* mem = malloc(sz);
    ASSERT(mem != NULL, "alloc");
    MemoryRegion r = {0};
    r.start_address = mem;
    r.end_address = (void*)((char*)mem + sz);
    strcpy(r.permissions, "rw-p");
    r.path_name[0] = '\0';
    int ok = should_scan_memory_region(&r);
    free(mem);
    ASSERT(ok, "anonymous rw-p should be scanned");
}

TEST(region_should_scan_no_read_perm) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x20000;
    strcpy(r.permissions, "---p");
    ASSERT(!should_scan_memory_region(&r), "no read perm excluded");
}

TEST(region_should_scan_too_small) {
    MemoryRegion r = {0};
    r.start_address = (void*)0x10000;
    r.end_address = (void*)0x103FF;
    strcpy(r.permissions, "rw-p");
    ASSERT(!should_scan_memory_region(&r), "region < MIN excluded");
}

TEST(region_create_copy_valid) {
    uint8_t src[256];
    for (int i = 0; i < 256; i++) src[i] = (uint8_t)i;
    void* copy = create_memory_copy(src, 256);
    ASSERT(copy != NULL, "copy allocated");
    ASSERT_MEM_EQ(copy, src, 256, "copy matches");
    free(copy);
}

TEST(region_create_copy_null) {
    ASSERT(create_memory_copy(NULL, 100) == NULL, "NULL src");
}

TEST(region_create_copy_zero) {
    ASSERT(create_memory_copy((void*)0x10000, 0) == NULL, "zero size");
}

TEST(region_create_copy_too_large) {
    ASSERT(create_memory_copy((void*)0x10000, DEX_MAX_FILE_SIZE + 1) == NULL, "oversized");
}

/* ==================== REGISTRY MANAGER TESTS ==================== */

static uint8_t known_sha1[20] = {0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,0xaf,0xd8,0x07,0x09};

TEST(registry_inode_dedup) {
    ASSERT(!is_file_already_dumped(42), "inode 42 not yet dumped");
    register_dumped_file_with_checksum(42, "/tmp/test_dump.dex", known_sha1);
    ASSERT(is_file_already_dumped(42), "inode 42 now recognized");
}

TEST(registry_checksum_dedup) {
    ASSERT(is_checksum_already_dumped(known_sha1), "SHA1 already registered");
}

TEST(registry_checksum_not_dedup) {
    uint8_t other[20];
    memset(other, 0xFF, 20);
    ASSERT(!is_checksum_already_dumped(other), "unknown SHA1 not registered");
}

TEST(registry_sha1_excluded_match) {
    uint8_t digest[20];
    compute_sha1_checksum("", 0, digest);
    ASSERT(is_sha1_excluded(digest), "empty SHA1 is in exclusion list");
}

TEST(registry_sha1_excluded_no_match) {
    uint8_t digest[20];
    compute_sha1_checksum("not excluded content", 20, digest);
    ASSERT(!is_sha1_excluded(digest), "non-empty not excluded");
}

TEST(registry_dir_duplicate_found) {
    char dir_template[] = "/tmp/dexduptest_XXXXXX";
    char* dir = mkdtemp(dir_template);
    ASSERT(dir != NULL, "temp dir created");

    uint8_t* dex = make_dex_buf(0x1000);
    ASSERT(dex != NULL, "dex buf");
    uint8_t sha1[20];
    compute_sha1_checksum(dex, 0x1000, sha1);

    char path[512];
    snprintf(path, sizeof(path), "%s/test.dex", dir);
    FILE* f = fopen(path, "wb");
    ASSERT(f != NULL, "file created");
    fwrite(dex, 1, 0x1000, f);
    fclose(f);
    free(dex);

    int found = is_sha1_duplicate_in_directory(dir, sha1);
    ASSERT(found != 0, "duplicate detected in dir");

    unlink(path);
    rmdir(dir);
}

TEST(registry_dir_duplicate_not_found) {
    char dir_template[] = "/tmp/dexduptest_XXXXXX";
    char* dir = mkdtemp(dir_template);
    ASSERT(dir != NULL, "temp dir created");

    uint8_t sha1[20];
    compute_sha1_checksum("some content", 12, sha1);

    int found = is_sha1_duplicate_in_directory(dir, sha1);
    ASSERT(found == 0, "no duplicate in empty dir");

    rmdir(dir);
}

TEST(registry_dir_no_match_different_content) {
    char dir_template[] = "/tmp/dexduptest_XXXXXX";
    char* dir = mkdtemp(dir_template);
    ASSERT(dir != NULL, "temp dir created");

    uint8_t* dex = make_dex_buf(0x1000);
    ASSERT(dex != NULL, "dex buf");

    char path[512];
    snprintf(path, sizeof(path), "%s/test.dex", dir);
    FILE* f = fopen(path, "wb");
    ASSERT(f != NULL, "file created");
    fwrite(dex, 1, 0x1000, f);
    fclose(f);

    uint8_t other_sha1[20];
    compute_sha1_checksum("different data", 13, other_sha1);
    int found = is_sha1_duplicate_in_directory(dir, other_sha1);
    ASSERT(found == 0, "different content not match");

    free(dex);
    unlink(path);
    rmdir(dir);
}

/* ==================== CONFIG CLEANUP TESTS ==================== */

TEST(cfg_cleanup_twice_safe) {
    init_config_manager();
    cleanup_config_manager();
    cleanup_config_manager();
}

TEST(cfg_cleanup_reinit) {
    init_config_manager();
    cleanup_config_manager();
    init_config_manager();
    ASSERT_EQ(should_enable_second_scan(), 0, "after reinit: second scan off");
    ASSERT_EQ(get_initial_delay(), 8, "after reinit: delay 8");
}

/* ==================== PATTERN MATCHING TESTS ==================== */

TEST(pat_valid_normal)      { ASSERT(matches_dex_dump_pattern("dex_0_0x7ff000_20250101_120000.dex"), "normal"); }
TEST(pat_valid_large_idx)   { ASSERT(matches_dex_dump_pattern("dex_999_0xabcd1234_20251231_235959.dex"), "large idx"); }
TEST(pat_valid_zero_ptr)    { ASSERT(matches_dex_dump_pattern("dex_0_0x0_20210101_000000.dex"), "zero ptr"); }
TEST(pat_valid_cap_x)       { ASSERT(matches_dex_dump_pattern("dex_5_0XABCD_20220101_120000.dex"), "cap X"); }
TEST(pat_no_dex_prefix)     { ASSERT(!matches_dex_dump_pattern("dex_0x7ff000_20250101_120000.dex"), "no dex_"); }
TEST(pat_no_x_in_ptr)       { ASSERT(!matches_dex_dump_pattern("dex_0_7ff000_20250101_120000.dex"), "no x"); }
TEST(pat_wrong_ext)         { ASSERT(!matches_dex_dump_pattern("dex_0_0x7ff000_20250101_120000.txt"), "wrong ext"); }
TEST(pat_extra_after)       { ASSERT(!matches_dex_dump_pattern("dex_0_0x7ff000_20250101_120000.dex.extra"), "extra"); }
TEST(pat_non_numeric)       { ASSERT(!matches_dex_dump_pattern("dex_abc_0x7ff000_20250101_120000.dex"), "non-num"); }
TEST(pat_negative)          { ASSERT(!matches_dex_dump_pattern("dex_-1_0x7ff000_20250101_120000.dex"), "negative"); }
TEST(pat_empty)             { ASSERT(!matches_dex_dump_pattern(""), "empty"); }
TEST(pat_no_timestamp)      { ASSERT(!matches_dex_dump_pattern("dex_0_0x7ff000.dex"), "no ts"); }
TEST(pat_missing_under)     { ASSERT(!matches_dex_dump_pattern("dex_0x7ff000_20250101_120000.dex"), "missing under"); }

/* ==================== CONFIG TESTS ==================== */

TEST(cfg_defaults) {
    ASSERT_EQ(ENABLE_SECOND_SCAN, 0, "second scan default");
    ASSERT_EQ(THREAD_INITIAL_DELAY, 8, "init delay");
    ASSERT_EQ(ENABLE_REGION_FILTERING, 1, "filtering default");
    ASSERT_EQ(DEX_HEADER_SIZE, 0x70, "header size");
}

TEST(cfg_exclusion_list) {
    int count = 0;
    const char** list = get_excluded_sha1_list(&count);
    ASSERT(count > 0, "entries exist");
    ASSERT(list != NULL, "not null");
}

TEST(cfg_api_init) {
    init_config_manager();
    ASSERT_EQ(should_enable_second_scan(), 0, "2nd scan off");
    ASSERT_EQ(get_initial_delay(), 8, "delay 8");
    ASSERT_EQ(should_enable_region_filtering(), 1, "filtering on");
}

TEST(cfg_templates) {
    init_config_manager();
    int count = 0;
    const char** t = get_output_directory_templates(&count);
    ASSERT(count > 0, "templates exist");
    ASSERT(t != NULL, "not null");
    ASSERT(strstr(t[0], "%s") != NULL, "placeholder present");
}

TEST(cfg_sha1_hex_valid) {
    int count = 0;
    const char** list = get_excluded_sha1_list(&count);
    for (int i = 0; i < count; i++) {
        ASSERT(strlen(list[i]) == 40, "40 chars");
        for (int j = 0; j < 40; j++) {
            char c = list[i][j];
            ASSERT((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'), "hex char");
        }
    }
}

/* ==================== MAIN ==================== */

int main(void) {
    printf("========================================\n");
    printf("  DexDumper Test Suite\n");
    printf("========================================\n");

    printf("\n--- Signal Handler Tests ---\n");
    RUN_TEST(sig_install);
    RUN_TEST(sig_null_ptr);
    RUN_TEST(sig_low_addr);
    RUN_TEST(sig_heap);
    RUN_TEST(sig_read_heap);
    RUN_TEST(sig_read_null);
    RUN_TEST(sig_read_zero);

    printf("\n--- SHA1 Tests ---\n");
    RUN_TEST(sha1_empty);
    RUN_TEST(sha1_abc);
    RUN_TEST(sha1_fox);
    RUN_TEST(sha1_compare_equal);
    RUN_TEST(sha1_compare_diff);
    RUN_TEST(sha1_hex);
    RUN_TEST(sha1_hex_small_buffer);
    RUN_TEST(sha1_streaming);
    RUN_TEST(sha1_large);

    printf("\n--- DEX Detector Tests ---\n");
    RUN_TEST(dex_valid_header);
    RUN_TEST(dex_invalid_magic);
    RUN_TEST(dex_size_too_small);
    RUN_TEST(dex_size_exceeds_buf);
    RUN_TEST(dex_bad_header_size);
    RUN_TEST(dex_bad_endian);
    RUN_TEST(dex_string_table_oob);
    RUN_TEST(dex_buf_too_small);
    RUN_TEST(dex_scan_signature);
    RUN_TEST(dex_non_dex_memory);
    RUN_TEST(dex_oat_container);

    printf("\n--- Alignment Bug Tests ---\n");
    RUN_TEST(dex_align_offset_0);
    RUN_TEST(dex_align_offset_4);
    RUN_TEST(dex_align_offset_1);
    RUN_TEST(dex_align_offset_2);
    RUN_TEST(dex_align_offset_3);

    printf("\n--- Memory Scanner Tests ---\n");
    RUN_TEST(region_parse_maps);
    RUN_TEST(region_potential_anonymous);
    RUN_TEST(region_potential_dex_path);
    RUN_TEST(region_potential_oat);
    RUN_TEST(region_potential_app_data);
    RUN_TEST(region_potential_classes);
    RUN_TEST(region_not_potential_system);
    RUN_TEST(region_should_scan_valid);
    RUN_TEST(region_should_scan_no_read_perm);
    RUN_TEST(region_should_scan_too_small);
    RUN_TEST(region_create_copy_valid);
    RUN_TEST(region_create_copy_null);
    RUN_TEST(region_create_copy_zero);
    RUN_TEST(region_create_copy_too_large);

    printf("\n--- Registry Manager Tests ---\n");
    RUN_TEST(registry_inode_dedup);
    RUN_TEST(registry_checksum_dedup);
    RUN_TEST(registry_checksum_not_dedup);
    RUN_TEST(registry_sha1_excluded_match);
    RUN_TEST(registry_sha1_excluded_no_match);
    RUN_TEST(registry_dir_duplicate_found);
    RUN_TEST(registry_dir_duplicate_not_found);
    RUN_TEST(registry_dir_no_match_different_content);

    printf("\n--- Config Cleanup Tests ---\n");
    RUN_TEST(cfg_cleanup_twice_safe);
    RUN_TEST(cfg_cleanup_reinit);

    printf("\n--- Pattern Matching Tests ---\n");
    RUN_TEST(pat_valid_normal);
    RUN_TEST(pat_valid_large_idx);
    RUN_TEST(pat_valid_zero_ptr);
    RUN_TEST(pat_valid_cap_x);
    RUN_TEST(pat_no_dex_prefix);
    RUN_TEST(pat_no_x_in_ptr);
    RUN_TEST(pat_wrong_ext);
    RUN_TEST(pat_extra_after);
    RUN_TEST(pat_non_numeric);
    RUN_TEST(pat_negative);
    RUN_TEST(pat_empty);
    RUN_TEST(pat_no_timestamp);
    RUN_TEST(pat_missing_under);

    printf("\n--- Configuration Tests ---\n");
    RUN_TEST(cfg_defaults);
    RUN_TEST(cfg_exclusion_list);
    RUN_TEST(cfg_api_init);
    RUN_TEST(cfg_templates);
    RUN_TEST(cfg_sha1_hex_valid);

    printf("\n========================================\n");
    printf("  Results: %d run, %d passed, %d failed, %d assertions\n",
           g_tests_run, g_tests_run - g_tests_failed, g_tests_failed, g_assertions);
    printf("========================================\n");

    return g_tests_failed > 0 ? 1 : 0;
}
