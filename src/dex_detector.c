#include "dex_detector.h"

#define SCAN_CHUNK_SIZE (64 * 1024)

int validate_dex_header_structure(const void* header_start, size_t buffer_size, 
                                 size_t header_offset) {
    if (header_offset + DEX_HEADER_SIZE > buffer_size) return 0;

    uint32_t dex_file_size = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x20, 
                           &dex_file_size, sizeof(uint32_t))) {
        return 0;
    }

    if (dex_file_size < DEX_MIN_FILE_SIZE || dex_file_size > DEX_MAX_FILE_SIZE) {
        LOGW("Invalid DEX file size in header: %u (expected %d-%d)", 
             dex_file_size, DEX_MIN_FILE_SIZE, DEX_MAX_FILE_SIZE);
        return 0;
    }

    if (dex_file_size > (buffer_size - header_offset)) {
        LOGW("DEX file size %u exceeds available buffer space %zu", 
             dex_file_size, buffer_size - header_offset);
        return 0;
    }

    uint32_t header_size_value = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x24, 
                           &header_size_value, sizeof(uint32_t))) {
        return 0;
    }
    
    if (header_size_value != DEX_HEADER_SIZE) {
        LOGW("DEX header size mismatch: %u (expected %u)", 
             header_size_value, DEX_HEADER_SIZE);
        return 0;
    }

    uint32_t endian_tag_value = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x28, 
                           &endian_tag_value, sizeof(uint32_t))) {
        return 0;
    }
    
    if (endian_tag_value != 0x12345678U) {
        LOGW("Unexpected DEX endian tag: 0x%08x", endian_tag_value);
        return 0;
    }

    uint32_t string_table_size = 0, string_table_offset = 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x38, 
                           &string_table_size, sizeof(uint32_t))) return 0;
    if (!read_memory_safely((const char*)header_start + header_offset + 0x3C, 
                           &string_table_offset, sizeof(uint32_t))) return 0;
    
    if (string_table_offset > dex_file_size) return 0;
    if ((uint64_t)string_table_offset + (uint64_t)string_table_size * 4 > dex_file_size) return 0;

    return 1;
}

int scan_for_dex_signature(const void* scan_start, size_t scan_size, 
                          size_t max_scan_limit, DexDetectionResult* detection_result) {
    if (scan_start == NULL || scan_size == 0) return 0;
    
    size_t actual_scan_limit = (max_scan_limit > scan_size) ? scan_size : max_scan_limit;
    if (actual_scan_limit < 8) return 0;
    
    unsigned char chunk[SCAN_CHUNK_SIZE];
    
    for (size_t chunk_offset = 0; chunk_offset + 8 <= actual_scan_limit; chunk_offset += SCAN_CHUNK_SIZE) {
        size_t chunk_sz = actual_scan_limit - chunk_offset;
        if (chunk_sz > SCAN_CHUNK_SIZE) chunk_sz = SCAN_CHUNK_SIZE;
        
        if (!read_memory_safely((const char*)scan_start + chunk_offset, chunk, chunk_sz)) {
            continue;
        }
        
        size_t scan_end = chunk_sz - 8;
        for (size_t local_offset = 0; local_offset <= scan_end; local_offset++) {
            if (memcmp(chunk + local_offset, "dex\n035", 7) == 0 || 
                memcmp(chunk + local_offset, "dex\n036", 7) == 0 ||
                memcmp(chunk + local_offset, "dex\n037", 7) == 0 ||
                memcmp(chunk + local_offset, "dex\n038", 7) == 0 ||
                memcmp(chunk + local_offset, "dex\n039", 7) == 0) {
                
                size_t global_offset = chunk_offset + local_offset;
                VLOGD("Detected DEX signature at offset %zu", global_offset);
                
                if (validate_dex_header_structure(scan_start, scan_size, global_offset)) {
                    uint32_t file_size_value = 0;
                    if (read_memory_safely((const char*)scan_start + global_offset + 0x20, 
                                          &file_size_value, sizeof(uint32_t))) {
                        detection_result->dex_size = file_size_value;
                        detection_result->dex_address = (void*)((char*)scan_start + global_offset);
                        LOGI("Valid DEX file detected at %p, size: %u bytes", 
                             detection_result->dex_address, file_size_value);
                        return 1;
                    }
                } else {
                    LOGW("DEX signature found but header validation failed at offset %zu", 
                         global_offset);
                }
            }
        }
    }
    return 0;
}

int scan_region_for_dex_files(const void* region_start, size_t region_size, 
                             DexDetectionResult* detection_result) {
    if (region_size < DEX_HEADER_SIZE) return 0;
    
    size_t scan_limit = (region_size > DEFAULT_SCAN_LIMIT) ? DEFAULT_SCAN_LIMIT : region_size;
    return scan_for_dex_signature(region_start, region_size, scan_limit, detection_result);
}

int scan_region_for_oat_dex_files(const void* region_start, size_t region_size, 
                                 DexDetectionResult* detection_result) {
    if (region_size < 8) return 0;
    
    unsigned char oat_magic[4];
    if (!read_memory_safely(region_start, oat_magic, 4)) return 0;
    
    if (memcmp(oat_magic, "oat\n", 4) != 0) return 0;
    
    VLOGD("Detected OAT container, scanning for embedded DEX");
    return scan_for_dex_signature(region_start, region_size, 64 * 1024, detection_result);
}

int perform_comprehensive_dex_detection(const void* region_start, size_t region_size, 
                                       DexDetectionResult* detection_result) {
    const struct {
        const char* detection_type;
        int (*detector_function)(const void*, size_t, DexDetectionResult*);
    } detection_strategies[] = {
        {"standard DEX", scan_region_for_dex_files},
        {"OAT container", scan_region_for_oat_dex_files}
    };
    
    size_t strategy_count = sizeof(detection_strategies) / sizeof(detection_strategies[0]);
    
    for (size_t i = 0; i < strategy_count; i++) {
        VLOGD("Attempting %s detection", detection_strategies[i].detection_type);
        if (detection_strategies[i].detector_function(region_start, region_size, detection_result)) {
            LOGI("DEX file detected via %s strategy", detection_strategies[i].detection_type);
            return 1;
        }
    }
    
    return 0;
}
