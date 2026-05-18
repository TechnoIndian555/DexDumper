#include "memory_scanner.h"
#include "file_utils.h"
#include "config_manager.h"

/**
 * @brief Tests if a memory region can be safely read
 * 
 * Attempts to read the first byte of the region to verify read permissions.
 * This prevents crashes when trying to scan protected memory regions.
 * 
 * @param memory_region Region to test for read access
 * @return 1 if readable, 0 if protected or invalid
 */
int test_region_read_access(const MemoryRegion* memory_region) {
    // Basic sanity checks
    if (memory_region->start_address == NULL || 
        memory_region->end_address == NULL || 
        memory_region->start_address >= memory_region->end_address) {
        return 0;
    }
    
    // Check region size constraints
    size_t region_size = (char*)memory_region->end_address - (char*)memory_region->start_address;
    if (region_size < 16 || region_size > MAX_REGION_SIZE) {
        return 0;
    }
    
    // Test read access by attempting to read first byte
    unsigned char test_byte;
    return read_memory_safely(memory_region->start_address, &test_byte, 1);
}

/**
 * @brief Parses /proc/self/maps to get memory region information
 * 
 * Reads the process memory map to identify all memory regions with their
 * permissions, backing files, and other metadata.
 * 
 * @param regions_array Output parameter for allocated array of regions
 * @return Number of memory regions found, 0 on error
 */
int parse_memory_regions(MemoryRegion** regions_array) {
    // Open process memory maps file
    FILE* maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        LOGE("Failed to open process memory maps: %s", strerror(errno));
        return 0;
    }
    
    char map_line[1024];
    int region_count = 0;
    int regions_capacity = MAX_REGIONS_INITIAL_CAPACITY;
    
    // Allocate initial regions array
    *regions_array = malloc(regions_capacity * sizeof(MemoryRegion));
    if (!*regions_array) {
        LOGE("Memory allocation failed for regions array");
        fclose(maps_file);
        return 0;
    }

    // Read each line from /proc/self/maps
    while (fgets(map_line, sizeof(map_line), maps_file)) {
        // Resize array if needed
        if (region_count >= regions_capacity) {
            regions_capacity *= 2;
            MemoryRegion* temporary_array = realloc(*regions_array, 
                                                   regions_capacity * sizeof(MemoryRegion));
            if (!temporary_array) {
                LOGE("Memory reallocation failed for regions, current count: %d", region_count);
                break;
            }
            *regions_array = temporary_array;
        }
        
        // Parse current line into MemoryRegion structure
        MemoryRegion* current_region = &(*regions_array)[region_count];
        memset(current_region, 0, sizeof(MemoryRegion));
        
        unsigned long start_addr = 0, end_addr = 0;
        
        int field_count = sscanf(map_line, "%lx-%lx %4s %lx %x:%x %lu %255s",
                           &start_addr, 
                           &end_addr, 
                           current_region->permissions,
                           &current_region->file_offset, 
                           &current_region->device_major, 
                           &current_region->device_minor,
                           &current_region->inode_number, 
                           current_region->path_name);
        
        current_region->start_address = (void*)start_addr;
        current_region->end_address = (void*)end_addr;

        // Handle case where pathname is missing
        if (field_count == 7) {
            current_region->path_name[0] = '\0';
        }
        
        // Valid line must have at least 7 fields
        if (field_count >= 7) {
            region_count++;
        }
    }
    
    fclose(maps_file);
    LOGI("Successfully parsed %d memory regions", region_count);
    return region_count;
}

/**
 * @brief Determines if a memory region should be scanned for DEX files
 * 
 * Applies filtering rules to exclude system regions, read-protected areas,
 * and regions that are too small or too large to contain DEX files.
 * 
 * @param memory_region Region to evaluate for scanning
 * @return 1 if region should be scanned, 0 if excluded
 */
int should_scan_memory_region(const MemoryRegion* memory_region) {
    // Check read permission
    if (strchr(memory_region->permissions, 'r') == NULL) {
        return 0;
    }
    
    // Check size constraints
    size_t region_size = (char*)memory_region->end_address - (char*)memory_region->start_address;
    if (region_size < DEX_MIN_FILE_SIZE || region_size > MAX_REGION_SIZE) {
        return 0;
    }
    
    // Validate address range
    if (memory_region->start_address == NULL || 
        memory_region->end_address == NULL || 
        memory_region->start_address >= memory_region->end_address) {
        return 0;
    }
    
    // Test actual read access
    if (!test_region_read_access(memory_region)) {
        VLOGD("Skipping unreadable memory region: %p-%p %s", 
              memory_region->start_address, memory_region->end_address, 
              memory_region->path_name);
        return 0;
    }

    // Configurable region filtering
    if (should_enable_region_filtering()) {
        // Apply smart filtering to exclude system regions
        if (strlen(memory_region->path_name) > 0) {
            // Patterns for regions to exclude
            const char* excluded_path_patterns[] = {
                "/system/", "/apex/", "/vendor/", "/framework/",  // System directories
                "core-oj", "core-libart", "android.", "java.",    // System libraries
                "com.android.", "com.google.", "/dev/", "/proc/", // More system paths
                "/ashmem/", "/dmabuf", "kgsl-3d0", "graphics",    // Hardware buffers
                "[heap]", "[stack]", "[anon:",                    // Special regions
                "hwui"                                            // UI framework
            };
    
            const char* package_name = get_current_package_name();
    
            // Check against exclusion patterns
            for (size_t i = 0; i < sizeof(excluded_path_patterns)/sizeof(excluded_path_patterns[0]); i++) {
                if (strstr(memory_region->path_name, excluded_path_patterns[i])) {
                    // Override exclusion for certain DEX-related patterns
                    if (strstr(memory_region->path_name, ".dex") ||
                        strstr(memory_region->path_name, ".vdex") ||
                        strstr(memory_region->path_name, ".apk") ||
                        strstr(memory_region->path_name, "dalvik") ||
                        strstr(memory_region->path_name, "jit") ||
                        (package_name && strlen(package_name) > 0 && 
                         strstr(memory_region->path_name, package_name))) {
                        VLOGD("Exclusion overridden for region: %s", memory_region->path_name);
                        break;
                    }
                    VLOGD("Excluding system region: %s", memory_region->path_name);
                    return 0;
                }
            }
        }
    }
    
    VLOGD("Region approved for scanning: %p-%p %s", 
          memory_region->start_address, memory_region->end_address, 
          memory_region->path_name);
    return 1;
}

/**
 * @brief Identifies memory regions likely to contain DEX files
 * 
 * Uses heuristics to prioritize regions that are more likely to contain
 * DEX files, such as app-specific regions, anonymous mappings with DEX
 * indicators, and known DEX container files.
 * 
 * @param memory_region Region to evaluate
 * @return 1 if high-potential region, 0 otherwise
 */
int is_potential_dex_region(const MemoryRegion* memory_region) {
    if (memory_region == NULL) {
        LOGW("NULL memory region provided to potential check");
        return 0;
    }
    
    const char* region_path = memory_region->path_name;
    const char* package_name = get_current_package_name();
    
    // Anonymous regions are often where runtime-loaded DEX resides
    if (strlen(region_path) == 0) {
        return 1;
    }
    
    // Check anonymous regions with DEX indicators
    if (strstr(region_path, "[anon:") != NULL) {
        if (strstr(region_path, "dalvik") != NULL || 
            strstr(region_path, "jit") != NULL ||
            strstr(region_path, "dex") != NULL) {
            return 1;
        }
        // Consider all anonymous regions as potential
        // return 1;
    }
    
    // Direct DEX file indicators
    if (strstr(region_path, ".dex") != NULL || 
        strstr(region_path, ".vdex") != NULL ||
        strstr(region_path, ".odex") != NULL ||
        strstr(region_path, ".art") != NULL) {
        return 1;
    }
    
    // App-specific regions
    if (package_name && strstr(region_path, package_name)) {
        return 1;
    }
    
    // ART/OAT related regions
    if (strstr(region_path, "oat/") != NULL || 
        strstr(region_path, "dalvik-cache") != NULL) {
        return 1;
    }
    
    // Container files that may hold DEX
    if (strstr(region_path, ".apk") != NULL || 
        strstr(region_path, ".jar") != NULL ||
        strstr(region_path, ".zip") != NULL) {
        return 1;
    }
    
    // Application data directories
    if (strstr(region_path, "/data/app/") != NULL ||
        strstr(region_path, "/data/data/") != NULL ||
        strstr(region_path, "/data/user/") != NULL ||
        strstr(region_path, "/data/user_de/") != NULL) {
        return 1;
    }
    
    // Temporary and cache directories
    if (strstr(region_path, "/data/local/tmp/") != NULL ||
        strstr(region_path, "/cache/") != NULL ||
        strstr(region_path, "code_cache") != NULL) {
        return 1;
    }
    
    // Common APK and class file patterns
    if (strstr(region_path, "classes") != NULL ||
        strstr(region_path, "base.apk") != NULL ||
        strstr(region_path, "split_config") != NULL) {
        return 1;
    }
    
    return 0;
}

/**
 * @brief Creates a safe copy of memory region for processing
 * 
 * Copies memory from potentially unstable regions into a stable buffer
 * for analysis and dumping. This prevents issues if the original memory
 * becomes unavailable during processing.
 * 
 * @param source_address Address to copy from
 * @param copy_size Number of bytes to copy
 * @return Pointer to allocated copy, NULL on failure
 */
void* create_memory_copy(const void* source_address, size_t copy_size) {
    // Validate inputs
    if (source_address == NULL || copy_size == 0 || copy_size > DEX_MAX_FILE_SIZE) {
        return NULL;
    }
    
    // Allocate buffer for copy
    void* memory_copy = malloc(copy_size);
    if (!memory_copy) return NULL;
    
    // Safely copy memory using signal-protected read
    if (!read_memory_safely(source_address, memory_copy, copy_size)) {
        free(memory_copy);
        return NULL;
    }
    
    return memory_copy;
}