#include "common.h"
#include "config.h"
#include "signal_handler.h"
#include "file_utils.h"
#include "registry_manager.h"
#include "memory_scanner.h"
#include "dex_detector.h"
#include "stealth.h"
#include "config_manager.h"

// Global verbosity control - set to 1 for verbose debugging output
int verbose_logging = 0;

/**
 * @brief Scans a single memory region and dumps any found DEX files
 * 
 * This function handles the complete process for one memory region:
 * - Checks if region should be scanned
 * - Performs DEX detection
 * - Creates safe memory copy
 * - Dumps to file if DEX found
 * 
 * @param output_directory Directory to save dumped files
 * @param memory_region Memory region to scan
 * @param region_index Index of region for logging and filenames
 * @return 1 if DEX was dumped, 0 otherwise
 */
static int scan_and_dump_region(const char* output_directory, 
                               const MemoryRegion* memory_region, 
                               int region_index) {
    // Apply region filtering rules
    if (!should_scan_memory_region(memory_region)) {
        return 0;
    }
    
    size_t region_size = (char*)memory_region->end_address - (char*)memory_region->start_address;
    
    // Check if this is a high-priority region for scanning
    int is_high_priority = is_potential_dex_region(memory_region);
    
    // Log region information with appropriate detail level
    if (is_high_priority) {
        LOGI("HIGH PRIORITY: Scanning region %d: %p-%p (%zu bytes) %s", 
             region_index, memory_region->start_address, memory_region->end_address, 
             region_size, memory_region->path_name);
    } else {
        VLOGD("Scanning region %d: %p-%p (%zu bytes) %s", 
             region_index, memory_region->start_address, memory_region->end_address, 
             region_size, memory_region->path_name);
    }
    
    int dump_successful = 0;
    
    // Perform DEX detection on this region
    DexDetectionResult detection_result = {0};
    if (perform_comprehensive_dex_detection(memory_region->start_address, region_size, 
                                           &detection_result)) {
        // Create safe copy of detected DEX file
        void* safe_memory_copy = create_memory_copy(detection_result.dex_address, 
                                                   detection_result.dex_size);
        if (safe_memory_copy) {
            // Dump the copied memory to file
            if (dump_memory_to_file(output_directory, memory_region, region_index, 
                                   safe_memory_copy, detection_result.dex_size)) {
                dump_successful = 1;
                LOGI("Successfully dumped DEX from region %d", region_index);
            }
            free(safe_memory_copy); // Always free the copy
        } else {
            LOGW("Failed to create memory copy for region %d", region_index);
        }
    }
    
    return dump_successful;
}

/**
 * @brief Executes the complete memory dumping process
 * 
 * This is the main dumping logic that:
 * - Parses all memory regions
 * - Scans high-priority regions first
 * - Falls back to all regions if no DEX found
 * - Manages the overall scanning strategy
 * 
 * @param output_directory Directory where dumped files will be saved
 */
static void execute_memory_dumping(const char* output_directory) {
    MemoryRegion* memory_regions = NULL;
    
    // Parse process memory map to get all regions
    int region_count = parse_memory_regions(&memory_regions);
    
    if (region_count == 0) {
        LOGE("No memory regions found for scanning");
        return;
    }
    
    LOGI("Initiating memory dump for %d regions (Filtering: %d)", 
         region_count, ENABLE_REGION_FILTERING);
    
    int total_dumps_successful = 0;
    int processed_region_count = 0;
    
    // First pass: Scan only high-priority regions
    for (int i = 0; i < region_count; i++) {
        if (is_potential_dex_region(&memory_regions[i]) && 
            should_scan_memory_region(&memory_regions[i])) {
            if (scan_and_dump_region(output_directory, &memory_regions[i], i)) {
                total_dumps_successful++;
            }
            processed_region_count++;
        }
    }
    
    // Second pass: If no DEX found in priority regions, scan everything
    if (total_dumps_successful == 0) {
        LOGI("No DEX files found in priority regions, scanning all regions");
        for (int i = 0; i < region_count; i++) {
            if (!is_potential_dex_region(&memory_regions[i]) && 
                should_scan_memory_region(&memory_regions[i])) {
                if (scan_and_dump_region(output_directory, &memory_regions[i], i)) {
                    total_dumps_successful++;
                }
                processed_region_count++;
            }
        }
    }
    
    // Log final statistics
    LOGI("Dumping process completed: Processed %d regions, dumped %d DEX files", 
         processed_region_count, total_dumps_successful);
    
    // Clean up memory regions array
    if (memory_regions) {
        free(memory_regions);
    }
}

/**
 * @brief Main dumping thread function
 * 
 * This function runs in a separate thread and coordinates the entire
 * dumping process including initialization, cleaning, and multiple passes.
 * 
 * @param thread_argument Thread argument (unused)
 * @return NULL
 */
static void* dumping_thread_function(void* thread_argument) {
    // Initialize configuration system (loads runtime config if available)
    init_config_manager();
    
    // Initialize random seed for stealth techniques
    srand((unsigned)(time(NULL) ^ getpid() ^ (uintptr_t)pthread_self()));
    
    // Apply anti-detection techniques
    apply_stealth_techniques();
    
    // Configurable initial delay
    int initial_delay = get_initial_delay();
    LOGI("Initial delay: %d seconds", initial_delay);
    sleep(initial_delay);
    
    // Determine where to save dumped files
    char* output_directory = get_output_directory_path();
    
    // Clean previous dumps to avoid accumulation
    LOGI("Cleaning output directory before dump");
    clean_output_directory(output_directory);
    
    // Ensure output directory exists
    mkdir(output_directory, 0755);
    
    // First scan
    LOGI("=== STARTING FIRST DEX DUMP OPERATION ===");
    execute_memory_dumping(output_directory); // Execute main dumping process
    
    // Configurable conditional second scan
    if (should_enable_second_scan()) {
        int second_delay = get_second_scan_delay(); // Configurable second scan
        LOGI("Second scan delay: %d seconds", second_delay);
        sleep(second_delay);
        
        LOGI("=== STARTING SECOND DEX DUMP OPERATION ===");
        apply_stealth_techniques();  // Re-apply stealth for second scan
        execute_memory_dumping(output_directory); // Re-apply dumping process
    } else {
        LOGI("Second scan disabled in configuration");
    }
    
    // Clean up global registry to free memory
    pthread_mutex_lock(&dump_registry_mutex);
    if (dumped_files_registry) {
        free(dumped_files_registry);
        dumped_files_registry = NULL;
        dumped_files_count = 0;
        dumped_files_capacity = 0;
    }
    pthread_mutex_unlock(&dump_registry_mutex);
    
    LOGI("=== DEX DUMPING OPERATION COMPLETED SUCCESSFULLY ===");
    return NULL;
}

/**
 * @brief Library constructor - automatically starts dumping when loaded
 * 
 * This function is automatically called when the shared library is loaded
 * into a process. It starts the dumping thread in the background.
 */
__attribute__((constructor)) 
void initialize_dumper() {
    pthread_t dumper_thread;
    pthread_attr_t thread_attributes;
    
    // Configure thread attributes
    pthread_attr_init(&thread_attributes);
    pthread_attr_setdetachstate(&thread_attributes, PTHREAD_CREATE_DETACHED);
    
    // Create and start dumping thread
    if (pthread_create(&dumper_thread, &thread_attributes, 
                      dumping_thread_function, NULL) == 0) {
        LOGI("Dex dumping thread started successfully");
    } else {
        LOGE("Failed to create dex dumping thread");
    }
    
    pthread_attr_destroy(&thread_attributes);
}
