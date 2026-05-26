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
    
    // Configurable conditional second scan
    if (should_enable_second_scan()) {
        int second_delay = get_second_scan_delay(); // Configurable second scan
        LOGI("Second scan delay: %d seconds", second_delay);
        sleep(second_delay);
        
        LOGI("=== STARTING SECOND DEX DUMP OPERATION ===");
        apply_stealth_techniques();  // Re-apply stealth for second scan
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
