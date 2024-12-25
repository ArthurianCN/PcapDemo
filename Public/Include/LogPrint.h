#pragma once
#pragma once
#include <stdio.h>


#define LOG_ERROR(format, ...)  printf("[ERROR] [%d %s] " format "\n", __LINE__, __func__, ##__VA_ARGS__)
#define LOG_WARNING(format, ...)  printf("[WARN] [%d %s] " format "\n", __LINE__, __func__, ##__VA_ARGS__)			
#define LOG_DEBUG(format, ...)  printf("[DEBUG] [%d %s] " format "\n", __LINE__, __func__, ##__VA_ARGS__)			
#define LOG_INFO(format, ...)  printf("[INFO] [%d %s] " format "\n", __LINE__, __func__, ##__VA_ARGS__)			
