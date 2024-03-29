#include <stdio.h>
#include "loader.hpp"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// example

/* compile: 
xtensa-esp32-elf-gcc file.c -r -nostartfiles -nodefaultlibs -nostdlib -e local_main -falign-functions=4
*/

/* elf file code
#include <stdio.h>
#include <stdint.h>

extern void del(int32_t);

void local_main() {
	puts("WON THIS CODE");
	for(int32_t p=0; p < 20; p++){
		printf("Hello world!\n");
		printf("It works for %d times!\n",p);
		del(3000);
	}
}
*/

uint8_t elfFile[] = {

	0x7F, 0x45, 0x4C, 0x46, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x5E, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x04, 0x00, 0x00,
	0x00, 0x03, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x00,
	0x0F, 0x00, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x20, 0x00, 0x00, 0x00, 0xB8, 0x0B, 0x00, 0x00, 0x36, 0x61, 0x00, 0x7D,
	0x01, 0x21, 0xFA, 0xFF, 0xAD, 0x02, 0x25, 0x00, 0x00, 0x0C, 0x02, 0x29,
	0x07, 0x46, 0x08, 0x00, 0x21, 0xF8, 0xFF, 0xAD, 0x02, 0x25, 0x00, 0x00,
	0x21, 0xF7, 0xFF, 0xB2, 0x27, 0x00, 0x20, 0xA2, 0x20, 0x25, 0x00, 0x00,
	0x21, 0xF5, 0xFF, 0xAD, 0x02, 0x25, 0x00, 0x00, 0x28, 0x07, 0x1B, 0x22,
	0x29, 0x07, 0x28, 0x07, 0x1C, 0x33, 0x27, 0xA3, 0xD6, 0x3D, 0xF0, 0x1D,
	0xF0, 0x00, 0x00, 0x00, 0x57, 0x55, 0x4E, 0x20, 0x54, 0x48, 0x49, 0x53,
	0x20, 0x43, 0x4F, 0x44, 0x45, 0x00, 0x00, 0x00, 0x48, 0x65, 0x6C, 0x6C,
	0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x00, 0x00, 0x00, 0x00,
	0x49, 0x74, 0x20, 0x77, 0x6F, 0x72, 0x6B, 0x73, 0x20, 0x66, 0x6F, 0x72,
	0x20, 0x25, 0x64, 0x20, 0x74, 0x69, 0x6D, 0x65, 0x73, 0x21, 0x0A, 0x00,
	0x00, 0x47, 0x43, 0x43, 0x3A, 0x20, 0x28, 0x63, 0x72, 0x6F, 0x73, 0x73,
	0x74, 0x6F, 0x6F, 0x6C, 0x2D, 0x4E, 0x47, 0x20, 0x65, 0x73, 0x70, 0x2D,
	0x32, 0x30, 0x32, 0x30, 0x72, 0x33, 0x29, 0x20, 0x38, 0x2E, 0x34, 0x2E,
	0x30, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x58, 0x74, 0x65, 0x6E, 0x73, 0x61, 0x5F, 0x49, 0x6E, 0x66,
	0x6F, 0x00, 0x55, 0x53, 0x45, 0x5F, 0x41, 0x42, 0x53, 0x4F, 0x4C, 0x55,
	0x54, 0x45, 0x5F, 0x4C, 0x49, 0x54, 0x45, 0x52, 0x41, 0x4C, 0x53, 0x3D,
	0x30, 0x0A, 0x41, 0x42, 0x49, 0x3D, 0x30, 0x0A, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x28, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x14, 0x00,
	0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x2D, 0x00,
	0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x04, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0E, 0x00,
	0x00, 0x00, 0x04, 0x28, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x0D, 0x00,
	0x00, 0x00, 0x04, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x07, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0xF1, 0xFF,
	0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x18, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
	0x12, 0x00, 0x01, 0x00, 0x00, 0x6D, 0x61, 0x69, 0x6E, 0x2E, 0x63, 0x00,
	0x64, 0x65, 0x6C, 0x00, 0x70, 0x72, 0x69, 0x6E, 0x74, 0x66, 0x00, 0x70,
	0x75, 0x74, 0x73, 0x00, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x5F, 0x6D, 0x61,
	0x69, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x14, 0x0C, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x46, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x14, 0x0C, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x08, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x14, 0x0B, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x00, 0x00, 0x14, 0x0A, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x00, 0x14, 0x01, 0x00, 0x00,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x73, 0x79, 0x6D, 0x74, 0x61, 0x62,
	0x00, 0x2E, 0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2E, 0x73, 0x68,
	0x73, 0x74, 0x72, 0x74, 0x61, 0x62, 0x00, 0x2E, 0x72, 0x65, 0x6C, 0x61,
	0x2E, 0x74, 0x65, 0x78, 0x74, 0x00, 0x2E, 0x72, 0x6F, 0x64, 0x61, 0x74,
	0x61, 0x00, 0x2E, 0x64, 0x61, 0x74, 0x61, 0x00, 0x2E, 0x62, 0x73, 0x73,
	0x00, 0x2E, 0x63, 0x6F, 0x6D, 0x6D, 0x65, 0x6E, 0x74, 0x00, 0x2E, 0x78,
	0x74, 0x65, 0x6E, 0x73, 0x61, 0x2E, 0x69, 0x6E, 0x66, 0x6F, 0x00, 0x2E,
	0x72, 0x65, 0x6C, 0x61, 0x2E, 0x78, 0x74, 0x2E, 0x6C, 0x69, 0x74, 0x00,
	0x2E, 0x72, 0x65, 0x6C, 0x61, 0x2E, 0x78, 0x74, 0x2E, 0x70, 0x72, 0x6F,
	0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x34, 0x00, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1B, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x98, 0x02, 0x00, 0x00, 0x9C, 0x00, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x34, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x39, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
	0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00,
	0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xE6, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x54, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x1E, 0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x4F, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x03, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x26, 0x01, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x5C, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x03, 0x00, 0x00, 0x6C, 0x00, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x0C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x94, 0x01, 0x00, 0x00,
	0xE0, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
	0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x74, 0x02, 0x00, 0x00, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x11, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xAC, 0x03, 0x00, 0x00, 0x6A, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00

};

extern "C" void del(int32_t m) {
	TickType_t xDelay = m / portTICK_PERIOD_MS;
	vTaskDelay(xDelay);
}

extern "C" void app_main() {
	ElfLoader test((void*)elfFile, {
		{"puts", (void*) puts},
		{"printf", (void*) printf},
		{"del", (void*) del}
	});
	test.parse();
	test.relocate();
	((void (*) ())test.getEntryPoint("local_main"))();
/*
	// aligned new
	ElfLoader *test = new (32) ElfLoader((void*)elfFile, {
		{"puts", (void*) puts},
		{"printf", (void*) printf},
		{"del", (void*) del}
	});

	test->parse();
	test->relocate();

	// search entry point by name if header_m->e_entry == 0
  
	((void (*) ())test->getEntryPoint("local_main"))();

	delete test;
*/
}
