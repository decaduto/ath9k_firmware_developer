
/*
	Made by Edoardo Mantovani, aka Bpl
		2021-2022 Edoardo Mantovani All Rights Reserved
*/

#if defined(__ELF__) && defined(__GNUC__)
    #pragma message("GCC: The output executable format is an ELF")

#define FUSE_USE_VERSION 30
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <pthread.h>
#include <link.h>
#include <stdbool.h>
#include <signal.h>
#include <dialog.h>
#include <ncurses.h>
#include <fuse.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <libusb-1.0/libusb.h>

#pragma message("built-in headers are: elf, signal, dialog, link, pthread")
#pragma message("external headers are: libusb, ncurses, fuse")
#pragma message("system dependent headers are: uio, mman")

#ifdef __thread
    #pragma message("__thread only allocation is available!")
#endif

#define FIRMWARE_DOWNLOAD       0x30
#define FIRMWARE_DOWNLOAD_COMP  0x31

#define USB_MSG_TIMEOUT 	1000

#ifndef USB_DIR_OUT
	#define USB_DIR_OUT	0
#endif

#ifndef min
	size_t min(size_t a, size_t b){
		return( a > b )  ? b : a;
	}
#endif

#ifndef ATH9U_DESCRIPTOR_SIZE
    #define ATH9U_DESCRIPTOR_SIZE 128
#endif

/* this will be very important later, is going to be updated by playing with the section size */
static int chip_firmware_size = 0;
static int out_endpoint = 0;

extern unsigned char _binary_ath9u_fw_htc_9271_fw_start;
extern unsigned char _binary_ath9u_fw_htc_9271_fw_end;

/* function prototypes */
void ddv_upload_fw(struct libusb_device_handle *, const void *, size_t);
signed int ddv_send_management_frame(struct libusb_device_handle *, const void *);
void ddv_eject_device(struct libusb_device_handle *);
signed int ddv_reboot_device(struct libusb_device_handle *);

enum ddv_errors{
	/* misc related errors */
	NO_CORRECT_PARAMS = 1,
	NO_CORRECT_ENDPOINT,
	/* LIBUSB related errors */
	LIBUSB_INIT_FAIL = 7,
	LIBUSB_VID_PID_FAIL,
	LIBUSB_CONTROL_FAIL,
    	LIBUSB_DESCRIPTOR_FAIL,
};


/* General 802.11 adapter description */

/* device capabilities */
enum{
	DEV_CAN_TX = 0x21,
	DEV_CAN_RX,
	DEV_CAN_STA_MODE,
	DEV_CAN_AP_MODE,
	DEV_CAN_P2P_MODE,
	DEV_CAN_ADHOC_MODE,
	DEV_CAN_MONITOR_MODE,
	DEV_CAN_2GHZ,
	DEV_CAN_5GHZ,
    	DEV_CAN_INJECT,
    	DEV_CAN_SUPPORT_WPA,
   	DEV_CAN_SUPPORT_WPA2,
    	DEV_CAN_SUPPORT_WPA3,
    	DEV_IS_80211N,
    	DEV_IS_80211AC,
    	DEV_IS_80211AX,
	DEV_IS_CUSTOM_FIRMWARE,
	DEV_IS_SPECTRAL_COMPATIBLE,
};

enum dev_bus{
	DEV_IS_ON_PCI = 0x1,
	DEV_IS_ON_USB,
	DEV_IS_ON_SDIO,
	DEV_IS_ON_I2C,	 /* for automotive systems, this is only a general flag, not to be used */
};

enum dev_arch{
	DEV_IS_ARM32,
	DEV_IS_ARM64,
	DEV_IS_INTEL, /* just for Joke */
	DEV_IS_XTENSA, /* our case */
    	DEV_IS_HEXAGON, /* for Pure-Qualcomm products, not our case */
};

static struct ath9u_device_informations{
	unsigned char *device_name;
	unsigned int   device_vendor_id;
	unsigned int   device_product_id;
    	unsigned char  device_description[ATH9U_DESCRIPTOR_SIZE];
	enum dev_bus   device_bus;
	enum dev_arch  device_architecture;
	long 	       device_capabilities;
	long           device_total_rammemory;
    	short          device_usb_power_voltage;
    	short          device_transfer;
	bool	       device_is_on;
    	bool           device_is_supported;
	bool           device_is_plugged;
	bool 	       device_has_modified_fw;
    	bool           device_support_legacy_dfu; /* this will be discovered by reading its USB descriptor */
}__thread global_device_informations = {
	.device_has_modified_fw = false,


};


static struct global_address_space_info{
	uint32_t boot_segment_vaddr;
	uint32_t boot_segment_memsz;
	uint32_t ath9u_ops_segment_vaddr;
	uint32_t ath9u_ops_segment_memsz;
	uint32_t compiler_segment_vaddr;
	uint32_t compiler_segment_memsz;
	uint32_t source_segment_vaddr;
	uint32_t source_segment_memsz;
	uint32_t firmware_segment_vaddr;
	uint32_t firmware_segment_memsz;
}__thread __attribute__((aligned(1))) global_address = {
	.boot_segment_vaddr = 0x00,
	.boot_segment_memsz = 0x00,
	.ath9u_ops_segment_vaddr = 0x00,
	.ath9u_ops_segment_memsz = 0x00,
	.compiler_segment_vaddr = 0x00,
	.compiler_segment_memsz = 0x00,
	.source_segment_vaddr = 0x00,
	.source_segment_memsz = 0x00,
	.firmware_segment_vaddr = 0x00,
	.firmware_segment_memsz = 0x00,
};

#ifndef GENERATE_PLUGIN_CB_N
	#define GENERATE_PLUGIN_CB_N	3
#endif

#define GENERATE_PLUGIN_CB(callback_number)	{	\
	int (*plugin_callback_ ##callback_number)();	\
}	\

#define INITIALIZE_PLUGIN_CB(callback_number)	{	\
}

struct{
	void (*upload_firmware)(struct libusb_device_handle *, const void *, size_t);
	void (*init_device)();
	void (*shtd_device)();
	void (*send_device)();
    	signed int (*reboot_device)(struct libusb_device_handle *);
	void (*eject_device)(struct libusb_device_handle *);
	void (*add_plugin)();
	void (*delete_plugin)();
	void (*manage_plugin_list)();
	void (*activate_plugin)();
	#pragma message("plugin_callback number is: %d" GENERATE_PLUGIN_CB_N)
    	int  (*plugin_callback1)();
    	int  (*plugin_callback2)();
    	int  (*plugin_callback3)();
}ath9u_ops __attribute__((__section__(".ath9u_ops, \"xaw\", @progbits# "))) = {
	.upload_firmware    = ddv_upload_fw,
/*	.init_device        = ,
	.shtd_device        = ,
	.send_device        = ,
*/
	.eject_device       = ddv_eject_device,
    	.reboot_device      = ddv_reboot_device,
/*	.add_plugin         = ,
	.delete_plugin      = ,
	.manage_plugin_list = ,
	.activate_plugin    = ,
*/
    	.plugin_callback1   = NULL,
   	.plugin_callback2   = NULL,
    	.plugin_callback3   = NULL,
};

__attribute__((optimize("O0"))) int ath9u_discover_address_space(struct dl_phdr_info *info, size_t size, void *data){
	/* get the ELF header for gathering the e_entry information */
	Elf64_Ehdr *athu_main_header = (Elf64_Ehdr *)info->dlpi_addr;
	uint32_t entry_point = info->dlpi_addr + athu_main_header->e_entry;
	unsigned char *tmp_var = malloc(8);
	unsigned char * firmware_offset_start = (unsigned char *)&_binary_ath9u_fw_htc_9271_fw_start;
	unsigned char * firmware_offset_end   = (unsigned char *)&_binary_ath9u_fw_htc_9271_fw_end;
        snprintf(tmp_var, 8, "%d", (firmware_offset_end - firmware_offset_start));
        int firmware_size = atoi(tmp_var);

	printf("ath9k firmware offset start: 0x%x firmware offset end: 0x%x firmware size: %d\n",
		firmware_offset_start,
		firmware_offset_end,
		firmware_size
	);
	free(tmp_var);
	unsigned char *ath9u_mmap = mmap(NULL, firmware_size, ( PROT_READ | PROT_WRITE ), ( MAP_PRIVATE | MAP_ANON ), -1, 0);
	memcpy(ath9u_mmap, firmware_offset_start, firmware_size);
	//for(int i = 0; i < info->dlpi_phnum; i++){
		//printf("segment start: 0x%x segment end: 0x%x\n", /* segment size: %d segment flag: %d\n", */
		//	( info->dlpi_addr + info[i].dlpi_phdr->p_vaddr),
		//	( info->dlpi_addr + ( info[i].dlpi_phdr->p_vaddr + info[i].dlpi_phdr->p_memsz ) )
			/*info[i].dlpi_phdr->p_memsz,
			info[i].dlpi_phdr->p_flags */
		//);
	//}


	munmap(ath9u_mmap, firmware_size);
	return 0;
}

__attribute__((__section__(".boot, \"xaw\", @progbits#"))) __attribute__((constructor(101))) void init(void){
	/* start the discover function, which will populate the 'global_address_space_info' struct with the appropriate addresses */
	dl_iterate_phdr(ath9u_discover_address_space, NULL);


    	/* discover the VID and the PID */
    	unsigned int ath9u_vid = 0x0cf3;
    	unsigned int ath9u_pid = 0x9271;
	/* create libusb context and populate the general 802.11 struct */
	unsigned char ath9u_device_descriptor[ATH9U_DESCRIPTOR_SIZE];
    	memset(ath9u_device_descriptor, 0x00, ATH9U_DESCRIPTOR_SIZE);
	/* get the ath9u_device */
	if( libusb_init(NULL) < 0 ){
		exit(-LIBUSB_INIT_FAIL);
	}
	struct libusb_device_handle *ath9u_device = NULL;
    	global_device_informations.device_vendor_id = ath9u_vid;
    	global_device_informations.device_product_id = ath9u_pid;
	ath9u_device = libusb_open_device_with_vid_pid(NULL, ath9u_vid, ath9u_pid);
	if( ! ( ath9u_device ) ){
		libusb_exit(NULL);
		exit(-LIBUSB_VID_PID_FAIL);
	}
    	if( libusb_get_string_descriptor_ascii(ath9u_device, 0, ath9u_device_descriptor, ATH9U_DESCRIPTOR_SIZE) < 0 ){
        	libusb_exit(NULL);
        	exit(-LIBUSB_DESCRIPTOR_FAIL);
    	}
    	if( ! ( ath9u_device_descriptor ) ){
        	libusb_exit(NULL);
        	exit(-LIBUSB_DESCRIPTOR_FAIL);
    	}
    	memcpy(global_device_informations.device_description, ath9u_device_descriptor, ATH9U_DESCRIPTOR_SIZE);
    	/* gather additional data on the USB device attached */
    	struct libusb_bos_descriptor  *ath9u_configuration_descriptor = (struct libusb_bos_descriptor  *)malloc(sizeof(ath9u_configuration_descriptor));
    	libusb_get_bos_descriptor(ath9u_device, &ath9u_configuration_descriptor);
    	/*
    	global_device_informations.device_capabilities[0]->bDescriptorType = ath9u_configuration_descriptor-> ;
    	global_device_informations.device_capabilities[0]->bDevCapabilityType = ath9u_configuration_descriptor-> ;
    	global_device_informations.device_capabilities[0]-> = ath9u_configuration_descriptor-> ;
    	global_device_informations.device_capabilities[0]-> = ath9u_configuration_descriptor-> ;
    	global_device_informations.device_capabilities[0]-> = ath9u_configuration_descriptor-> ;
    	*/

    	/* use the specific function for freeing, instead of the classic 'free' */
    	libusb_free_bos_descriptor(ath9u_configuration_descriptor);
	/* discover the endpoint, which will be used for every USB bulk/interrupt/control exchange */
	out_endpoint = 0x1;
}

__attribute__((__section__(".end, \"xaw\", @progbits#"))) __attribute__((destructor())) void end(void){
	end_dialog(); /* terminate the dialog API */
	libusb_exit(NULL);
}

signed int ddv_send_management_frame(struct libusb_device_handle *ath9u_usb_handler, const void *tx_frame){
	if( ! ( ath9u_usb_handler ) || sizeof(tx_frame) == 0 ){
		return -1;
	}

	//libusb_bulk_transfer();
}

signed int ar9271_firmware_transfer(int sent_blocks){
  /* this function will be called only if a) TUI option is enabled b) a firmware update is going to be flashed to the AR9271 */
  if( sent_blocks == 0 || chip_firmware_size == 0 ){ /* control that the firmware size is != 0 */
        return -1;
  }
  void *gauge_obj = dlg_allocate_gauge("sending the firmware to the AR9271", NULL, 7, 70, 0);
  for(int i = 0; i <= chip_firmware_size; i += sent_blocks){
        dlg_update_gauge(gauge_obj, i);
        usleep(USB_MSG_TIMEOUT); /* sync the graphical progresses with the USB URB sending time */
  }
  dlg_free_gauge(gauge_obj);
  return 1;
}


void ddv_upload_fw(struct libusb_device_handle *ath9u_usb_handler, const void *fw_data, size_t fw_len){
	if( !( ath9u_usb_handler ) || ( sizeof(fw_data) == 0 ) || ( fw_len == 0 ) ){
		exit(-NO_CORRECT_PARAMS);
	}

    	int addr = 0x501000;
	unsigned char *data = (unsigned char *)malloc(4096);
	/*
	usb_control_msg(hif_dev->udev,  usb_sndctrlpipe(hif_dev->udev, 0),  FIRMWARE_DOWNLOAD,
		(0x40 | USB_DIR_OUT), addr >> 8, 0, buf, transfer,  USB_MSG_TIMEOUT);
	*/
	while(fw_len){
		size_t data_length = min(4096, fw_len);
		memcpy(data, fw_data, data_length);
		int err = libusb_control_transfer(ath9u_usb_handler, 0x40 | USB_DIR_OUT, FIRMWARE_DOWNLOAD, addr >> 8, 0, data, data_length, USB_MSG_TIMEOUT);

		if( err < 0 ){
			libusb_exit(NULL);
			exit(LIBUSB_CONTROL_FAIL);
		}
		fw_len  -= data_length;
		fw_data += data_length;
		addr    += data_length;
	}

	free(data);
	/* complete download message */

	/*
	usb_control_msg(hif_dev->udev, usb_sndctrlpipe(hif_dev->udev, 0), FIRMWARE_DOWNLOAD_COMP,
		         0x40 | USB_DIR_OUT, firm_offset >> 8, 0, NULL, 0, USB_MSG_TIMEOUT);
	*/

	/* where firm_offset is AR9271_FIRMWARE_TEXT  0x903000 */
	#ifndef AR9271_FIRMWARE_TEXT
		#define AR9271_FIRMWARE_TEXT  0x903000
	#endif
	libusb_control_transfer(ath9u_usb_handler, 0x40 | USB_DIR_OUT, FIRMWARE_DOWNLOAD_COMP, AR9271_FIRMWARE_TEXT >> 8, 0, NULL, 0, USB_MSG_TIMEOUT);
}


void ddv_eject_device(struct libusb_device_handle *ath9u_usb){
	/* check args */
	if( sizeof(ath9u_usb) == 0 || !( ath9u_usb ) ){
		exit(-NO_CORRECT_PARAMS);
	}
	/* iterate for finding the bulk out endpoints for sending the URB */


	/* allocate the BULK URB packet to send to the adapter */
	unsigned char *ath9u_bulk_cmd = (unsigned char *)calloc(31, sizeof(char));
	memset(ath9u_bulk_cmd, 0x00, sizeof(ath9u_bulk_cmd));
	ath9u_bulk_cmd[0]  = 0x55;	/* bulk command signature */
	ath9u_bulk_cmd[1]  = 0x53;	/* bulk command signature */
	ath9u_bulk_cmd[2]  = 0x42;	/* bulk command signature */
	ath9u_bulk_cmd[3]  = 0x43;	/* bulk command signature */
	ath9u_bulk_cmd[14] = 0x06;	/* command length */
	ath9u_bulk_cmd[15] = 0x1b;	/* SCSI command: START STOP UNIT */
	ath9u_bulk_cmd[19] = 0x02;	/* eject disc */

	/*
		usb_bulk_msg(udev, usb_sndbulkpipe(udev, bulk_out_ep),
			     cmd, 31, NULL, 2 * USB_MSG_TIMEOUT);
	*/
	libusb_bulk_transfer(ath9u_usb, out_endpoint, ath9u_bulk_cmd, sizeof(ath9u_bulk_cmd), 0, USB_MSG_TIMEOUT);
	free(ath9u_bulk_cmd);
}

/*
If firmware was loaded we should drop it
	 * go back to first stage bootloader.
*/

signed int ddv_reboot_device(struct libusb_device_handle *ath9u_device){
	if( out_endpoint == 0x00 ){
		return -NO_CORRECT_ENDPOINT;
	}
	#ifdef ATH9K_REBOOT_CMD
		#define ATH9U_REBOOT_CMD	ATH9K_REBOOT_CMD
	#else
    		#define ATH9U_REBOOT_CMD	0xffffffff
	#endif
	void *reboot_buf = malloc(sizeof(0xffffffff));
    	memcpy(reboot_buf, (void *)ATH9U_REBOOT_CMD, 4);
    	if( libusb_interrupt_transfer(ath9u_device, out_endpoint, reboot_buf, 4, NULL, USB_MSG_TIMEOUT) < 0 ){
        	exit(-LIBUSB_CONTROL_FAIL);
    	}
	free(reboot_buf);
}

long ath9u_get_device_capabilities(void){
	return( DEV_CAN_TX | DEV_CAN_RX | DEV_CAN_STA_MODE | DEV_CAN_AP_MODE | DEV_CAN_MONITOR_MODE |
            DEV_CAN_2GHZ | DEV_CAN_INJECT |  DEV_CAN_SUPPORT_WPA | DEV_CAN_SUPPORT_WPA2 | DEV_IS_80211N | DEV_IS_SPECTRAL_COMPATIBLE);

}

int main(int argc, char *argv[]){
        /* init the dialog API */
        //init_dialog(stdin, stdout);


	return 0;
}

#endif
