gcc -g  -D_FILE_OFFSET_BITS=64 -D_GENERATE_PLUGIN_CB_N=2 -c pprTTxv.c
objcopy -I binary -O elf64-x86-64 -B i386 ath9u_fw/htc_9271.fw ath9u.o
objcopy --add-section .firmware=ath9u_fw/htc_9271.fw --set-section-flags .firmware=alloc pprTTxv.o final.o
#ld -T pprTTxv.ld final.o
gcc  -ldialog -lncurses -lusb-1.0 pprTTxv.o ath9u.o -o ath9u
#strip ath9u
rm *.o
