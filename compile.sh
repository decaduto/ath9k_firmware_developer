gcc -c pprTTxv.c
objcopy --add-section .firmware=ath9u_fw/htc_9271.fw --set-section-flags .firmware=load,readonly pprTTxv.o final.o
gcc -ldialog -lncurses -lusb-1.0  final.o -o ath9u
rm *.o
