#ifndef CERTIGHOST_BEACON_H
#define CERTIGHOST_BEACON_H

#ifndef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT __declspec(dllimport)
#endif

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT void BeaconOutput(int type, const char *data, int len);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *fmt, ...);

#endif
