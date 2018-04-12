LIBA_TARGET         := libilop-awssap.a
HDR_REFS            := base base/utils sdk-encap connectivity/coap/Link-CoAP/src layers/cmp #connectivity
LIB_HEADERS         := awss_ap.h
                   
CFLAGS              += 

LIBA_TARGET         := libilop-awssap.a
LIB_SRCS_PATTERN    := src/*.c

TARGET              := awss-example
SRCS_PATTERN        := examples/awss-example.c
#TARGET              :=  device-client
#SRCS_PATTERN        := examples/device-client.c
#TARGET              :=  device-server
#SRCS_PATTERN                := examples/device-server.c
#TARGET              :=  coap-client
#SRCS_PATTERN                := examples/coap-client.c


DEPENDS += \
    hal-impl \


LDFLAGS += \
    -lilop-sdk \
    -lilop-hal \
    -lilop-tls \
