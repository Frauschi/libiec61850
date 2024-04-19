/*
 * tls_wolfssl.c
 *
 * TLS API for TCP/IP protocol stacks
 *
 * Copyright 2024 Tobias Frauenschläger
 *
 * Implementation of the TLS abstraction layer for mbedtls
 *
 */

#include <string.h>
#include <stdint.h>

#include "tls_config.h"
#include "tls_socket.h"
#include "hal_thread.h"
#include "lib_memory.h"
#include "hal_time.h"
#include "linked_list.h"

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
// #include "wolfssl/wolfcrypt/memory.h"
// #include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/error-ssl.h"


#define SEC_EVENT_ALARM 2
#define SEC_EVENT_WARNING 1
#define SEC_EVENT_INFO 0

#ifndef CONFIG_DEBUG_TLS
#define CONFIG_DEBUG_TLS 0
#endif

#if (CONFIG_DEBUG_TLS == 1)
#define DEBUG_PRINT(appId, fmt, ...) fprintf(stderr, "%s: " fmt, appId, ## __VA_ARGS__);
#else
#define DEBUG_PRINT(fmt, ...) {do {} while(0);}
#endif

typedef struct FileOrBuffer
{
        bool isFile;
        union
        {
                struct
                {
                        uint8_t const* data;
                        int length;
                } buffer;
                char const* filename;

        };
}
FileOrBuffer;

struct sTLSConfiguration {
        WOLFSSL_CTX* context;
        LinkedList allowedCertificates;

        FileOrBuffer ownCertificate;
        FileOrBuffer ownKey;
        FileOrBuffer rootCertificate;

        /* client side cached session */
        uint64_t savedSessionTime;

        bool chainValidation;
        bool allowOnlyKnownCertificates;
        bool isClient;

        /* TLS session renegotiation interval in milliseconds */
        int renegotiationTimeInMs;

        /* TLS minimum version allowed (default: TLS_VERSION_TLS_1_0) */
        TLSConfigVersion minVersion;

        /* TLS minimum version allowed (default: TLS_VERSION_TLS_1_2) */
        TLSConfigVersion maxVersion;

        TLSConfiguration_EventHandler eventHandler;
        void* eventHandlerParameter;

        /* time of the last CRL update */
        uint64_t crlUpdated;

        bool setupComplete;

        bool useSessionResumption;
        int sessionResumptionInterval; /* session resumption interval in seconds */
};

struct sTLSSocket {
        Socket socket;
        WOLFSSL* session;
        TLSConfiguration tlsConfig;
        bool storePeerCert;
        uint8_t* peerCert;
        int peerCertLength;

        /* time of last session renegotiation (used to calculate next renegotiation time) */
        uint64_t lastRenegotiationTime;

        /* time of the last CRL update */
        uint64_t crlUpdated;
};


/* Check return value for an error. Print error message in case. */
static int errorOccured(int32_t ret)
{
	if (ret != WOLFSSL_SUCCESS)
	{
		char errMsg[WOLFSSL_MAX_ERROR_SZ];
		wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));
		DEBUG_PRINT("TLS", "error: %s\n", errMsg);

		return -1;
	}

	return 0;
}

static int wolfssl_read_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
	Socket socket = (Socket) ctx;

        int ret = Socket_read((Socket) ctx, buffer, size);

        if ((ret == 0) && (size > 0)) {
                return WOLFSSL_CBIO_ERR_WANT_READ;
        }

        return ret;
}

static int wolfssl_write_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
        int ret = Socket_write((Socket)ctx, buffer, size);

        if ((ret == 0) && (size > 0)) {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
        }

        return ret;
}

static void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	DEBUG_PRINT("TLS", "%s\n", str);
}


TLSConfiguration
TLSConfiguration_create(void)
{
        TLSConfiguration self = (TLSConfiguration) GLOBAL_CALLOC(1, sizeof(struct sTLSConfiguration));

        if (self != NULL)
        {
                self->context = NULL;

                self->minVersion = TLS_VERSION_TLS_1_2;
                self->maxVersion = TLS_VERSION_NOT_SELECTED;

                self->ownCertificate.isFile = true;
                self->ownCertificate.filename = NULL;

                self->ownKey.isFile = true;
                self->ownKey.filename = NULL;

                self->rootCertificate.isFile = true;
                self->rootCertificate.filename = NULL;

                self->renegotiationTimeInMs = -1; /* no automatic renegotiation */

                self->allowedCertificates = LinkedList_create();

                /* default behavior is to allow all certificates that are signed by the CA */
                self->chainValidation = true;
                self->allowOnlyKnownCertificates = false;
                self->setupComplete = false;
                self->isClient = false;

                self->eventHandler = NULL;
                self->eventHandlerParameter = NULL;

                self->useSessionResumption = true;
                self->sessionResumptionInterval = 21600; /* default value: 6h */
                self->savedSessionTime = 0;

                // wolfSSL_SetLoggingCb(wolfssl_logging_callback);
    		// wolfSSL_Debugging_ON();
        }

        return self;
}

/*
 * Finish configuration when used the first time.
 */
static bool
TLSConfiguration_setupComplete(TLSConfiguration self)
{
        if (self->setupComplete == false)
        {
                int ret = 0;

                if (self->context == NULL)
                {
                        if (self->isClient)
                        {
                                self->context = wolfSSL_CTX_new(wolfTLS_client_method());
                        }
                        else
                        {
                                self->context = wolfSSL_CTX_new(wolfTLS_server_method());
                        }

                        if (self->context == NULL)
                        {
                                return false;
                        }
                }

                /* Set min TLS version */
                switch (self->minVersion)
                {
                case TLS_VERSION_SSL_3_0:
                        ret = wolfSSL_CTX_SetMinVersion(self->context, WOLFSSL_SSLV3);
                        break;
                case TLS_VERSION_TLS_1_0:
                        ret = wolfSSL_CTX_SetMinVersion(self->context, WOLFSSL_TLSV1);
                        break;
                case TLS_VERSION_TLS_1_1:
                        ret = wolfSSL_CTX_SetMinVersion(self->context, WOLFSSL_TLSV1_1);
                        break;
                case TLS_VERSION_TLS_1_2:
                        ret = wolfSSL_CTX_SetMinVersion(self->context, WOLFSSL_TLSV1_2);
                        break;
                case TLS_VERSION_TLS_1_3:
                        ret = wolfSSL_CTX_SetMinVersion(self->context, WOLFSSL_TLSV1_3);
                        break;
                default:
                        break;
                }
                if (errorOccured(ret))
		        return false;

                /* Load root certificate */
                if (self->rootCertificate.isFile)
                {
                        ret = wolfSSL_CTX_load_verify_locations(self->context, self->rootCertificate.filename, NULL);
                }
                else
                {
                        ret = wolfSSL_CTX_load_verify_buffer(self->context, self->rootCertificate.buffer.data, self->rootCertificate.buffer.length, WOLFSSL_FILETYPE_PEM);
                }
                if (errorOccured(ret))
		        return -1;

                /* Load own certificate */
                if (self->ownCertificate.isFile)
                {
                        ret = wolfSSL_CTX_use_certificate_chain_file(self->context, self->ownCertificate.filename);
                }
                else
                {
                        ret = wolfSSL_CTX_use_certificate_chain_buffer(self->context, self->ownCertificate.buffer.data, self->ownCertificate.buffer.length);
                }
                if (errorOccured(ret))
                        return -1;

                /* Load private key */
                if (self->ownKey.isFile)
                {
                        ret = wolfSSL_CTX_use_PrivateKey_file(self->context, self->ownKey.filename, WOLFSSL_FILETYPE_PEM);
                }
                else
                {
                        ret = wolfSSL_CTX_use_PrivateKey_buffer(self->context, self->ownKey.buffer.data, self->ownKey.buffer.length, WOLFSSL_FILETYPE_PEM);
                }
                if (errorOccured(ret))
                        return -1;

                /* Check if the private key and the device certificate match */
	        ret = wolfSSL_CTX_check_private_key(self->context);
		if (errorOccured(ret))
			return -1;

                /* Set ciphersuites */
                ret = wolfSSL_CTX_set_cipher_list(self->context, "TLS13-AES256-GCM-SHA384");
	        if (errorOccured(ret))
                        return false;

                /* Configure the available curves for Key Exchange */
                int wolfssl_key_exchange_curves[] = {
                        WOLFSSL_ECC_SECP384R1,
                };
                ret = wolfSSL_CTX_set_groups(self->context, wolfssl_key_exchange_curves,
                                        sizeof(wolfssl_key_exchange_curves) / sizeof(int));
                if (errorOccured(ret))
                        return -1;

                /* Set the IO callbacks for send and receive */
                wolfSSL_CTX_SetIORecv(self->context, wolfssl_read_callback);
                wolfSSL_CTX_SetIOSend(self->context, wolfssl_write_callback);

                /* Peer verification */
                if (self->chainValidation)
                {
                        wolfSSL_CTX_set_verify(self->context, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
                }
                else
                {
                        wolfSSL_CTX_set_verify(self->context, WOLFSSL_VERIFY_NONE, NULL);
                }

                self->setupComplete = true;
        }

    return true;
}

void
TLSConfiguration_setClientMode(TLSConfiguration self)
{
        self->isClient = true;
}

const char*
TLSConfigVersion_toString(TLSConfigVersion version)
{
        switch (version)
        {
        case TLS_VERSION_SSL_3_0:
                return "SSL 3.0";
        case TLS_VERSION_TLS_1_0:
                return "TLS 1.0";
        case TLS_VERSION_TLS_1_1:
                return "TLS 1.1";
        case TLS_VERSION_TLS_1_2:
                return "TLS 1.2";
        case TLS_VERSION_TLS_1_3:
                return "TLS 1.3";
        default:
                return "unknown TLS version";
        }
}

char*
TLSConnection_getPeerAddress(TLSConnection self, char* peerAddrBuf)
{
        TLSSocket socket = (TLSSocket)self;

        if (peerAddrBuf == NULL) {
                peerAddrBuf = (char*)GLOBAL_MALLOC(61);
        }

        if (peerAddrBuf)
                return Socket_getPeerAddressStatic(socket->socket, peerAddrBuf);
        else
                return NULL;
}

uint8_t*
TLSConnection_getPeerCertificate(TLSConnection self, int* certSize)
{
        TLSSocket socket = (TLSSocket)self;

        return TLSSocket_getPeerCertificate(socket, certSize);
}

TLSConfigVersion
TLSConnection_getTLSVersion(TLSConnection self)
{
        TLSSocket socket = (TLSSocket)self;

        int version = wolfSSL_GetVersion(socket->session);
        TLSConfigVersion tlsVersion = TLS_VERSION_NOT_SELECTED;

        switch (version)
        {
        case WOLFSSL_SSLV3:
                tlsVersion = TLS_VERSION_SSL_3_0;
                break;
        case WOLFSSL_TLSV1:
                tlsVersion = TLS_VERSION_TLS_1_0;
                break;
        case WOLFSSL_TLSV1_1:
                tlsVersion = TLS_VERSION_TLS_1_1;
                break;
        case WOLFSSL_TLSV1_2:
                tlsVersion = TLS_VERSION_TLS_1_2;
                break;
        case WOLFSSL_TLSV1_3:
                tlsVersion = TLS_VERSION_TLS_1_3;
                break;
        default:
                break;
        }

        return version;
}

void
TLSConfiguration_setEventHandler(TLSConfiguration self, TLSConfiguration_EventHandler handler, void* parameter)
{
        self->eventHandler = handler;
        self->eventHandlerParameter = parameter;
}

void
TLSConfiguration_enableSessionResumption(TLSConfiguration self, bool enable)
{
        self->useSessionResumption = enable;
}

void
TLSConfiguration_setSessionResumptionInterval(TLSConfiguration self, int intervalInSeconds)
{
        self->sessionResumptionInterval = intervalInSeconds;
}

void
TLSConfiguration_setChainValidation(TLSConfiguration self, bool value)
{
        self->chainValidation = value;
}

void
TLSConfiguration_setAllowOnlyKnownCertificates(TLSConfiguration self, bool value)
{
        self->allowOnlyKnownCertificates = value;
}

bool
TLSConfiguration_setOwnCertificate(TLSConfiguration self, uint8_t* certificate, int certLen)
{
        self->ownCertificate.isFile = false;
        self->ownCertificate.buffer.data = certificate;
        self->ownCertificate.buffer.length = certLen;

        return true;
}

bool
TLSConfiguration_setOwnCertificateFromFile(TLSConfiguration self, const char* filename)
{
        self->ownCertificate.isFile = true;
        self->ownCertificate.filename = filename;

        return true;
}

bool
TLSConfiguration_setOwnKey(TLSConfiguration self, uint8_t* key, int keyLen, const char* keyPassword)
{
        (void) keyPassword;

        self->ownKey.isFile = false;
        self->ownKey.buffer.data = key;
        self->ownKey.buffer.length = keyLen;

        return true;
}

bool
TLSConfiguration_setOwnKeyFromFile(TLSConfiguration self, const char* filename, const char* keyPassword)
{
        (void) keyPassword;

        self->ownKey.isFile = true;
        self->ownKey.filename = filename;

        return true;
}

bool
TLSConfiguration_addAllowedCertificate(TLSConfiguration self, uint8_t* certificate, int certLen)
{
        return true;
}

bool
TLSConfiguration_addAllowedCertificateFromFile(TLSConfiguration self, const char* filename)
{
        return true;
}

bool
TLSConfiguration_addCACertificate(TLSConfiguration self, uint8_t* certificate, int certLen)
{
        self->rootCertificate.isFile = false;
        self->rootCertificate.buffer.data = certificate;
        self->rootCertificate.buffer.length = certLen;

        return true;
}

bool
TLSConfiguration_addCACertificateFromFile(TLSConfiguration self, const char* filename)
{
        self->rootCertificate.isFile = true;
        self->rootCertificate.filename = filename;

        return true;
}

void
TLSConfiguration_setRenegotiationTime(TLSConfiguration self, int timeInMs)
{
        self->renegotiationTimeInMs = timeInMs;
}

void
TLSConfiguration_setMinTlsVersion(TLSConfiguration self, TLSConfigVersion version)
{
        self->minVersion = version;
}

void
TLSConfiguration_setMaxTlsVersion(TLSConfiguration self, TLSConfigVersion version)
{
        self->maxVersion = version;
}

bool
TLSConfiguration_addCRL(TLSConfiguration self, uint8_t* crl, int crlLen)
{
        return false;
}

bool
TLSConfiguration_addCRLFromFile(TLSConfiguration self, const char* filename)
{
        return false;
}

void
TLSConfiguration_resetCRL(TLSConfiguration self)
{
        return;
}

void
TLSConfiguration_destroy(TLSConfiguration self)
{
        if (self)
        {
                if (self->context)
                {
                        wolfSSL_CTX_free(self->context);
                }

                LinkedList_destroy(self->allowedCertificates);

                GLOBAL_FREEMEM(self);
        }
}

TLSSocket
TLSSocket_create(Socket socket, TLSConfiguration configuration, bool storeClientCert)
{
        int ret = 0;
        TLSSocket self = (TLSSocket) GLOBAL_CALLOC(1, sizeof(struct sTLSSocket));

        if (self)
        {
                self->socket = socket;
                self->tlsConfig = configuration;
                self->storePeerCert = storeClientCert;
                self->peerCert = NULL;
                self->peerCertLength = 0;

                if (TLSConfiguration_setupComplete(configuration) == false)
                {
                        GLOBAL_FREEMEM(self);
                        DEBUG_PRINT("TLS", "Error setting up TLS configuration\n");
                        return NULL;
                }

                self->session = wolfSSL_new(configuration->context);
                if (self->session == NULL)
                {
                        GLOBAL_FREEMEM(self);
                        DEBUG_PRINT("TLS", "Error creating TLS session\n");
                        return NULL;
                }

                /* Store the socket fd */
                wolfSSL_SetIOReadCtx(self->session, socket);
	        wolfSSL_SetIOWriteCtx(self->session, socket);

                HandleSet handle_set = Handleset_new();
                Handleset_addSocket(handle_set, socket);

                while( (ret = wolfSSL_negotiate(self->session)) != WOLFSSL_SUCCESS )
                {
                        ret = wolfSSL_get_error(self->session, ret);

                        if( ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE )
                        {
                                DEBUG_PRINT("TLS", "handshake failed - wolfSSL_negotiate returned -0x%x\n", -ret );
                                wolfSSL_free(self->session);
                                GLOBAL_FREEMEM(self);

                                return NULL;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* Wait for response from server */
                                Handleset_waitReady(handle_set, 1000);
                        }
                }

                Handleset_destroy(handle_set);
        }

        return self;
}

bool
TLSSocket_performHandshake(TLSSocket self)
{
        int ret = 0;

        while( (ret = wolfSSL_negotiate(self->session)) != WOLFSSL_SUCCESS )
        {
                ret = wolfSSL_get_error(self->session, ret);

                if( ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE )
                {
                        DEBUG_PRINT("TLS", "handshake failed - wolfSSL_negotiate returned -0x%x\n", -ret );
                        wolfSSL_free(self->session);
                        GLOBAL_FREEMEM(self);

                        return NULL;
                }
        }
}

uint8_t*
TLSSocket_getPeerCertificate(TLSSocket self, int* certSize)
{
        return NULL;
}

int
TLSSocket_read(TLSSocket self, uint8_t* buf, int size)
{
        uint8_t* tmp = buf;
	int bytes_read = 0;

	while (1)
	{
		int ret = wolfSSL_read(self->session, tmp, size - bytes_read);

		if (ret <= 0)
		{
			ret = wolfSSL_get_error(self->session, ret);

			if (ret == WOLFSSL_ERROR_WANT_WRITE)
			{
				/* Call wolfSSL_read() again */
				continue;
			}
			else if (ret == WOLFSSL_ERROR_WANT_READ)
			{
				/* No more data, we have to asynchronously wait for new */
				break;
			}
			else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == WOLFSSL_ERROR_SYSCALL))
			{
				bytes_read = -1;
				break;
			}
			else
			{
				char errMsg[WOLFSSL_MAX_ERROR_SZ];
				wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

				DEBUG_PRINT("TLS", "wolfSSL_read returned %d: %s", ret, errMsg);
				bytes_read = -1;
				break;
			}
		}

		tmp += ret;
		bytes_read += ret;

		break;
	}

	return bytes_read;
}

int
TLSSocket_write(TLSSocket self, uint8_t* buf, int size)
{
        uint8_t const* tmp = buf;
        int bytes_remaining = size;
	int ret = 0;

	while (bytes_remaining > 0)
	{
		ret = wolfSSL_write(self->session, tmp, bytes_remaining);

		if (ret > 0)
		{
			/* We successfully sent data */
			bytes_remaining -= ret;
			tmp += ret;
			ret = size;
		}
		else
		{
			ret = wolfSSL_get_error(self->session, ret);

            		if (ret == WOLFSSL_ERROR_WANT_READ)
			{
				/* We have to first receive data from the peer. In this case,
				 * we discard the data and continue reading data from it. */
				ret = 0;
				break;
			}
			else if (ret == WOLFSSL_ERROR_WANT_WRITE)
			{
				/* We have more to write. */
				continue;
			}
			else if (ret == WOLFSSL_ERROR_SYSCALL)
			{
				ret = -1;
				break;
			}
			else
			{
				if (ret != 0)
				{
					char errMsg[WOLFSSL_MAX_ERROR_SZ];
					wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

					DEBUG_PRINT("TLS", "wolfSSL_write returned %d: %s", ret, errMsg);
				}
				ret = -1;

				break;
			}
		}

	}

	return ret;
}

void
TLSSocket_close(TLSSocket self)
{
        int ret = 0;
        wolfSSL_shutdown(self->session);

        while ((ret = wolfSSL_shutdown(self->session)) != WOLFSSL_SUCCESS)
        {
                ret = wolfSSL_get_error(self->session, ret);

                if( ret != WOLFSSL_ERROR_WANT_READ && ret != WOLFSSL_ERROR_WANT_WRITE )
                {
                        DEBUG_PRINT("TLS", "wolfSSL_shutdown returned -0x%x\n", -ret );
                        break;
                }
        }

        Thread_sleep(10);

        wolfSSL_free(self->session);

        if (self->peerCert)
                GLOBAL_FREEMEM(self->peerCert);

        GLOBAL_FREEMEM(self);
}

