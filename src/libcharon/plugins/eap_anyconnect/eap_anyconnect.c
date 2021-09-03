/*
 * Copyright (C) 2020 Stafan Gula
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "eap_anyconnect.h"

#include <daemon.h>
#include <library.h>
#include <crypto/hashers/hasher.h>
#include <inttypes.h>
#include <collections/array.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <asn1/asn1_parser.h>
#include <sa/ikev2/keymat_v2.h>
#include <sa/ikev2/authenticators/pubkey_authenticator.h>
#include <encoding/payloads/auth_payload.h>
#include <libxml/xmlwriter.h>
#include <ctype.h>

enum eap_anyconnect_types_t {
	EAP_ANY_XML = 0,
	EAP_ANY_SIGN = 1,
	EAP_ANY_PKCS7 = 3,
};

enum eap_anyconnect_xml_types_t {
	EAP_ANY_XML_NONE = 0,
	EAP_ANY_XML_HELLO,
	EAP_ANY_XML_INIT,
	EAP_ANY_XML_AUTH_REQUEST,
	EAP_ANY_XML_AUTH_REPLY,
	EAP_ANY_XML_AUTH_COMPLETE,
	EAP_ANY_XML_ACK,
};

enum_name_t *eap_anyconnect_xml_types_keywords;
ENUM(eap_anyconnect_xml_types_keywords, EAP_ANY_XML_NONE, EAP_ANY_XML_ACK,
	"",
	"hello",
	"init",
	"auth-request",
	"auth-reply",
	"complete",
	"ack"
);

enum xml_element_type_t {
	XML_ELEM_STRING,
	XML_ELEM_CHUNK_C,
	XML_ELEM_CHUNK_M,
	XML_ELEM_ATTR,
	XML_ELEM_END,
	XML_ELEM_NOEND,
};

enum eap_anyconnect_union_type_t {
	EAP_ANY_UNION_TYPE_VALUE,
	EAP_ANY_UNION_TYPE_SETTINGS,
	EAP_ANY_UNION_TYPE_ARRAY,
};

enum eap_anyconnect_device_id_settings_t {
	EAP_ANY_SET_COMPUTER_NAME = 0,
	EAP_ANY_SET_DEVICE_TYPE,
	EAP_ANY_SET_PLATFORM_VERSION,
	EAP_ANY_SET_UNIQUE_ID,
	EAP_ANY_SET_UNIQUE_ID_GLOBAL,
	EAP_ANY_SET_DEVICE_ID_VALUE,
};

enum eap_anyconnect_opaque_settings_t {
	EAP_ANY_SET_TUNNEL_GROUP = 0,
	EAP_ANY_SET_CONFIG_HASH,
};

enum eap_anyconnect_host_scan_settings_t {
	EAP_ANY_SET_BASE_URI = 0,
	EAP_ANY_SET_WAIT_URI,
	EAP_ANY_SET_TOKEN_XML_FILE,
};

enum eap_anyconnect_vpn_profile_manifest_settings_t {
	EAP_ANY_SET_PROFILE_SERVICE_TYPE = 0,
	EAP_ANY_SET_URI,
	EAP_ANY_SET_HASHTYPE,
	EAP_ANY_SET_HASH,
};

enum eap_anyconnect_service_profile_settings_t {
	EAP_ANY_SET_SERVICE_TYPE = 0,
	EAP_ANY_SET_SERVICE_FILE,
	EAP_ANY_SET_EXTENSION,
	EAP_ANY_SET_DERIVED_EXTENSION,
	EAP_ANY_SET_DIRECTORY,
	EAP_ANY_SET_DEPLOY_DIRECTORY,
	EAP_ANY_SET_DESCRIPTION,
	EAP_ANY_SET_REMOVE_EMPTY,
};

enum eap_anyconnect_vpn_core_manifest_settings_t {
	EAP_ANY_SET_VPN_VERSION = 0,
	EAP_ANY_SET_IS_CORE,
	EAP_ANY_SET_TYPE,
	EAP_ANY_SET_ACTION,
	EAP_ANY_SET_OS,
	EAP_ANY_SET_VPN_URI,
	EAP_ANY_SET_DISPLAY_NAME,
};

enum eap_anyconnect_client_settings_t {
	EAP_ANY_SET_VERSION = 0,
	EAP_ANY_SET_DEVICE_ID,
	EAP_ANY_SET_MAC_ADDRESS,
	EAP_ANY_SET_GROUP_ACCESS,
	EAP_ANY_SET_OPAQUE_CLIENT,
	EAP_ANY_SET_CSD_WRAPPER,
	EAP_ANY_SET_AUTH_METHOD,
};

enum eap_anyconnect_server_settings_t {
	EAP_ANY_SET_HOST_SCAN = 0,
	EAP_ANY_SET_VPN_PROFILE_MANIFEST,
	EAP_ANY_SET_SERVICE_PROFILE,
	EAP_ANY_SET_PKGVERSION,
	EAP_ANY_SET_VPN_CORE_MANIFEST,
	EAP_ANY_SET_DYN_EXC_DOMAINS,
	EAP_ANY_SET_OPAQUE_SERVER,
	EAP_ANY_SET_CSPORT,
	EAP_ANY_SET_CRYPTO_SUPPORTED,
	EAP_ANY_SET_BASE_PACKAGE_URI,
};

typedef enum eap_anyconnect_types_t eap_anyconnect_types_t;
typedef enum eap_anyconnect_xml_types_t eap_anyconnect_xml_types_t;
typedef enum eap_anyconnect_union_type_t eap_anyconnect_union_type_t;
typedef enum xml_element_type_t xml_element_type_t;
typedef struct eap_anyconnect_tlv_t eap_anyconnect_tlv_t;
typedef struct eap_anyconnect_data_t eap_anyconnect_data_t;
typedef struct private_eap_anyconnect_t private_eap_anyconnect_t;
typedef struct eap_anyconnect_header_t eap_anyconnect_header_t;
typedef struct eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_setting_rule_t;
typedef struct eap_anyconnect_setting_t eap_anyconnect_setting_t;
typedef union eap_anyconnect_setting_u_t eap_anyconnect_setting_u_t;

struct eap_anyconnect_tlv_t {
	uint16_t type;
	uint16_t length;
};

struct eap_anyconnect_data_t {
	eap_anyconnect_types_t type;
	chunk_t data;
	bool own_data;
};

struct eap_anyconnect_header_t {
	uint8_t code;
	uint8_t id;
	uint16_t length;
	uint8_t type;
	uint8_t vendor[3];
	uint32_t vendor_type;
};

struct eap_anyconnect_setting_t;

union eap_anyconnect_setting_u_t {
	char *val;
	eap_anyconnect_setting_t *set;
	eap_anyconnect_setting_t **arr;
};

struct eap_anyconnect_setting_t {
	eap_anyconnect_union_type_t type;
	size_t set_count;
	size_t arr_count;
	eap_anyconnect_setting_u_t u;
};

struct eap_anyconnect_xml_setting_rule_t {
	char *key;
	char *default_value;
	bool mandatory;
	eap_anyconnect_xml_setting_rule_t* embedded_rules;
	size_t rules_count;
	bool is_array;
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_device_id_rules[] = {
	{"computer-name",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"device-type",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"platform-version",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"unique-id",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"unique-id-global",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"value",		NULL,	TRUE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_opaque_rules[] = {
	{"tunnel-group",	NULL,	FALSE,	NULL,	0,	FALSE},
	{"config-hash",		NULL,	FALSE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_vpn_profile_file_rules[] = {
	{"service-type",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"uri",			NULL,	TRUE,	NULL,	0,	FALSE},
	{"hash-type",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"hash",		NULL,	TRUE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_service_profile_rules[] = {
	{"service-type",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"file",			NULL,	FALSE,	NULL,	0,	FALSE},
	{"extension",			NULL,	TRUE,	NULL,	0,	FALSE},
	{"derived-extension",		NULL,	FALSE,	NULL,	0,	FALSE},
	{"directory",			NULL,	FALSE,	NULL,	0,	FALSE},
	{"deploy-directory",		NULL,	FALSE,	NULL,	0,	FALSE},
	{"description",			NULL,	TRUE,	NULL,	0,	FALSE},
	{"download-remove-empty",	NULL,	TRUE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_vpn_core_manifest_rules[] = {
	{"version",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"is-core",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"type",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"action",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"os",			NULL,	TRUE,	NULL,	0,	FALSE},
	{"uri",			NULL,	TRUE,	NULL,	0,	FALSE},
	{"display-name",	NULL,	TRUE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_host_scan_rules[] = {
	{"base-uri",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"wait-uri",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"token-xml-file",	NULL,	TRUE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_client_setting_rules[] = {
	{"version",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"device-id",		NULL,	TRUE,
		eap_anyconnect_xml_device_id_rules, countof(eap_anyconnect_xml_device_id_rules), FALSE},
	{"mac-address",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"group-access",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"opaque",		NULL,	FALSE,
		eap_anyconnect_xml_opaque_rules, countof(eap_anyconnect_xml_opaque_rules), FALSE},
	{"csd-wrapper",		NULL,	TRUE,	NULL,	0,	FALSE},
	{"auth-method",		NULL,	FALSE,	NULL,	0,	FALSE},
};

eap_anyconnect_xml_setting_rule_t eap_anyconnect_xml_server_setting_rules[] = {
	{"host-scan",				NULL,	TRUE,
		eap_anyconnect_xml_host_scan_rules, countof(eap_anyconnect_xml_host_scan_rules), FALSE},
	{"vpn-profile-manifest",		NULL,	TRUE,
		eap_anyconnect_xml_vpn_profile_file_rules, countof(eap_anyconnect_xml_vpn_profile_file_rules), TRUE},
	{"service-profiles",			NULL,	TRUE,
		eap_anyconnect_xml_service_profile_rules, countof(eap_anyconnect_xml_service_profile_rules), TRUE},
	{"pkgversion",				NULL,	TRUE,	NULL,	0,	FALSE},
	{"vpn-core-manifest",			NULL,	TRUE,
		eap_anyconnect_xml_vpn_core_manifest_rules, countof(eap_anyconnect_xml_vpn_core_manifest_rules), TRUE},
	{"dynamic-split-exclude-domains",	NULL,	TRUE,	NULL,	0,	FALSE},
	{"opaque",				NULL,	FALSE,
		eap_anyconnect_xml_opaque_rules, countof(eap_anyconnect_xml_opaque_rules), FALSE},
	{"csport",				NULL,	TRUE,	NULL,	0,	FALSE},
	{"crypto-supported",			NULL,	FALSE,	NULL,	0,	FALSE},
	{"base-package-uri",			NULL,	TRUE,	NULL,	0,	FALSE},
};

#define EAP_VENDOR_HEADER_LEN 12
#define EAP_VENDOR_ENTRY_LEN 4
#define EAP_ANY_XML_VERSION "1.0"
#define EAP_ANY_XML_ENCODING "UTF-8"
#define EAP_ANY_XML_REVISION "1.0"
#define EAP_ANY_OCTET_ID "{201}:*$AnyConnectClient$*"
#define EAP_ANY_HOST_SCAN_LEN 12

/**
 * Private data of an eap_anyconnect_t object.
 */
struct private_eap_anyconnect_t {

	/**
	 * Public authenticator_t interface.
	 */
	eap_anyconnect_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * challenge sent by the server
	 */
	chunk_t challenge;

	/**
	 * EAP message identifier
	 */
	uint8_t identifier;

	/**
	 * EAP anyconnect header
	 */
	eap_anyconnect_header_t header;

	/**
	 * array of TLVs
	 */
	array_t *tlvs;

	/**
	 * The nonce for authentication
	 */
	chunk_t nonce;

	/**
	 * The IKE_SA_INIT message for authentication
	 */
	chunk_t ike_sa_init;

	/**
	 * The reserved bytes for authentication
	 */
	char reserved[3];

	/**
	 * Whether the reserved bytes were set or not
	 */
	bool set_reserved_called;

	/**
	 * The XML document
	 */
	xmlDocPtr xml;

	/**
	 * The host scan ticket
	 */
	chunk_t host_scan_ticket;

	/**
	 * The host scan token
	 */
	chunk_t host_scan_token;

	/**
	 * The opaque data from secure gateway
	 */
	chunk_t opaque_sg;

	/**
	 * The settings
	 */
	eap_anyconnect_setting_t *settings;

	/**
	 * The size of settings
	 */
	size_t settings_size;

	/**
	 * Whether we received client certificate or not
	 */
	bool client_cert_received;

	/**
	 * The session ID
	 */
	chunk_t session_id;

	/**
	 * The session token
	 */
	chunk_t session_token;

	/**
	 * Expected message type
	 */
	eap_anyconnect_xml_types_t expected_msg_type;

	/**
	 * The weak random data generator
	 */
	rng_t *rng;
};

static eap_anyconnect_xml_types_t get_type_by_string(const char *str)
{
	int val = 0;
	if (str && enum_from_name_as_int(eap_anyconnect_xml_types_keywords, str, &val))
	{
		return (eap_anyconnect_xml_types_t)val;
	}

	return EAP_ANY_XML_NONE;
}

static void destroy_tlv(void *data, int idx, void *user)
{
	eap_anyconnect_data_t *data2 = data;
	if(data2)
	{
		if (data2->own_data)
		{
			free(data2->data.ptr);
		}
		free(data2);
	}
}

static void destroy_xml(private_eap_anyconnect_t *this)
{
	if (this->xml)
	{
		xmlFreeDoc(this->xml);
	}

	this->xml = NULL;
}

static void clear_array(array_t* array)
{
	if (array)
	{
		array_destroy_function(array, &destroy_tlv, NULL);
	}
}

static eap_anyconnect_data_t *get_tlv(array_t *tlvs, eap_anyconnect_types_t type)
{
	eap_anyconnect_data_t *tlv, *ret = NULL;
	enumerator_t *enumerator = array_create_enumerator(tlvs);
	while (enumerator->enumerate(enumerator, &tlv))
	{
		if (tlv->type == type)
		{
			ret = tlv;
			break;
		}
	}
	enumerator->destroy(enumerator);
	return ret;
}

/**
 * ASN.1 definition of the PKCS#7
 */
static const asn1Object_t pkcs7Objects[] = {
	{ 0, "sequence0",		ASN1_SEQUENCE,		ASN1_OBJ  }, /* 0 */
	{ 1,  "pkcs7signedData",	ASN1_OID,		ASN1_OBJ  }, /* 1 */
	{ 1,  "context0",		ASN1_CONTEXT_C_0,	ASN1_LOOP }, /* 2 */
	{ 2,   "sequence1",		ASN1_SEQUENCE,		ASN1_OBJ  }, /* 3 */
	{ 3,    "version",		ASN1_INTEGER,		ASN1_BODY }, /* 4 */
	{ 3,    "set0",			ASN1_SET,		ASN1_LOOP }, /* 5 */
	{ 3,    "end set0",		ASN1_EOC,		ASN1_END  }, /* 6 */
	{ 3,    "sequence2",		ASN1_SEQUENCE,		ASN1_OBJ  }, /* 7 */
	{ 4,     "pkcs7data",		ASN1_OID,		ASN1_OBJ  }, /* 8 */
	{ 4,     "context1",		ASN1_CONTEXT_C_0,	ASN1_LOOP }, /* 9 */
	{ 5,      "string0",		ASN1_OCTET_STRING,	ASN1_BODY }, /* 10 */
	{ 4,     "end context1",	ASN1_EOC,		ASN1_END  }, /* 11 */
	{ 3,    "certs",		ASN1_CONTEXT_C_0,	ASN1_LOOP }, /* 12 */
	{ 4,     "cert",		ASN1_SEQUENCE,		ASN1_OBJ  }, /* 13 */
	{ 3,    "end certs",		ASN1_EOC,		ASN1_END  }, /* 14 */
	{ 3,    "set1",			ASN1_SET,		ASN1_LOOP }, /* 15 */
	{ 3,    "end set1",		ASN1_EOC,		ASN1_END  }, /* 16 */
	{ 1,  "end context0",		ASN1_EOC,		ASN1_END  }, /* 17 */
	{ 0, "exit",			ASN1_EOC,		ASN1_EXIT }
};
#define EAP_ANY_PKCS7_VERSION	4
#define EAP_ANY_PKCS7_CERT	13

static bool parse_certificate(private_eap_anyconnect_t *this, chunk_t blob)
{
	asn1_parser_t *parser;
	chunk_t object;
	int objectID;
	bool first = TRUE;
	bool success = FALSE;

	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA");
		return FALSE;
	}

	auth_cfg_t *auth = ike_sa->get_auth_cfg(ike_sa, FALSE);
	if (!auth)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get AUTH CFG");
		return FALSE;
	}

	parser = asn1_parser_create(pkcs7Objects, blob);
	parser->set_top_level(parser, 0);

	while (parser->iterate(parser, &objectID, &object))
	{
		switch (objectID)
		{
			case EAP_ANY_PKCS7_VERSION:
			{
				int version = object.len ? (int)*object.ptr : 0;
				if(version != 1)
				{
					DBG1(DBG_IKE, "eap_anyconnect received incorrect version of PKCS7: %d", version);
					return FALSE;
				}
				break;
			}
			case EAP_ANY_PKCS7_CERT:
			{
				certificate_t *cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_BLOB_ASN1_DER, object, BUILD_END);
				if (first)
				{	/* the first is an end entity certificate */
					identification_t *identity = cert->get_subject(cert);
					DBG2(DBG_IKE, "eap_anyconnect received end entity cert \"%Y\"", identity);
					identity = identity->clone(identity);
					ike_sa->set_other_id(ike_sa, identity);
					auth->add(auth, AUTH_HELPER_SUBJECT_CERT, cert);
					first = FALSE;
				}
				else if(cert->issued_by(cert, cert, NULL))
				{
					DBG2(DBG_IKE, "eap_anyconnect received CA cert \"%Y\"",
						 cert->get_subject(cert));
				}
				else
				{
					DBG2(DBG_IKE, "eap_anyconnect received IM cert \"%Y\"",
						 cert->get_subject(cert));
					auth->add(auth, AUTH_HELPER_IM_CERT, cert);
				}
				break;
			}
			default:
				break;
		}
	}

	success = parser->success(parser);
	parser->destroy(parser);

	return success;
}

static status_t parse_payload(private_eap_anyconnect_t *this, eap_payload_t *payload, uint8_t *id)
{
	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	chunk_t remaining_data = payload->get_data(payload);
	if (remaining_data.len < EAP_VENDOR_HEADER_LEN)
	{
		DBG1(DBG_IKE, "eap_anyconnect received EAP anyconnect tlvs with invalid header");
		return FAILED;
	}

	eap_anyconnect_header_t header = *(eap_anyconnect_header_t*)remaining_data.ptr;
	header.length = untoh16(&header.length);
	*id = header.id;
	remaining_data = chunk_create(remaining_data.ptr + EAP_VENDOR_HEADER_LEN,
		remaining_data.len - EAP_VENDOR_HEADER_LEN);

	while (remaining_data.len > EAP_VENDOR_ENTRY_LEN)
	{
		eap_anyconnect_tlv_t tlv_header = *(eap_anyconnect_tlv_t*)remaining_data.ptr;
		tlv_header.length = untoh16(&tlv_header.length);
		tlv_header.type = untoh16(&tlv_header.type);
		if (tlv_header.length + EAP_VENDOR_ENTRY_LEN > remaining_data.len)
		{
			break;
		}

		chunk_t data = chunk_create(remaining_data.ptr + EAP_VENDOR_ENTRY_LEN, tlv_header.length);
		switch (tlv_header.type)
		{
			case EAP_ANY_XML:
				xmlInitParser();
				destroy_xml(this);
				this->xml = xmlReadMemory(data.ptr, data.len, "noname.xml", NULL, 0);
				xmlCleanupParser();
				break;
			case EAP_ANY_SIGN:
				break;
			case EAP_ANY_PKCS7:
				if (!parse_certificate(this, data))
				{
					DBG1(DBG_IKE, "eap_anyconnect ASN.1 parsing of PKCS7 certificate failed");
					return FAILED;
				}
				break;
			default:
				DBG1(DBG_IKE, "eap_anyconnect received unknown EAP anyconnect tlv type %"PRIu16, tlv_header.type);
				break;
		}

		eap_anyconnect_data_t *tlv;
		INIT(tlv, .type = tlv_header.type, .data = data, .own_data = FALSE);
		array_insert(this->tlvs, ARRAY_TAIL, tlv);
		remaining_data = chunk_create(remaining_data.ptr + EAP_VENDOR_ENTRY_LEN + tlv_header.length,
				remaining_data.len - EAP_VENDOR_ENTRY_LEN - tlv_header.length);
	}

	array_compress(this->tlvs);
	if (remaining_data.len > 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect received EAP anyconnect tlvs with invalid length, remaining length after parsing %"PRIu16, remaining_data.len);
		return FAILED;
	}

	return SUCCESS;
}

static eap_payload_t *encode_payload(private_eap_anyconnect_t *this)
{
	chunk_t encoded_data = chunk_empty;
	eap_anyconnect_data_t* current;

	enumerator_t* enumerator = array_create_enumerator(this->tlvs);
	while (enumerator->enumerate(enumerator, &current))
	{
		eap_anyconnect_tlv_t tlv;
		tlv.length = current->data.len;
		tlv.length = untoh16(&tlv.length);
		tlv.type = current->type;
		tlv.type = untoh16(&tlv.type);
		chunk_t tlv_header = chunk_create((u_char*)&tlv, EAP_VENDOR_ENTRY_LEN);
		encoded_data = chunk_cat("mcc", encoded_data, tlv_header, current->data);
	}
	enumerator->destroy(enumerator);

	eap_anyconnect_header_t header = this->header;
	header.length = encoded_data.len + EAP_VENDOR_HEADER_LEN;
	header.length = untoh16(&header.length);
	encoded_data = chunk_cat("cm", chunk_create((u_char*)&header, EAP_VENDOR_HEADER_LEN), encoded_data);
	eap_payload_t *ret = eap_payload_create_data(encoded_data);
	chunk_free(&encoded_data);
	return ret;
}

static bool verify_signature(private_eap_anyconnect_t *this)
{
	pubkey_authenticator_t *pubkey_authenticator = NULL;
	authenticator_t *authenticator = NULL;
	bool ret = TRUE;
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa && (this->nonce.len > 0) && (this->ike_sa_init.len > 0) && this->set_reserved_called)
	{
		pubkey_authenticator = pubkey_authenticator_create_verifier(ike_sa,
								this->nonce, this->ike_sa_init, this->reserved);
	}

	if (!pubkey_authenticator)
	{
		DBG1(DBG_IKE, "eap_anyconnect the pubkey authenticator was not yet created for EAP anyconnect tlv");
		return FALSE;
	}

	authenticator = &pubkey_authenticator->authenticator;
	message_t *msg = message_create(IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION);
	if (!msg)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create temporary message for RSA signature for EAP anyconnect tlv");
		DESTROY_IF(authenticator);
		return FALSE;
	}

	msg->set_exchange_type(msg, IKE_AUTH);
	auth_payload_t *auth_payload = auth_payload_create();
	if (!auth_payload)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create temporary auth payload for RSA signature for EAP anyconnect tlv");
		DESTROY_IF(authenticator);
		return FALSE;
	}

	eap_anyconnect_data_t *sign_tlv = get_tlv(this->tlvs, EAP_ANY_SIGN);
	auth_payload->set_auth_method(auth_payload, AUTH_RSA);
	auth_payload->set_data(auth_payload, sign_tlv->data);
	msg->add_payload(msg, (payload_t*)auth_payload);
	ike_sa->set_other_octet_id(ike_sa, identification_create_from_string(EAP_ANY_OCTET_ID));
	if (authenticator->process(authenticator, msg) != SUCCESS)
	{
		DBG1(DBG_IKE, "eap_anyconnect RSA signature verification failed for EAP anyconnect tlv");
		ret = FALSE;
	}

	DESTROY_IF(authenticator);
	msg->destroy(msg);
	return ret;
}

static bool add_signature(private_eap_anyconnect_t *this)
{
	pubkey_authenticator_t *pubkey_authenticator = NULL;
	authenticator_t *authenticator = NULL;
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (ike_sa && (this->nonce.len > 0) && (this->ike_sa_init.len > 0) && this->set_reserved_called)
	{
		pubkey_authenticator = pubkey_authenticator_create_builder(ike_sa,
								this->nonce, this->ike_sa_init, this->reserved);
	}

	if (!pubkey_authenticator)
	{
		DBG1(DBG_IKE, "eap_anyconnect the pubkey authenticator was not yet created for EAP anyconnect tlv");
		return FALSE;
	}

	authenticator = &pubkey_authenticator->authenticator;
	message_t *msg = message_create(IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION);
	if (!msg)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create temporary message for RSA signature for EAP anyconnect tlv");
		DESTROY_IF(authenticator);
		return FALSE;
	}

	msg->set_exchange_type(msg, IKE_AUTH);
	if (authenticator->build(authenticator, msg) != SUCCESS)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create RSA signature for EAP anyconnect tlv");
		DESTROY_IF(authenticator);
		msg->destroy(msg);
		return FALSE;
	}
	DESTROY_IF(authenticator);

	auth_payload_t *payload = (auth_payload_t *)msg->get_payload(msg, PLV2_AUTH);
	if (!payload)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get AUTH payload to extract signature for EAP anyconnect tlv");
		msg->destroy(msg);
		return FALSE;
	}

	eap_anyconnect_data_t *tlv;
	INIT(tlv, .type = EAP_ANY_SIGN, .data = chunk_clone(payload->get_data(payload)), .own_data = TRUE);
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	msg->destroy(msg);
	return TRUE;
}

static void destroy_settings(eap_anyconnect_setting_t *settings, size_t count)
{
	if (settings)
	{
		for (size_t i = 0; i < count; i++)
		{
			if (settings[i].type == EAP_ANY_UNION_TYPE_ARRAY)
			{
				for (size_t i2 = 0; i2 < settings[i].arr_count; i2++)
				{
					destroy_settings(settings[i].u.arr[i2], settings[i].u.arr[i2]->set_count);
				}
				free(settings[i].u.arr);
			}
			else if (settings[i].type == EAP_ANY_UNION_TYPE_SETTINGS)
			{
				destroy_settings(settings[i].u.set, settings[i].set_count);
			}
		}
		free(settings);
	}
}

static bool load_settings(const char *suffix, eap_anyconnect_setting_t **settings_out, eap_anyconnect_xml_setting_rule_t *rules, size_t rules_count)
{
	char buffer[BUF_LEN];
	bool ret = TRUE;
	if (!settings_out)
	{
		DBG1(DBG_IKE, "eap_anyconnect provided input data are wrong");
		return FALSE;
	}

	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA");
		return FALSE;
	}

	const char* conn_name = ike_sa->get_name(ike_sa);
	if (!conn_name)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA name");
		return FALSE;
	}

	eap_anyconnect_setting_t *settings = malloc(sizeof(eap_anyconnect_setting_t) * rules_count);
	if (!settings)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to allocate memory for settings");
		return FALSE;
	}

	for (size_t i = 0; i < rules_count; i++)
	{
		if (suffix)
		{
			snprintf(buffer, BUF_LEN, "%s.plugins.eap-anyconnect.%s%s.%s", lib->ns, conn_name, suffix, rules[i].key);
		}
		else
		{
			snprintf(buffer, BUF_LEN, "%s.plugins.eap-anyconnect.%s.%s", lib->ns, conn_name, rules[i].key);
		}

		char suffix2[BUF_LEN];
		if (rules[i].is_array)
		{
			char *key = NULL;
			size_t arr_size = 0;
			enumerator_t *enumerator = lib->settings->create_section_enumerator(lib->settings, buffer);
			while (enumerator->enumerate(enumerator, &key))
			{
				arr_size++;
			}

			enumerator->destroy(enumerator);
			eap_anyconnect_setting_t **arr = malloc(sizeof(eap_anyconnect_setting_t *) * arr_size);
			if (!arr)
			{
				DBG1(DBG_IKE, "eap_anyconnect unable to allocate memory for settings");
				destroy_settings(settings, rules_count);
				return FALSE;
			}

			enumerator = lib->settings->create_section_enumerator(lib->settings, buffer);
			size_t i2 = 0;
			while (ret && enumerator->enumerate(enumerator, &key))
			{
				if (rules[i].embedded_rules)
				{
					if (suffix)
					{
						snprintf(suffix2, BUF_LEN, "%s.%s.%s", suffix, rules[i].key, key);
					}
					else
					{
						snprintf(suffix2, BUF_LEN, ".%s.%s", rules[i].key, key);
					}
					ret = load_settings(suffix2, &(arr[i2++]), rules[i].embedded_rules, rules[i].rules_count);
				}
				else
				{
					arr[i2]->type = EAP_ANY_UNION_TYPE_VALUE;
					arr[i2]->set_count = 0;
					arr[i2]->arr_count = 0;
					arr[i2]->u.val = key;
					i2++;
				}
			}

			enumerator->destroy(enumerator);
			if(!ret)
			{
				free(arr);
				destroy_settings(settings, rules_count);
				return FALSE;
			}

			settings[i].type = EAP_ANY_UNION_TYPE_ARRAY;
			settings[i].set_count = rules[i].rules_count;
			settings[i].arr_count = arr_size;
			settings[i].u.arr = arr;
		}
		else if (rules[i].embedded_rules)
		{
			if (suffix)
			{
				snprintf(suffix2, BUF_LEN, "%s.%s", suffix, rules[i].key);
			}
			else
			{
				snprintf(suffix2, BUF_LEN, ".%s", rules[i].key);
			}

			eap_anyconnect_setting_t *settings2 = NULL;
			ret = load_settings(suffix2, &settings2, rules[i].embedded_rules, rules[i].rules_count);
			if(!ret)
			{
				destroy_settings(settings, rules_count);
				return FALSE;
			}

			settings[i].type = EAP_ANY_UNION_TYPE_SETTINGS;
			settings[i].set_count = rules[i].rules_count;
			settings[i].arr_count = 0;
			settings[i].u.set = settings2;
		}
		else
		{
			settings[i].type = EAP_ANY_UNION_TYPE_VALUE;
			settings[i].set_count = 0;
			settings[i].arr_count = 0;
			settings[i].u.val = lib->settings->get_str(lib->settings, buffer, rules[i].default_value);
		}

		if (rules[i].mandatory &&
			((settings[i].type == EAP_ANY_UNION_TYPE_VALUE && settings[i].u.val == NULL) ||
			(settings[i].type == EAP_ANY_UNION_TYPE_ARRAY && settings[i].arr_count == 0) ||
			(settings[i].type == EAP_ANY_UNION_TYPE_SETTINGS && settings[i].set_count == 0)))
		{
			DBG1(DBG_IKE, "eap_anyconnect missing mandatory configuration settings %s", buffer);
			destroy_settings(settings, rules_count);
			return FALSE;
		}
	}

	*settings_out = settings;
	return TRUE;
}

bool xml_element_va(xmlTextWriterPtr writer, const char *name, va_list attrs)
{
	chunk_t ch_value = chunk_empty;
	bool readnext = TRUE;
	bool generate_end = TRUE;
	xml_element_type_t type;
	if (name)
	{
		if (xmlTextWriterStartElement(writer, BAD_CAST name))
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to start XML element%s", name);
			return FALSE;
		}
	}

	while (readnext)
	{
		type = va_arg(attrs, xml_element_type_t);
		switch (type)
		{
			case XML_ELEM_STRING:
			{
				char *val = va_arg(attrs, char *);
				if (!strlen(val))
				{
					DBG2(DBG_IKE, "eap_anyconnect skipping adding of empty string to XML element %s", name);
					break;
				}

				ch_value = chunk_cat("mc", ch_value, chunk_from_str(val));
				break;
			}
			case XML_ELEM_CHUNK_C:
			{
				chunk_t val = va_arg(attrs, chunk_t);
				if (!val.len)
				{
					DBG2(DBG_IKE, "eap_anyconnect skipping adding of empty raw data to XML element %s", name);
					break;
				}

				ch_value = chunk_cat("mc", ch_value, val);
				break;
			}
			case XML_ELEM_CHUNK_M:
			{
				chunk_t val = va_arg(attrs, chunk_t);
				if (!val.len)
				{
					DBG2(DBG_IKE, "eap_anyconnect skipping adding of empty raw data to XML element %s", name);
					break;
				}

				ch_value = chunk_cat("mm", ch_value, val);
				break;
			}
			case XML_ELEM_ATTR:
			{
				const char *attr_name = va_arg(attrs, const char *);
				const char *attr_value = va_arg(attrs, const char *);
				if (xmlTextWriterWriteAttribute(writer, BAD_CAST attr_name, BAD_CAST attr_value) < 0)
				{
					DBG1(DBG_IKE, "eap_anyconnect unable to add attribute %s with value %s to XML element%s", attr_name, attr_value, name);
					chunk_free(&ch_value);
					return FALSE;
				}
				break;
			}
			case XML_ELEM_NOEND:
				generate_end = FALSE;
			case XML_ELEM_END:
				readnext = FALSE;
				break;
		}
	}

	if (ch_value.ptr && ch_value.len)
	{
		if (xmlTextWriterWriteRawLen(writer, BAD_CAST ch_value.ptr, ch_value.len) < 0)
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to add value to XML element %s, data %B", name, &ch_value);
			chunk_free(&ch_value);
			return FALSE;
		}
	}

	chunk_free(&ch_value);
	if (generate_end && xmlTextWriterEndElement(writer) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to end XML element %s", name);
		return FALSE;
	}

	return TRUE;
}

static bool xml_stop(xmlTextWriterPtr writer, xmlBufferPtr buf, bool end_doc, chunk_t *output)
{
	bool ret = TRUE;
	if (end_doc)
	{
		ret = ret && xmlTextWriterEndDocument(writer) >= 0;
	}

	if (writer)
	{
		xmlFreeTextWriter(writer);
	}

	if (output)
	{
		*output = chunk_clone(chunk_from_str(buf->content));
	}

	if (buf)
	{
		xmlBufferFree(buf);
	}

	return ret;
}

static bool xml_start(xmlTextWriterPtr *writer, xmlBufferPtr *buf, bool start_doc, const char* filename)
{
	LIBXML_TEST_VERSION
	if (filename)
	{
		*writer = xmlNewTextWriterFilename(filename, 0);
	}
	else if (buf && writer)
	{
		*buf = xmlBufferCreate();
		if (!*buf)
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to allocate output buffer for XML writter");
			return FALSE;
		}

		*writer = xmlNewTextWriterMemory(*buf, 0);
	}
	else
	{
		DBG1(DBG_IKE, "eap_anyconnect incorrect input values");
		return FALSE;
	}

	if (!*writer)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to create XML writer");
		if (buf)
		{
			xmlBufferFree(*buf);
		}

		return FALSE;
	}

	if (start_doc && xmlTextWriterStartDocument(*writer, EAP_ANY_XML_VERSION, EAP_ANY_XML_ENCODING, NULL) < 0)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to start XML document");
		xml_stop(*writer, buf ? *buf : NULL, FALSE, NULL);
		return FALSE;
	}

	return TRUE;
}

chunk_t xml_element_chunk(const char *name, ...)
{
	bool ret = TRUE;
	xmlBufferPtr buf = NULL;
	xmlTextWriterPtr writer = NULL;
	chunk_t output = chunk_empty;
	va_list attrs;

	ret = xml_start(&writer, &buf, FALSE, NULL);
	va_start(attrs, name);
	ret = ret && xml_element_va(writer, name, attrs);
	va_end(attrs);
	xml_stop(writer, buf, FALSE, &output);
	return output;
}

static chunk_t generate_random_dec(private_eap_anyconnect_t *this)
{
	uint32_t val;
	char buffer[11];
	chunk_t out = chunk_empty;
	if (this->rng->get_bytes(this->rng, sizeof(val), (char *)&val))
	{
		snprintf(buffer, sizeof(buffer), "%"PRIu32, val);
		out = chunk_clone(chunk_from_str(buffer));
	}
	else
	{
		DBG2(DBG_IKE, "eap_anyconnect unable to generate random data");
	}

	return out;
}

static chunk_t generate_random_hex(private_eap_anyconnect_t *this, size_t len)
{
	char buffer[len];
	chunk_t out = chunk_empty;
	if (this->rng->get_bytes(this->rng, len, buffer))
	{
		out = chunk_create(buffer, len);
		out = chunk_to_hex(out, NULL, TRUE);
	}
	else
	{
		DBG2(DBG_IKE, "eap_anyconnect unable to generate random data");
	}

	return out;
}

bool xml_element(xmlTextWriterPtr writer, const char *name, ...)
{
	va_list attrs;
	bool ret;

	va_start(attrs, name);
	ret = xml_element_va(writer, name, attrs);
	va_end(attrs);
	return ret;
}

static bool xml_element_list(private_eap_anyconnect_t *this, xmlTextWriterPtr writer,
	const char* root_name,
	char* root_value,
	bool cat_mode,
	char* arg1,
	char* arg2,
	char* arg3
	)
{
	bool first = TRUE;
	bool ret = TRUE;
	if (!root_name || !root_value || !arg1)
	{
		DBG1(DBG_IKE, "eap_anyconnect element root name, root value and arg1 was not provided");
		return FALSE;
	}

	if (!cat_mode)
	{
		ret = ret && xml_element(writer, root_name, XML_ELEM_NOEND);
	}

	char *saveptr = NULL;
	char *leaf_value = strtok_r(root_value, ",", &saveptr);
	chunk_t cat_ch = chunk_empty;
	while (ret && leaf_value)
	{
		if (!strlen(leaf_value))
		{
			continue;
		}

		chunk_t ch = chunk_remove_unprintable('c', chunk_from_str(leaf_value));
		if (!ch.len)
		{
			continue;
		}

		if (cat_mode)
		{
			cat_ch = chunk_cat("mcc", cat_ch, chunk_from_str(ch.len ? arg1 : ""), ch);
		}
		else if (first && arg2 && arg3)
		{
			ret = ret && xml_element(writer, arg1,
				XML_ELEM_ATTR, arg2, arg3,
				XML_ELEM_CHUNK_M, ch,
				XML_ELEM_END);
		}
		else
		{
			ret = ret && xml_element(writer, arg1, XML_ELEM_CHUNK_M, ch, XML_ELEM_END);
		}

		first = FALSE;
		leaf_value = strtok_r(NULL, ",", &saveptr);
	}

	if (cat_mode)
	{
		if (cat_ch.len)
		{
			cat_ch = chunk_cat("cmc", chunk_from_str(arg2), cat_ch, chunk_from_str(arg3));
			ret = ret && xml_element(writer, root_name, XML_ELEM_CHUNK_M, cat_ch, XML_ELEM_END);
		}
	}
	else
	{
		ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	}

	return ret;
}

static bool xml_header(private_eap_anyconnect_t *this, xmlTextWriterPtr writer, eap_anyconnect_xml_types_t type)
{
	bool ret = TRUE;
	bool generate_client_header;
	char *type_str = enum_to_name(eap_anyconnect_xml_types_keywords, type);
	switch(type)
	{
		case EAP_ANY_XML_HELLO:
		case EAP_ANY_XML_AUTH_REQUEST:
		case EAP_ANY_XML_AUTH_COMPLETE:
			generate_client_header = FALSE;
			break;
		case EAP_ANY_XML_INIT:
		case EAP_ANY_XML_AUTH_REPLY:
		case EAP_ANY_XML_ACK:
			generate_client_header = TRUE;
			break;
		case EAP_ANY_XML_NONE:
		default:
			DBG1(DBG_IKE, "eap_anyconnect invalid XML type");
			return FALSE;
	}

	ret = ret && xml_element(writer, "config-auth",
		XML_ELEM_ATTR, "client", "vpn",
		XML_ELEM_ATTR, "type", type_str,
		XML_ELEM_ATTR, "aggregate-auth-version", "2",
		XML_ELEM_NOEND);

	if (ret && generate_client_header)
	{
		ret = ret && xml_element(writer, "version",
			XML_ELEM_ATTR, "who", "vpn",
			XML_ELEM_STRING, this->settings[EAP_ANY_SET_VERSION].u.val,
			XML_ELEM_END);
		eap_anyconnect_setting_t *settings = this->settings[EAP_ANY_SET_DEVICE_ID].u.set;
		ret = ret && xml_element(writer, "device-id",
			XML_ELEM_ATTR, "computer-name", settings[EAP_ANY_SET_COMPUTER_NAME].u.val,
			XML_ELEM_ATTR, "device-type", settings[EAP_ANY_SET_DEVICE_TYPE].u.val,
			XML_ELEM_ATTR, "platform-version", settings[EAP_ANY_SET_PLATFORM_VERSION].u.val,
			XML_ELEM_ATTR, "unique-id", settings[EAP_ANY_SET_UNIQUE_ID].u.val,
			XML_ELEM_ATTR, "unique-id-global", settings[EAP_ANY_SET_UNIQUE_ID_GLOBAL].u.val,
			XML_ELEM_STRING, settings[EAP_ANY_SET_DEVICE_ID_VALUE].u.val,
			XML_ELEM_END);
		ret = ret && xml_element_list(this, writer, "mac-address-list",
			this->settings[EAP_ANY_SET_MAC_ADDRESS].u.val,
			FALSE, "mac-address", "public-interface", "true");
	}

	return ret;
}

static bool xml_session(private_eap_anyconnect_t *this, xmlTextWriterPtr writer, bool client)
{
	bool ret = TRUE;
	chunk_t session_id = chunk_empty;
	chunk_t session_token = chunk_empty;
	if (!client)
	{
		chunk_t delim = chunk_from_str("@");
		session_id = generate_random_dec(this);
		session_token = chunk_cat("mcccmcm",
				generate_random_hex(this, 3),
				delim,
				session_id,
				delim,
				generate_random_hex(this, 2),
				delim,
				generate_random_hex(this, 20));
	}

	ret = ret && xml_element(writer, "session-id", XML_ELEM_CHUNK_C, session_id, XML_ELEM_END);
	ret = ret && xml_element(writer, "session-token", XML_ELEM_CHUNK_C, session_token, XML_ELEM_END);
	return ret;
}

static bool xml_opaque_sg(private_eap_anyconnect_t *this, xmlTextWriterPtr writer, bool client)
{
	bool ret = TRUE;
	eap_anyconnect_setting_t *settings = client ? this->settings[EAP_ANY_SET_OPAQUE_CLIENT].u.set :
		this->settings[EAP_ANY_SET_OPAQUE_SERVER].u.set;
	if (this->opaque_sg.len == 0 && settings[EAP_ANY_SET_TUNNEL_GROUP].u.val && settings[EAP_ANY_SET_CONFIG_HASH].u.val)
	{
		this->opaque_sg = xml_element_chunk("opaque",
			XML_ELEM_ATTR, "is-for", "sg",
			XML_ELEM_CHUNK_M, xml_element_chunk("tunnel-group", XML_ELEM_STRING, settings[EAP_ANY_SET_TUNNEL_GROUP].u.val, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("config-hash", XML_ELEM_STRING, settings[EAP_ANY_SET_CONFIG_HASH].u.val, XML_ELEM_END),
			XML_ELEM_END);
	}

	if (this->opaque_sg.len > 0)
	{
		ret = ret && xml_element(writer, NULL, XML_ELEM_CHUNK_C, this->opaque_sg, XML_ELEM_NOEND);
	}

	return ret;
}

static bool xml_auth_success(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "auth",
		XML_ELEM_ATTR, "id", "success",
		XML_ELEM_CHUNK_M, xml_element_chunk("message",
			XML_ELEM_ATTR, "id", "0",
			XML_ELEM_ATTR, "param1", "",
			XML_ELEM_ATTR, "param2", "",
			XML_ELEM_END),
		XML_ELEM_END);
}

static bool xml_auth_complete(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "auth",
		XML_ELEM_ATTR, "id", "main",
		XML_ELEM_CHUNK_M, xml_element_chunk("authentication-complete", XML_ELEM_END),
		XML_ELEM_END);
}

static bool xml_auth(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "auth", XML_ELEM_END);
}

static bool xml_csport(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "csport", XML_ELEM_STRING, this->settings[EAP_ANY_SET_CSPORT].u.val, XML_ELEM_END);
}

static bool xml_cert_request(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "client-cert-request", XML_ELEM_END);
}

static bool xml_client_capabilities(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "group-access", XML_ELEM_STRING, this->settings[EAP_ANY_SET_GROUP_ACCESS].u.val, XML_ELEM_END);
	ret = ret && xml_element_list(this, writer, "capabilities",
			this->settings[EAP_ANY_SET_AUTH_METHOD].u.val,
			FALSE, "auth-method", NULL, NULL);
	return ret;
}

static bool xml_server_capabilities(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "capabilities", XML_ELEM_NOEND);
	if (this->settings[EAP_ANY_SET_CRYPTO_SUPPORTED].u.val)
	{
		ret = ret && xml_element(writer, "crypto-supported", XML_ELEM_STRING, this->settings[EAP_ANY_SET_CRYPTO_SUPPORTED].u.val, XML_ELEM_END);
	}

	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_host_scan_token(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "host-scan-token", XML_ELEM_CHUNK_C, this->host_scan_token, XML_ELEM_END);
}

static bool xml_host_scan(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	eap_anyconnect_setting_t *settings = this->settings[EAP_ANY_SET_HOST_SCAN].u.set;
	if (settings[EAP_ANY_SET_BASE_URI].u.val && settings[EAP_ANY_SET_WAIT_URI].u.val)
	{
		ret = ret && xml_element(writer, "host-scan",
			XML_ELEM_CHUNK_M, xml_element_chunk("host-scan-ticket", XML_ELEM_CHUNK_C, this->host_scan_ticket, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("host-scan-token", XML_ELEM_CHUNK_C, this->host_scan_token, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("host-scan-base-uri", XML_ELEM_STRING, settings[EAP_ANY_SET_BASE_URI].u.val, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("host-scan-wait-uri", XML_ELEM_STRING, settings[EAP_ANY_SET_WAIT_URI].u.val, XML_ELEM_END),
			XML_ELEM_END);
	}

	return ret;
}

static chunk_t xml_certificate_hash(const char* name, bool local, auth_rule_t rule)
{
	chunk_t hash = chunk_empty;
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA");
		return hash;
	}

	auth_cfg_t *auth = ike_sa->get_auth_cfg(ike_sa, local);
	if (!auth)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get AUTH CFG");
		return hash;
	}

	certificate_t *cert = (certificate_t *)auth->get(auth, rule);
	if (!cert)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to find certificate");
		return hash;
	}
	public_key_t *public_key = cert->get_public_key(cert);
	if (!public_key)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get public key from certificate");
		return hash;
	}

	if (!public_key->get_fingerprint(public_key, KEYID_PUBKEY_SHA1, &hash))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get public key fingerprint");
		return hash;
	}

	return xml_element_chunk(name, XML_ELEM_CHUNK_M, chunk_to_hex(hash, NULL, TRUE), XML_ELEM_END);
}

static bool xml_vpn_base_config(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	return xml_element(writer, "vpn-base-config",
		XML_ELEM_CHUNK_M, xml_element_chunk("base-package-uri", XML_ELEM_STRING, this->settings[EAP_ANY_SET_BASE_PACKAGE_URI].u.val, XML_ELEM_END),
		XML_ELEM_CHUNK_M, xml_certificate_hash("client-cert-hash", FALSE, AUTH_HELPER_SUBJECT_CERT),
		XML_ELEM_CHUNK_M, xml_certificate_hash("server-cert-hash", TRUE, AUTH_RULE_SUBJECT_CERT),
		XML_ELEM_END);
}

static bool xml_create_token_xml(private_eap_anyconnect_t *this)
{
	bool ret = TRUE;
	xmlTextWriterPtr writer = NULL;
	eap_anyconnect_setting_t *settings = this->settings[EAP_ANY_SET_HOST_SCAN].u.set;
	ret = xml_start(&writer, NULL, TRUE, settings[EAP_ANY_SET_TOKEN_XML_FILE].u.val);
	ret = ret && xml_element(writer, "hostscan",
		XML_ELEM_CHUNK_M, xml_element_chunk("ticket", XML_ELEM_CHUNK_C, this->host_scan_ticket, XML_ELEM_END),
		XML_ELEM_CHUNK_M, xml_element_chunk("token", XML_ELEM_CHUNK_C, this->host_scan_token, XML_ELEM_END),
		XML_ELEM_CHUNK_M, xml_element_chunk("certhash",
			XML_ELEM_CHUNK_M, xml_certificate_hash("server", TRUE, AUTH_RULE_SUBJECT_CERT),
			XML_ELEM_CHUNK_M, xml_certificate_hash("client", FALSE, AUTH_HELPER_SUBJECT_CERT),
			XML_ELEM_END),
		XML_ELEM_END);
	xml_stop(writer, NULL, TRUE, NULL);
	return ret;
}

static bool xml_vpn_profile_manifest(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "vpn-profile-manifest", XML_ELEM_NOEND);
	ret = ret && xml_element(writer, "vpn", XML_ELEM_ATTR, "rev", EAP_ANY_XML_REVISION, XML_ELEM_NOEND);
	eap_anyconnect_setting_t **arr = this->settings[EAP_ANY_SET_VPN_PROFILE_MANIFEST].u.arr;
	for (size_t i = 0; ret && i < this->settings[EAP_ANY_SET_VPN_PROFILE_MANIFEST].arr_count; i++)
	{
		eap_anyconnect_setting_t *settings = arr[i];;
		ret = ret && xml_element(writer, "file",
			XML_ELEM_ATTR, "type", "profile",
			XML_ELEM_ATTR, "service-type", settings[EAP_ANY_SET_PROFILE_SERVICE_TYPE].u.val,
			XML_ELEM_CHUNK_M, xml_element_chunk("uri", XML_ELEM_STRING, settings[EAP_ANY_SET_URI].u.val, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("hash",
				XML_ELEM_ATTR, "type", settings[EAP_ANY_SET_HASHTYPE].u.val,
				XML_ELEM_STRING, settings[EAP_ANY_SET_HASH].u.val, XML_ELEM_END),
			XML_ELEM_END);
	}

	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_opaque_service_profiles(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "service-profile-manifest", XML_ELEM_NOEND);
	ret = ret && xml_element(writer, "ServiceProfiles", XML_ELEM_ATTR, "rev", EAP_ANY_XML_REVISION, XML_ELEM_NOEND);
	eap_anyconnect_setting_t **arr = this->settings[EAP_ANY_SET_SERVICE_PROFILE].u.arr;
	for (size_t i = 0; ret && i < this->settings[EAP_ANY_SET_SERVICE_PROFILE].arr_count; i++)
	{
		eap_anyconnect_setting_t *settings = arr[i];;
		ret = ret && xml_element(writer, "Profile",
			XML_ELEM_ATTR, "service-type", settings[EAP_ANY_SET_SERVICE_TYPE].u.val,
			XML_ELEM_NOEND);
		if (settings[EAP_ANY_SET_SERVICE_FILE].u.val)
		{
			ret = ret && xml_element(writer, "FileName", XML_ELEM_STRING, settings[EAP_ANY_SET_SERVICE_FILE].u.val, XML_ELEM_END);
		}

		ret = ret && xml_element(writer, "FileExtension", XML_ELEM_STRING, settings[EAP_ANY_SET_EXTENSION].u.val, XML_ELEM_END);
		if (settings[EAP_ANY_SET_DERIVED_EXTENSION].u.val)
		{
			ret = ret && xml_element(writer, "DerivedFileExtension", XML_ELEM_STRING, settings[EAP_ANY_SET_DERIVED_EXTENSION].u.val, XML_ELEM_END);
		}

		if (settings[EAP_ANY_SET_DIRECTORY].u.val)
		{
			ret = ret && xml_element(writer, "Directory", XML_ELEM_STRING, settings[EAP_ANY_SET_DIRECTORY].u.val, XML_ELEM_END);
		}

		if (settings[EAP_ANY_SET_DEPLOY_DIRECTORY].u.val)
		{
			ret = ret && xml_element(writer, "DeployDirectory", XML_ELEM_STRING, settings[EAP_ANY_SET_DEPLOY_DIRECTORY].u.val, XML_ELEM_END);
		}

		xml_element(writer, NULL,
			XML_ELEM_CHUNK_M, xml_element_chunk("Description", XML_ELEM_STRING, settings[EAP_ANY_SET_DESCRIPTION].u.val, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("DownloadRemoveEmpty", XML_ELEM_STRING, settings[EAP_ANY_SET_REMOVE_EMPTY].u.val, XML_ELEM_END),
			XML_ELEM_END);
	}

	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_opaque_vpn_core_manifest(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "vpn-core-manifest", XML_ELEM_NOEND);
	ret = ret && xml_element(writer, "vpn", XML_ELEM_ATTR, "rev", EAP_ANY_XML_REVISION, XML_ELEM_NOEND);

	eap_anyconnect_setting_t **arr = this->settings[EAP_ANY_SET_VPN_CORE_MANIFEST].u.arr;
	for (size_t i = 0; ret && i < this->settings[EAP_ANY_SET_VPN_CORE_MANIFEST].arr_count; i++)
	{
		eap_anyconnect_setting_t *settings = arr[i];;
		ret = ret && xml_element(writer, "file",
			XML_ELEM_ATTR, "version", settings[EAP_ANY_SET_VPN_VERSION].u.val,
			XML_ELEM_ATTR, "is_core", settings[EAP_ANY_SET_IS_CORE].u.val,
			XML_ELEM_ATTR, "type", settings[EAP_ANY_SET_TYPE].u.val,
			XML_ELEM_ATTR, "action", settings[EAP_ANY_SET_ACTION].u.val,
			XML_ELEM_ATTR, "os", settings[EAP_ANY_SET_OS].u.val,
			XML_ELEM_CHUNK_M, xml_element_chunk("uri", XML_ELEM_STRING, settings[EAP_ANY_SET_VPN_URI].u.val, XML_ELEM_END),
			XML_ELEM_CHUNK_M, xml_element_chunk("display-name", XML_ELEM_STRING, settings[EAP_ANY_SET_DISPLAY_NAME].u.val, XML_ELEM_END),
			XML_ELEM_END);
	}

	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_dynamic_split_exclude_domains(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element_list(this, writer, "dynamic-split-exclude-domains",
		this->settings[EAP_ANY_SET_DYN_EXC_DOMAINS].u.val,
		TRUE, ", ", "<![CDATA[", "]]>");
	return ret;
}

static bool xml_opaque_vpn_client(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "opaque", XML_ELEM_ATTR, "is-for", "vpn-client", XML_ELEM_NOEND);
	ret = ret && xml_opaque_service_profiles(this, writer);
	ret = ret && xml_element(writer, "vpn-client-pkg-version",
		XML_ELEM_CHUNK_M, xml_element_chunk("pkgversion", XML_ELEM_STRING, this->settings[EAP_ANY_SET_PKGVERSION].u.val, XML_ELEM_END),
		XML_ELEM_END);
	ret = ret && xml_opaque_vpn_core_manifest(this, writer);
	ret = ret && xml_element(writer, "custom-attr", XML_ELEM_NOEND);
	ret = ret && xml_dynamic_split_exclude_domains(this, writer);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_config_client(private_eap_anyconnect_t *this, xmlTextWriterPtr writer)
{
	bool ret = TRUE;
	ret = ret && xml_element(writer, "config", XML_ELEM_ATTR, "vpn", "private", XML_ELEM_NOEND);
	ret = ret && xml_vpn_base_config(this, writer);
	ret = ret && xml_csport(this, writer);
	ret = ret && xml_opaque_vpn_client(this, writer);
	ret = ret && xml_vpn_profile_manifest(this, writer);
	ret = ret && xml_element(writer, NULL, XML_ELEM_END);
	return ret;
}

static bool xml_footer(xmlTextWriterPtr writer)
{
	return xml_element(writer, NULL, XML_ELEM_END);
}

static bool create_xml(private_eap_anyconnect_t *this, eap_anyconnect_xml_types_t type, chunk_t *output)
{
	bool ret = TRUE;
	xmlTextWriterPtr writer;
	xmlBufferPtr buf;
	if (!xml_start(&writer, &buf, TRUE, NULL) || !xml_header(this, writer, type))
	{
		return FALSE;
	}

	switch(type)
	{
		case EAP_ANY_XML_HELLO:
			break;
		case EAP_ANY_XML_INIT:
			ret = ret && xml_opaque_sg(this, writer, TRUE);
			ret = ret && xml_client_capabilities(this, writer);
			break;
		case EAP_ANY_XML_AUTH_REQUEST:
			if (this->client_cert_received)
			{
				ret = ret && xml_opaque_sg(this, writer, FALSE);
				ret = ret && xml_csport(this, writer);
				ret = ret && xml_auth_complete(this, writer);
				ret = ret && xml_host_scan(this, writer);
				ret = ret && xml_create_token_xml(this);
			}
			else
			{
				ret = ret && xml_csport(this, writer);
				ret = ret && xml_cert_request(this, writer);
			}
			break;
		case EAP_ANY_XML_AUTH_REPLY:
			ret = ret && xml_session(this, writer, TRUE);
			ret = ret && xml_opaque_sg(this, writer, TRUE);
			ret = ret && xml_auth(this, writer);
			ret = ret && xml_host_scan_token(this, writer);
			break;
		case EAP_ANY_XML_AUTH_COMPLETE:
			ret = ret && xml_session(this, writer, FALSE);
			ret = ret && xml_auth_success(this, writer);
			ret = ret && xml_server_capabilities(this, writer);
			ret = ret && xml_config_client(this, writer);
			break;
		case EAP_ANY_XML_ACK:
			break;
		default:
			ret = FALSE;
	}

	ret = ret && xml_footer(writer);
	xml_stop(writer, buf, TRUE, output);
	return ret;
}

static bool add_cert_to_blob(private_eap_anyconnect_t *this, auth_rule_t rule, certificate_t **subject, chunk_t *blob)
{
	enumerator_t *enumerator;
	certificate_t *cert;
	auth_rule_t type;

	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA");
		return FALSE;
	}

	auth_cfg_t *auth = ike_sa->get_auth_cfg(ike_sa, TRUE);
	if (!auth)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get AUTH CFG");
		return FALSE;
	}

	enumerator = auth->create_enumerator(auth);
	while (enumerator->enumerate(enumerator, &type, &cert))
	{
		if (type == rule && (*subject == NULL || (*subject)->issued_by(*subject, cert, NULL)))
		{
			chunk_t encoded;
			if (!cert->get_encoding(cert, CERT_ASN1_DER, &encoded))
			{
				DBG1(DBG_IKE, "eap_anyconnect unable to encode certificate");
				return FALSE;
			}

			*subject = cert;
			*blob = chunk_cat("mm", *blob, encoded);
			return TRUE;
		}
	}

	return TRUE;
}

static bool add_certificate_to_tlvs(private_eap_anyconnect_t *this)
{
	chunk_t data = chunk_empty;
	certificate_t *cert = NULL;
	if (!add_cert_to_blob(this, AUTH_RULE_SUBJECT_CERT, &cert, &data) ||
		!add_cert_to_blob(this, AUTH_RULE_IM_CERT, &cert, &data) ||
		!add_cert_to_blob(this, AUTH_RULE_CA_CERT, &cert, &data))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable prepare data for PKCS7 container");
		return FALSE;
	}

	data = asn1_wrap(ASN1_SEQUENCE, "mm",
			asn1_build_known_oid(OID_PKCS7_SIGNED_DATA),
			asn1_wrap(ASN1_CONTEXT_C_0, "m",
				asn1_wrap(ASN1_SEQUENCE, "cmmmm",
					ASN1_INTEGER_1,
					asn1_simple_object(ASN1_SET, chunk_empty),
					asn1_wrap(ASN1_SEQUENCE, "mm",
						asn1_build_known_oid(OID_PKCS7_DATA),
						asn1_wrap(ASN1_CONTEXT_C_0, "c", asn1_simple_object(ASN1_OCTET_STRING, chunk_empty))),
					asn1_wrap(ASN1_CONTEXT_C_0, "m", data),
					asn1_simple_object(ASN1_SET, chunk_empty)
				)));

	eap_anyconnect_data_t *tlv;
	INIT(tlv, .type = EAP_ANY_PKCS7, .data = data, .own_data = TRUE);
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	return TRUE;
}

static bool add_xml_to_tlvs(private_eap_anyconnect_t *this, eap_anyconnect_xml_types_t type)
{
	chunk_t xmldata = chunk_empty;
	if (!create_xml(this, type, &xmldata))
	{
		return FALSE;
	}

	eap_anyconnect_data_t *tlv;
	INIT(tlv, .type = EAP_ANY_XML, .data = xmldata, .own_data = TRUE);
	array_insert(this->tlvs, ARRAY_TAIL, tlv);
	return TRUE;
}

static xmlNodePtr find_by_name(xmlNodePtr root, const char *name)
{
	xmlNodePtr cur = root->children;
	while (cur)
	{
		if ((!xmlStrcmp(cur->name, (const xmlChar *)name)))
		{
			break;
		}

		cur = cur->next;
	}

	return cur;
}

static bool xml_store_value(xmlDocPtr xml, xmlNodePtr root, const char *element_name, chunk_t *storage, bool include_node)
{
	xmlNodePtr node = find_by_name(root, element_name);
	char *strval = NULL;
	if (!node)
	{
		DBG2(DBG_IKE, "eap_anyconnect unable to find element %s", element_name);
		return FALSE;
	}

	chunk_free(storage);
	xmlBufferPtr buf = xmlBufferCreate();
	if (!buf)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to allocated XML output buffer for XML node %s", element_name);
		xmlBufferFree(buf);
		return FALSE;
	}

	if (include_node)
	{
		if (xmlNodeDump(buf, xml, node, 0, 0) < 0)
		{
			DBG1(DBG_IKE, "eap_anyconnect unable to dump content content of XML node %s", element_name);
			xmlBufferFree(buf);
			return FALSE;
		}

		strval = buf->content;
	}
	else
	{
		strval = xmlNodeGetContent(node->children);
		if (!strval)
		{
			strval = "";
		}
	}

	if (!strval)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get content of XML node %s", element_name);
		xmlBufferFree(buf);
		return FALSE;
	}

	*storage = chunk_clone(chunk_from_str(strval));
	xmlBufferFree(buf);
	return TRUE;
}

static bool xml_verify_value(xmlDocPtr xml, xmlNodePtr root, const char *element_name, chunk_t expected_value, bool include_node)
{
	bool ret = TRUE;
	chunk_t received_value = chunk_empty;
	ret = xml_store_value(xml, root, element_name, &received_value, include_node);
	received_value = chunk_remove_unprintable('m', received_value);
	if (!ret || (ret && chunk_compare(expected_value, received_value)))
	{
		DBG1(DBG_IKE, "eap_anyconnect received value of element %s doesn't match expected value", element_name);
		DBG1(DBG_IKE, "eap_anyconnect received value %B", &received_value);
		DBG1(DBG_IKE, "eap_anyconnect expected value %B", &expected_value);
		ret = FALSE;
	}

	chunk_free(&received_value);
	return ret;
}


static status_t general_process(private_eap_anyconnect_t *this, eap_payload_t *in, eap_anyconnect_xml_types_t *type, xmlNodePtr *config_auth, uint8_t *id)
{
	status_t ret = parse_payload(this, in, id);
	if (ret != SUCCESS)
	{
		return ret;
	}

	*config_auth = xmlDocGetRootElement(this->xml);
	if (!*config_auth)
	{
		DBG2(DBG_IKE, "eap_anyconnect received XML doesn't include config-auth element");
		return FAILED;
	}

	xmlNodePtr err = find_by_name(*config_auth, "error");
	if (err)
	{
		char *errStr = (char *)xmlNodeGetContent(err->children);
		DBG1(DBG_IKE, "eap_anyconnect received XML with the following error: %s", errStr);
		return FAILED;
	}

	xmlChar* value = xmlGetProp(*config_auth, (const xmlChar *)"type");
	*type = get_type_by_string(value);
	if (*type != this->expected_msg_type)
	{
		DBG1(DBG_IKE, "eap_anyconnect received not expected message of type %N", eap_anyconnect_xml_types_keywords, *type);
		return NEED_MORE;
	}

	DBG2(DBG_IKE, "eap_anyconnect XML of type %N received", eap_anyconnect_xml_types_keywords, *type);
	return SUCCESS;
}

METHOD(eap_method_t, initiate_peer, status_t,
	private_eap_anyconnect_t *this, eap_payload_t **out)
{
	return FAILED;
}

METHOD(eap_method_t, initiate_server, status_t,
	private_eap_anyconnect_t *this, eap_payload_t **out)
{
	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	if (!add_xml_to_tlvs(this, EAP_ANY_XML_HELLO))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add XML");
		return FAILED;
	}

	this->header.code = EAP_REQUEST;
	this->header.id++;
	*out = encode_payload(this);
	return NEED_MORE;
}

METHOD(eap_method_t, process_peer, status_t,
	private_eap_anyconnect_t *this, eap_payload_t *in, eap_payload_t **out)
{
	*out = NULL;
	bool add_certs_and_sign = FALSE;
	eap_anyconnect_xml_types_t add_xml = EAP_ANY_XML_NONE;
	bool initiate_host_scan = FALSE;
	char buffer[1000];
	ike_sa_t *ike_sa = charon->bus->get_sa(charon->bus);
	if (!ike_sa)
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to get IKE SA");
		return FAILED;
	}

	eap_anyconnect_xml_types_t received_xml_type;
	xmlNodePtr config_auth;
	uint8_t msg_id;
	status_t ret = general_process(this, in, &received_xml_type, &config_auth, &msg_id);
	if (ret != SUCCESS)
	{
		return ret;
	}

	switch (received_xml_type)
	{
		case EAP_ANY_XML_HELLO:
			add_xml = EAP_ANY_XML_INIT;
			this->expected_msg_type = EAP_ANY_XML_AUTH_REQUEST;
			break;
		case EAP_ANY_XML_AUTH_REQUEST:
			xml_store_value(this->xml, config_auth, "opaque", &this->opaque_sg, TRUE);
			xmlNodePtr cert_request = find_by_name(config_auth, "client-cert-request");
			if (cert_request)
			{
				DBG2(DBG_IKE, "eap_anyconnect client-cert-request received");
				add_xml = EAP_ANY_XML_INIT;
				this->expected_msg_type = EAP_ANY_XML_AUTH_REQUEST;
				add_certs_and_sign = TRUE;
			}

			xmlNodePtr host_scan = find_by_name(config_auth, "host-scan");
			if (host_scan)
			{
				DBG2(DBG_IKE, "eap_anyconnect host-scan received");
				add_xml = EAP_ANY_XML_AUTH_REPLY;
				this->expected_msg_type = EAP_ANY_XML_AUTH_COMPLETE;
				initiate_host_scan = TRUE;
				if (!xml_store_value(this->xml, host_scan, "host-scan-ticket", &this->host_scan_ticket, FALSE) ||
					!xml_store_value(this->xml, host_scan, "host-scan-token", &this->host_scan_token, FALSE))
				{
					return FAILED;
				}
			}
			break;
		case EAP_ANY_XML_AUTH_COMPLETE:
			add_xml = EAP_ANY_XML_ACK;
			break;
		default:
			DBG1(DBG_IKE, "eap_anyconnect received invalid XML type %N", eap_anyconnect_xml_types_keywords, received_xml_type);
			return FAILED;
	}

	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	if (add_certs_and_sign && (!add_certificate_to_tlvs(this) || !add_signature(this)))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add certificate and signature");
		return FAILED;
	}

	if (initiate_host_scan)
	{
		host_t *other = ike_sa->get_other_host(ike_sa);
		snprintf(buffer, sizeof(buffer), "%s -host %H -ticket %.*s",
				this->settings[EAP_ANY_SET_CSD_WRAPPER].u.val, other,
				this->host_scan_ticket.len, this->host_scan_ticket.ptr);
		DBG2(DBG_IKE, "eap_anyconnect initiating CSD wrapper with command \"%s\"", buffer);
		int csd_ret = system(buffer);
		switch(system(buffer)){
			case 0:
				DBG2(DBG_IKE, "eap_anyconnect CSD wrapper finished successfully");
				break;
			case 1:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed to get token");
				return FAILED;
			case 2:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed to get proper response from wait");
				return FAILED;
			case 3:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed on CURL command");
				return FAILED;
			default:
				DBG1(DBG_IKE, "eap_anyconnect CSD wrapper failed due to unspecific reason with error code %d", csd_ret);
				return FAILED;
		}
	}

	if (add_xml != EAP_ANY_XML_NONE && !add_xml_to_tlvs(this, add_xml))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add XML");
		return FAILED;
	}

	this->header.code = EAP_RESPONSE;
	this->header.id = msg_id;
	*out = encode_payload(this);
	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	private_eap_anyconnect_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_anyconnect_xml_types_t add_xml = EAP_ANY_XML_NONE;
	eap_anyconnect_xml_types_t received_xml_type;
	xmlNodePtr config_auth;
	uint8_t msg_id;
	status_t ret = general_process(this, in, &received_xml_type, &config_auth, &msg_id);
	if (ret != SUCCESS)
	{
		return ret;
	}

	if (msg_id != this->header.id)
	{
		DBG1(DBG_IKE, "eap_anyconnect received message with invalid ID %d", msg_id);
		return NEED_MORE;
	}

	switch (received_xml_type)
	{
		case EAP_ANY_XML_INIT:
			if (get_tlv(this->tlvs, EAP_ANY_PKCS7) && get_tlv(this->tlvs, EAP_ANY_SIGN))
			{
				DBG2(DBG_IKE, "eap_anyconnect received client certificate and signature");
				if (verify_signature(this))
				{
					add_xml = EAP_ANY_XML_AUTH_REQUEST;
					this->expected_msg_type = EAP_ANY_XML_AUTH_REPLY;
					this->client_cert_received = TRUE;
				}
				else
				{
					DBG1(DBG_IKE, "eap_anyconnect client authentication using certificate and signature failed");
					return FAILED;
				}
			}
			else
			{
				add_xml = EAP_ANY_XML_AUTH_REQUEST;
				this->expected_msg_type = EAP_ANY_XML_INIT;
			}
			break;
		case EAP_ANY_XML_AUTH_REPLY:
		{
			bool verified = TRUE;
			verified = verified && xml_verify_value(this->xml, config_auth, "session-id", chunk_empty, FALSE);
			verified = verified && xml_verify_value(this->xml, config_auth, "session-token", chunk_empty, FALSE);
			verified = verified && xml_verify_value(this->xml, config_auth, "opaque", this->opaque_sg, TRUE);
			verified = verified && xml_verify_value(this->xml, config_auth, "auth", chunk_empty, FALSE);
			verified = verified && xml_verify_value(this->xml, config_auth, "host-scan-token", this->host_scan_token, FALSE);
			if (verified)
			{
				add_xml = EAP_ANY_XML_AUTH_COMPLETE;
				this->expected_msg_type = EAP_ANY_XML_ACK;
			}
			else
			{
				DBG1(DBG_IKE, "eap_anyconnect client authentication failed on session/opaque/auth/hostscan");
				return FAILED;
			}
			break;
		}
		case EAP_ANY_XML_ACK:
			return SUCCESS;
		default:
			DBG1(DBG_IKE, "eap_anyconnect received invalid XML type %N", eap_anyconnect_xml_types_keywords, received_xml_type);
			return FAILED;
	}

	clear_array(this->tlvs);
	this->tlvs = array_create(0, 2);
	if (add_xml != EAP_ANY_XML_NONE && !add_xml_to_tlvs(this, add_xml))
	{
		DBG1(DBG_IKE, "eap_anyconnect unable to add XML");
		return FAILED;
	}

	this->header.code = EAP_REQUEST;
	this->header.id++;
	*out = encode_payload(this);
	return NEED_MORE;
}

METHOD(eap_method_t, get_type, eap_type_t,
	private_eap_anyconnect_t *this, pen_t *vendor)
{
	*vendor = PEN_CISCO;
	return EAP_ANYCONNECT;
}

METHOD(eap_method_t, get_msk, status_t,
	private_eap_anyconnect_t *this, chunk_t *msk)
{
	return NOT_SUPPORTED;
}

METHOD(eap_method_t, is_mutual, bool,
	private_eap_anyconnect_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, get_identifier, uint8_t,
	private_eap_anyconnect_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	private_eap_anyconnect_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, destroy, void,
	private_eap_anyconnect_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	chunk_free(&this->challenge);
	clear_array(this->tlvs);
	chunk_free(&this->ike_sa_init);
	chunk_free(&this->nonce);
	destroy_xml(this);
	chunk_free(&this->host_scan_ticket);
	chunk_free(&this->host_scan_token);
	chunk_free(&this->opaque_sg);
	chunk_free(&this->session_id);
	chunk_free(&this->session_token);
	destroy_settings(this->settings, this->settings_size);
	DESTROY_IF(this->rng);
	free(this);
}

METHOD(eap_method_t, set_nonce, void,
	private_eap_anyconnect_t *this, chunk_t nonce)
{
	this->nonce = chunk_clone(nonce);
}

METHOD(eap_method_t, set_ike_sa_init, void,
	private_eap_anyconnect_t *this, chunk_t ike_sa_init)
{
	this->ike_sa_init = chunk_clone(ike_sa_init);
}

METHOD(eap_method_t, set_reserved, void,
	private_eap_anyconnect_t *this, char *reserved)
{
	memcpy(this->reserved, reserved, sizeof(this->reserved));
	this->set_reserved_called = TRUE;
}

void init_header(private_eap_anyconnect_t *this)
{
	this->header.code = 0;
	this->header.id = 0;
	this->header.length = 0;
	uint32_t vendor = (uint32_t)PEN_CISCO;
	vendor = untoh32(&vendor);
	*(uint32_t*)&this->header.type = vendor;
	this->header.type = EAP_EXPANDED;
	this->header.vendor_type = EAP_ANYCONNECT;
	this->header.vendor_type = untoh32(&this->header.vendor_type);
}

/*
 * See header
 */
eap_anyconnect_t *eap_anyconnect_create_server(identification_t *server, identification_t *peer)
{
	private_eap_anyconnect_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_server,
				.process = _process_server,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.get_identifier = _get_identifier,
				.set_identifier = _set_identifier,
				.destroy = _destroy,
				.set_nonce = _set_nonce,
				.set_ike_sa_init = _set_ike_sa_init,
				.set_reserved = _set_reserved,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.tlvs = NULL,
		.nonce = chunk_empty,
		.ike_sa_init = chunk_empty,
		.set_reserved_called = FALSE,
		.xml = NULL,
		.host_scan_ticket = chunk_empty,
		.host_scan_token = chunk_empty,
		.opaque_sg = chunk_empty,
		.session_id = chunk_empty,
		.session_token = chunk_empty,
		.client_cert_received = FALSE,
		.settings_size = countof(eap_anyconnect_xml_server_setting_rules),
		.expected_msg_type = EAP_ANY_XML_INIT,
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
	);

	init_header(this);
	memset(this->reserved, 0, sizeof(this->reserved));
	if (!this->rng || !load_settings(NULL, &this->settings, eap_anyconnect_xml_server_setting_rules, this->settings_size))
	{
		_destroy(this);
		return NULL;
	}

	this->host_scan_ticket = generate_random_hex(this, EAP_ANY_HOST_SCAN_LEN);
	this->host_scan_token = generate_random_hex(this, EAP_ANY_HOST_SCAN_LEN);
	/* generate a non-zero identifier */
	do {
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * See header
 */
eap_anyconnect_t *eap_anyconnect_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_anyconnect_t *this;

	INIT(this,
		.public = {
			.eap_method = {
				.initiate = _initiate_peer,
				.process = _process_peer,
				.get_type = _get_type,
				.is_mutual = _is_mutual,
				.get_msk = _get_msk,
				.destroy = _destroy,
				.set_nonce = _set_nonce,
				.set_ike_sa_init = _set_ike_sa_init,
				.set_reserved = _set_reserved,
			},
		},
		.peer = peer->clone(peer),
		.server = server->clone(server),
		.tlvs = NULL,
		.nonce = chunk_empty,
		.ike_sa_init = chunk_empty,
		.set_reserved_called = FALSE,
		.xml = NULL,
		.host_scan_ticket = chunk_empty,
		.host_scan_token = chunk_empty,
		.opaque_sg = chunk_empty,
		.session_id = chunk_empty,
		.session_token = chunk_empty,
		.client_cert_received = FALSE,
		.settings_size = countof(eap_anyconnect_xml_client_setting_rules),
		.expected_msg_type = EAP_ANY_XML_HELLO,
		.rng = NULL,
	);

	init_header(this);
	memset(this->reserved, 0, sizeof(this->reserved));
	if (!load_settings(NULL, &this->settings, eap_anyconnect_xml_client_setting_rules, this->settings_size))
	{
		_destroy(this);
		return NULL;
	}

	return &this->public;
}
