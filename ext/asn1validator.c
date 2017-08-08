/*
 * Ruby bindings for interfacing with asn1c-generated ASN.1 PDU parsing code.
 * Copyright (c) 2016 Matt Palmer <matt@hezmatt.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not
 * use this file except in compliance with the License. A copy of the License
 * is located at
 *
 *   http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
#include <ruby/ruby.h>

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

#include <asn_application.h>

extern asn_TYPE_descriptor_t *asn_pdu_collection[];

static VALUE mCertLint;
static VALUE cASN1Validator;

static asn_TYPE_descriptor_t *asn1pdu_type_descriptor(VALUE pdu_type) {
	asn_TYPE_descriptor_t **pdu = asn_pdu_collection;

	while(*pdu) {
		if (!strcmp((*pdu)->name, StringValuePtr(pdu_type))) {
			return *pdu;
		}
		pdu++;
	}
	
	rb_raise(rb_eArgError, "Unknown PDU type");
	return NULL;  /* Unreachable, we hope */
}

/* Remember to call ASN_STRUCT_FREE on the return value after you're done,
 * otherwise leaks will result.
 */
static void *asn1pdu_decode_pdu(VALUE pdu_data, VALUE pdu_type) {
	void *structure = NULL;
	asn_dec_rval_t rv;

	rv = ber_decode(NULL, asn1pdu_type_descriptor(pdu_type), &structure,
	                RSTRING_PTR(pdu_data), RSTRING_LEN(pdu_data));

	if (rv.code == RC_OK) {
		return structure;
	} else {
		rb_raise(rb_eArgError, "BER decoding failed at octet %ld: %s",
		                            rv.consumed,
		                            rv.code == RC_WMORE ? "Unexpected end of input" : "Parse error");
		return NULL;  /* Unreachable, we hope */
	}
}

static VALUE asn1pdu_initialize(VALUE self, VALUE pdu_data, VALUE pdu_type) {
	if (TYPE(pdu_data) != T_STRING) {
		rb_raise(rb_eTypeError, "PDU data must be a string");
	} else {
		rb_iv_set(self, "@pdu_data", pdu_data);
	}

	if (TYPE(pdu_type) == T_SYMBOL) {
		pdu_type = rb_str_new2(rb_id2name(SYM2ID(pdu_type)));
	}

	if (TYPE(pdu_type) == T_STRING) {
		rb_iv_set(self, "@pdu_type", pdu_type);
	} else {
		rb_raise(rb_eTypeError, "PDU type must be a symbol or string");
	}

	/* Do a test parse, so we can raise the failure exception nice and early */
	ASN_STRUCT_FREE(*asn1pdu_type_descriptor(pdu_type), asn1pdu_decode_pdu(pdu_data, pdu_type));

	return self;
}

static VALUE asn1pdu_check_constraints(VALUE self) {
	char errbuf[128];
	size_t errlen = sizeof(errbuf);
	VALUE d = rb_iv_get(self, "@pdu_data");
	VALUE t = rb_iv_get(self, "@pdu_type");
	void *pdu_structure = asn1pdu_decode_pdu(d, t);
	int rv;

	rv = asn_check_constraints(asn1pdu_type_descriptor(t), pdu_structure, errbuf, &errlen);
	ASN_STRUCT_FREE(*asn1pdu_type_descriptor(t), pdu_structure);

	if (rv) {
		rb_raise(rb_eRuntimeError, "ASN.1 constraint check failed: %s", errbuf);
		return Qfalse;  /* Unreachable, we hope */
	} else {
		return Qtrue;
	}
}

static VALUE asn1pdu_to_der(VALUE self) {
	char *derbuf = NULL;
	size_t derlen = 8192;  /* 16k ought to be enough for anybody? */
	VALUE d = rb_iv_get(self, "@pdu_data");
	VALUE t = rb_iv_get(self, "@pdu_type");
	void *pdu_structure = asn1pdu_decode_pdu(d, t);
	asn_enc_rval_t rv;
	VALUE ret;
	
	rv.encoded = -1;

	while (rv.encoded == -1) {
		if (derbuf) free(derbuf);
		derlen *= 2;
		
		derbuf = malloc(derlen);
		if (derbuf == NULL) {
			rb_raise(rb_eNoMemError, "Unable to allocate memory for derbuf");
			abort();  /* Unreachable, we hope */
		}

		rv = der_encode_to_buffer(asn1pdu_type_descriptor(t), pdu_structure, derbuf, derlen);
	}

	ASN_STRUCT_FREE(*asn1pdu_type_descriptor(t), pdu_structure);
	
	ret = rb_str_new(derbuf, rv.encoded);
	free(derbuf);
	return ret;
}

void Init_asn1validator() {
	mCertLint = rb_define_module("CertLint");
	cASN1Validator = rb_define_class_under(mCertLint, "ASN1Validator", rb_cObject);

	rb_define_method(cASN1Validator, "initialize", asn1pdu_initialize, 2);
	rb_define_method(cASN1Validator, "check_constraints", asn1pdu_check_constraints, 0);
	rb_define_method(cASN1Validator, "to_der", asn1pdu_to_der, 0);
}
