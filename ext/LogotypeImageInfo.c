/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "LogotypeCertExtn"
 * 	found in "asn1/rfc3709-LogotypeCertExtn.asn1"
 * 	`asn1c -S asn1c/skeletons -pdu=all -pdu=Certificate -fwide-types`
 */

#include "LogotypeImageInfo.h"

static int asn_DFL_2_set_1(int set_value, void **sptr) {
	LogotypeImageType_t *st = *sptr;
	
	if(!st) {
		if(!set_value) return -1;	/* Not a default value */
		st = (*sptr = CALLOC(1, sizeof(*st)));
		if(!st) return -1;
	}
	
	if(set_value) {
		/* Install default value 1 */
		return asn_long2INTEGER(st, 1);
	} else {
		/* Test default value 1 */
		long value;
		if(asn_INTEGER2long(st, &value))
			return -1;
		return (value == 1);
	}
}
asn_TYPE_member_t asn_MBR_LogotypeImageInfo_1[] = {
	{ ATF_POINTER, 1, offsetof(struct LogotypeImageInfo, type),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LogotypeImageType,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		asn_DFL_2_set_1,	/* DEFAULT 1 */
		"type"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogotypeImageInfo, fileSize),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_INTEGER,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"fileSize"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogotypeImageInfo, xSize),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_INTEGER,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"xSize"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct LogotypeImageInfo, ySize),
		(ASN_TAG_CLASS_UNIVERSAL | (2 << 2)),
		0,
		&asn_DEF_INTEGER,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"ySize"
		},
	{ ATF_POINTER, 2, offsetof(struct LogotypeImageInfo, resolution),
		-1 /* Ambiguous tag (CHOICE?) */,
		0,
		&asn_DEF_LogotypeImageResolution,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"resolution"
		},
	{ ATF_POINTER, 1, offsetof(struct LogotypeImageInfo, language),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_IA5String,
		0,
		0,	/* Defer constraints checking to the member type */
		0,	/* OER is not compiled, use -gen-OER */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"language"
		},
};
static const ber_tlv_tag_t asn_DEF_LogotypeImageInfo_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_LogotypeImageInfo_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 1, 0, 2 }, /* fileSize */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 2, -1, 1 }, /* xSize */
    { (ASN_TAG_CLASS_UNIVERSAL | (2 << 2)), 3, -2, 0 }, /* ySize */
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* type */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 4, 0, 0 }, /* numBits */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 4, 0, 0 }, /* tableSize */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 5, 0, 0 } /* language */
};
asn_SEQUENCE_specifics_t asn_SPC_LogotypeImageInfo_specs_1 = {
	sizeof(struct LogotypeImageInfo),
	offsetof(struct LogotypeImageInfo, _asn_ctx),
	asn_MAP_LogotypeImageInfo_tag2el_1,
	7,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_LogotypeImageInfo = {
	"LogotypeImageInfo",
	"LogotypeImageInfo",
	&asn_OP_SEQUENCE,
	SEQUENCE_constraint,
	asn_DEF_LogotypeImageInfo_tags_1,
	sizeof(asn_DEF_LogotypeImageInfo_tags_1)
		/sizeof(asn_DEF_LogotypeImageInfo_tags_1[0]), /* 1 */
	asn_DEF_LogotypeImageInfo_tags_1,	/* Same as above */
	sizeof(asn_DEF_LogotypeImageInfo_tags_1)
		/sizeof(asn_DEF_LogotypeImageInfo_tags_1[0]), /* 1 */
	0,	/* No OER visible constraints */
	0,	/* No PER visible constraints */
	asn_MBR_LogotypeImageInfo_1,
	6,	/* Elements count */
	&asn_SPC_LogotypeImageInfo_specs_1	/* Additional specs */
};

