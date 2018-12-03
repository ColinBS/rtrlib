/*
 * This file is part of RTRlib.
 *
 * This file is subject to the terms and conditions of the MIT license.
 * See the file LICENSE in the top level directory for more details.
 *
 * Website: http://rtrlib.realmv6.org/
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef BGPSEC

#include "rtrlib/bgpsec/bgpsec.h"

static uint8_t ski1[]  = {
		0xAB, 0x4D, 0x91, 0x0F, 0x55,
		0xCA, 0xE7, 0x1A, 0x21, 0x5E,
		0xF3, 0xCA, 0xFE, 0x3A, 0xCC,
		0x45, 0xB5, 0xEE, 0xC1, 0x54
};

static uint8_t sig1_old[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xEF, 0xD4, 0x8B, 0x2A, 0xAC,
		0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81,
		0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3,
		0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16, 0x02, 0x21, 0x00,
		0x8E, 0x21, 0xF6, 0x0E, 0x44, 0xC6, 0x06, 0x6C, 0x8B, 0x8A,
		0x95, 0xA3, 0xC0, 0x9D, 0x3A, 0xD4, 0x37, 0x95, 0x85, 0xA2,
		0xD7, 0x28, 0xEE, 0xAD, 0x07, 0xA1, 0x7E, 0xD7, 0xAA, 0x05,
		0x5E, 0xCA
};

static uint8_t sig1[] = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xF8, 0xF2, 0xEC, 0x8B, 0xA5, 0x81, 0x17, 0x2F, 0x32, 0x8B, 0x4B,
		0x01, 0xD9, 0x93, 0x6C, 0x49, 0xA1, 0x87, 0x93, 0xCC, 0x08, 0xF6, 0xED, 0x04, 0x5B, 0xC4, 0x25,
		0x06, 0x05, 0xEB, 0xE7, 0xE7, 0x02, 0x21, 0x00, 0xC4, 0x76, 0xEB, 0x43, 0xC0, 0xB1, 0xDF, 0xAA,
		0x5D, 0x59, 0x15, 0xB8, 0x3E, 0x99, 0x68, 0xF8, 0x86, 0x6D, 0x16, 0x4B, 0x16, 0xC2, 0x60, 0x90,
		0xB2, 0xA6, 0x8E, 0x4D, 0xE1, 0x2E, 0xC8, 0xCF
};

static uint8_t spki1[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x73, 0x91, 0xBA,
		0xBB, 0x92, 0xA0, 0xCB, 0x3B, 0xE1, 0x0E, 0x59, 0xB1, 0x9E,
		0xBF, 0xFB, 0x21, 0x4E, 0x04, 0xA9, 0x1E, 0x0C, 0xBA, 0x1B,
		0x13, 0x9A, 0x7D, 0x38, 0xD9, 0x0F, 0x77, 0xE5, 0x5A, 0xA0,
		0x5B, 0x8E, 0x69, 0x56, 0x78, 0xE0, 0xFA, 0x16, 0x90, 0x4B,
		0x55, 0xD9, 0xD4, 0xF5, 0xC0, 0xDF, 0xC5, 0x88, 0x95, 0xEE,
		0x50, 0xBC, 0x4F, 0x75, 0xD2, 0x05, 0xA2, 0x5B, 0xD3, 0x6F,
		0xF5
};

static uint8_t ski2[]  = {
		0x47, 0xF2, 0x3B, 0xF1, 0xAB,
		0x2F, 0x8A, 0x9D, 0x26, 0x86,
		0x4E, 0xBB, 0xD8, 0xDF, 0x27,
		0x11, 0xC7, 0x44, 0x06, 0xEC
};

static uint8_t sig2_old[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xEF, 0xD4, 0x8B, 0x2A, 0xAC,
		0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81,
		0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91, 0xC3,
		0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16, 0x02, 0x21, 0x00,
		0x90, 0xF2, 0xC1, 0x29, 0xAB, 0xB2, 0xF3, 0x9B, 0x6A, 0x07,
		0x96, 0x3B, 0xD5, 0x55, 0xA8, 0x7A, 0xB2, 0xB7, 0x33, 0x3B,
		0x7B, 0x91, 0xF1, 0x66, 0x8F, 0xD8, 0x61, 0x8C, 0x83, 0xFA,
		0xC3, 0xF1
};

static uint8_t sig2[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xC2, 0x0E, 0xDA, 0x15, 0x17, 0x17, 0x4A, 0xFF, 0x2B, 0x24, 0x7B,
		0xA7, 0x82, 0x08, 0x28, 0x75, 0x61, 0xB8, 0xDA, 0xDE, 0x52, 0xAF, 0x17, 0x9C, 0x44, 0x69, 0xDA,
		0x1C, 0x61, 0x8C, 0x8F, 0xCA, 0x02, 0x21, 0x00, 0xD4, 0xC1, 0xE5, 0xB9, 0x91, 0xD4, 0x33, 0xCA,
		0x4A, 0x5C, 0x70, 0x05, 0x43, 0xAE, 0xB2, 0xBD, 0x57, 0xB2, 0x3F, 0x93, 0xFB, 0xE0, 0xC5, 0xF5,
		0x2C, 0x14, 0xCA, 0x81, 0xE1, 0xA3, 0x29, 0x95
};

static uint8_t spki2[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x28, 0xFC, 0x5F,
		0xE9, 0xAF, 0xCF, 0x5F, 0x4C, 0xAB, 0x3F, 0x5F, 0x85, 0xCB,
		0x21, 0x2F, 0xC1, 0xE9, 0xD0, 0xE0, 0xDB, 0xEA, 0xEE, 0x42,
		0x5B, 0xD2, 0xF0, 0xD3, 0x17, 0x5A, 0xA0, 0xE9, 0x89, 0xEA,
		0x9B, 0x60, 0x3E, 0x38, 0xF3, 0x5F, 0xB3, 0x29, 0xDF, 0x49,
		0x56, 0x41, 0xF2, 0xBA, 0x04, 0x0F, 0x1C, 0x3A, 0xC6, 0x13,
		0x83, 0x07, 0xF2, 0x57, 0xCB, 0xA6, 0xB8, 0xB5, 0x88, 0xF4,
		0x1F
};

static uint8_t ski3[]  = {
		0x3A, 0x7C, 0x10, 0x49, 0x09,
		0xB3, 0x7C, 0x71, 0x77, 0xDF,
		0x8F, 0x29, 0xC8, 0x00, 0xC7,
		0xC8, 0xE2, 0xB8, 0x10, 0x1E
};

static uint8_t sig3[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xD2, 0x45, 0x55, 0x83, 0xB0, 0x96, 0x52, 0xA5, 0x4A, 0x53, 0x78,
		0xC9, 0x47, 0xB5, 0xC5, 0xB1, 0x8F, 0x04, 0x03, 0xFA, 0x80, 0x23, 0x02, 0x3C, 0xCF, 0x2D, 0x26,
		0x32, 0xF7, 0x04, 0xE5, 0x69, 0x02, 0x21, 0x00, 0xF9, 0xAE, 0x91, 0xC3, 0xFC, 0x25, 0x4F, 0xFA,
		0xD1, 0xAB, 0x65, 0x11, 0x72, 0xF5, 0x26, 0x40, 0x80, 0x3D, 0x87, 0x6D, 0x3B, 0x88, 0x39, 0xF5,
		0xD6, 0xFC, 0x43, 0x37, 0xF0, 0x30, 0x70, 0xBB
};

static uint8_t spki3[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xdb, 0x04, 0xb3,
		0x42, 0xe6, 0x9a, 0xba, 0x32, 0xbc, 0xc3, 0x52, 0x77, 0xef,
		0xe0, 0xff, 0x13, 0x43, 0x8f, 0x02, 0xab, 0x60, 0x7c, 0x95,
		0x56, 0x0e, 0x9a, 0x84, 0xa6, 0x60, 0x65, 0x08, 0x25, 0x9c,
		0x50, 0x3f, 0x20, 0x24, 0xf8, 0x78, 0x84, 0x61, 0xf7, 0x17,
		0xb1, 0x0e, 0x4e, 0x49, 0x33, 0x37, 0x96, 0x80, 0x02, 0x15,
		0xf5, 0x12, 0x9a, 0xbb, 0x66, 0x89, 0x87, 0xf4, 0x77, 0x00,
		0x31
};

static uint8_t ski4[]  = {
		0x8B, 0xE8, 0xCA, 0x65, 0x79,
		0xF8, 0x27, 0x4A, 0xF2, 0x8B,
		0x7C, 0x8C, 0xF9, 0x1A, 0xB8,
		0x94, 0x3A, 0xA8, 0xA2, 0x60
};

static uint8_t sig4[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0xA8, 0xF3, 0xA6, 0xFA, 0xC8, 0x36, 0x4C, 0x3D, 0x84, 0x45, 0xFD,
		0xD0, 0x3E, 0xF9, 0xED, 0x7F, 0x86, 0xA8, 0xB8, 0x32, 0x93, 0xCC, 0x12, 0xDC, 0x9C, 0xC0, 0x2F,
		0x10, 0x1E, 0x53, 0x82, 0x1E, 0x02, 0x21, 0x00, 0xA9, 0x50, 0xB4, 0x8F, 0x4D, 0xE6, 0x4B, 0x26,
		0x7B, 0x3E, 0xFE, 0x39, 0xC2, 0x3A, 0x2A, 0xFC, 0xAE, 0x38, 0x7B, 0x27, 0x13, 0x39, 0x4F, 0x95,
		0xDB, 0x11, 0xB8, 0x32, 0xA1, 0xDE, 0x02, 0xD5
};

static uint8_t spki4[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xaf, 0x83, 0x08,
		0x05, 0x67, 0xe9, 0x37, 0x0f, 0x12, 0x26, 0x80, 0x25, 0x20,
		0xc0, 0xd4, 0x05, 0x78, 0x58, 0x59, 0x0e, 0xf8, 0x34, 0xe2,
		0xfa, 0x88, 0x02, 0x5d, 0x53, 0xb0, 0x76, 0x2c, 0xd8, 0xea,
		0xd6, 0xdb, 0xcb, 0xbd, 0xb5, 0x06, 0x9c, 0xc1, 0x43, 0xf1,
		0x45, 0x2a, 0xfa, 0x84, 0x34, 0x12, 0x45, 0x2c, 0xc9, 0x5d,
		0xce, 0x5c, 0xd2, 0x06, 0x8a, 0x0a, 0x48, 0x29, 0xba, 0x44,
		0x70
};

static uint8_t ski5[]  = {
		0xFB, 0x5A, 0xA5, 0x2E, 0x51,
		0x9D, 0x8F, 0x49, 0xA3, 0xFB,
		0x9D, 0x85, 0xD4, 0x95, 0x22,
		0x6A, 0x30, 0x14, 0xF6, 0x27
};

static uint8_t sig5[]  = {
		0x30, 0x46, 0x02, 0x21, 0x00, 0x9B, 0x9A, 0x2C, 0x33, 0xAB, 0xDD, 0x07, 0xD2, 0xC3, 0x9C, 0xA6,
		0x0B, 0x25, 0xB5, 0xE3, 0xAC, 0x95, 0xBC, 0x7F, 0x1D, 0xFD, 0xEE, 0xBA, 0xF8, 0x43, 0x4D, 0x09,
		0x58, 0xA0, 0xF0, 0x04, 0x86, 0x02, 0x21, 0x00, 0xE7, 0x39, 0xD8, 0x37, 0x19, 0xEF, 0x6D, 0xC7,
		0xB3, 0x03, 0xD4, 0xD9, 0x6A, 0xD7, 0xCC, 0x1C, 0x08, 0x41, 0x18, 0x87, 0x8C, 0x02, 0xE8, 0x35,
		0x0A, 0xC0, 0x52, 0x24, 0x52, 0xCE, 0x68, 0xD3
};

static uint8_t spki5[] = {
		0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
		0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
		0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x07, 0xf8, 0xa8,
		0xd3, 0x74, 0x8f, 0x1d, 0xb0, 0x92, 0xe5, 0x37, 0x17, 0x04,
		0x53, 0x46, 0x48, 0x9f, 0xf6, 0x1b, 0x96, 0x4a, 0x61, 0x4d,
		0xf5, 0x27, 0xfb, 0x63, 0x62, 0x3f, 0x18, 0x93, 0xca, 0xbc,
		0xc2, 0x1d, 0x40, 0x85, 0xbe, 0x3c, 0x5b, 0xdd, 0x08, 0xa1,
		0x49, 0xdd, 0x29, 0x56, 0xe8, 0xab, 0x6c, 0xf8, 0x7d, 0x2a,
		0x7b, 0x11, 0x82, 0x6b, 0xe3, 0x88, 0xbd, 0x9f, 0x2d, 0xd9,
		0x27
};

// AB4D910F55CAE71A215EF3CAFE3ACC45B5EEC154
static uint8_t private_key1[] = {
		0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0xD8, 0xAA, 0x4D,
		0xFB, 0xE2, 0x47, 0x8F, 0x86, 0xE8, 0x8A, 0x74, 0x51, 0xBF,
		0x07, 0x55, 0x65, 0x70, 0x9C, 0x57, 0x5A, 0xC1, 0xC1, 0x36,
		0xD0, 0x81, 0xC5, 0x40, 0x25, 0x4C, 0xA4, 0x40, 0xB9, 0xA0,
		0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
		0x07, 0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x73, 0x91, 0xBA,
		0xBB, 0x92, 0xA0, 0xCB, 0x3B, 0xE1, 0x0E, 0x59, 0xB1, 0x9E,
		0xBF, 0xFB, 0x21, 0x4E, 0x04, 0xA9, 0x1E, 0x0C, 0xBA, 0x1B,
		0x13, 0x9A, 0x7D, 0x38, 0xD9, 0x0F, 0x77, 0xE5, 0x5A, 0xA0,
		0x5B, 0x8E, 0x69, 0x56, 0x78, 0xE0, 0xFA, 0x16, 0x90, 0x4B,
		0x55, 0xD9, 0xD4, 0xF5, 0xC0, 0xDF, 0xC5, 0x88, 0x95, 0xEE,
		0x50, 0xBC, 0x4F, 0x75, 0xD2, 0x05, 0xA2, 0x5B, 0xD3, 0x6F,
		0xF5
};

// 47F23BF1AB2F8A9D26864EBBD8DF2711C74406EC
static uint8_t private_key2[] = {
0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x6c, 0xb2, 0xe9, 0x31, 0xb1, 0x12, 0xf2, 0x45, 0x54,
0xbc, 0xdc, 0xaa, 0xfd, 0x95, 0x53, 0xa9, 0x51, 0x9a, 0x9a, 0xf3, 0x3c, 0x02, 0x3b, 0x60, 0x84,
0x6a, 0x21, 0xfc, 0x95, 0x58, 0x31, 0x72, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x28, 0xfc, 0x5f, 0xe9, 0xaf, 0xcf, 0x5f,
0x4c, 0xab, 0x3f, 0x5f, 0x85, 0xcb, 0x21, 0x2f, 0xc1, 0xe9, 0xd0, 0xe0, 0xdb, 0xea, 0xee, 0x42,
0x5b, 0xd2, 0xf0, 0xd3, 0x17, 0x5a, 0xa0, 0xe9, 0x89, 0xea, 0x9b, 0x60, 0x3e, 0x38, 0xf3, 0x5f,
0xb3, 0x29, 0xdf, 0x49, 0x56, 0x41, 0xf2, 0xba, 0x04, 0x0f, 0x1c, 0x3a, 0xc6, 0x13, 0x83, 0x07,
0xf2, 0x57, 0xcb, 0xa6, 0xb8, 0xb5, 0x88, 0xf4, 0x1f,
};

// 3A7C104909B37C7177DF8F29C800C7C8E2B8101E
static uint8_t private_key3[] = {
0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x7f, 0x9e, 0x85, 0x85, 0x2e, 0x1d, 0x31, 0xf3, 0xa8,
0x92, 0x87, 0x87, 0xb9, 0x43, 0x73, 0xc5, 0xb2, 0xa7, 0x53, 0x5c, 0xe4, 0x3b, 0x60, 0x7c, 0xa0,
0x02, 0x51, 0x92, 0xaa, 0xf1, 0x81, 0xe1, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xdb, 0x04, 0xb3, 0x42, 0xe6, 0x9a, 0xba,
0x32, 0xbc, 0xc3, 0x52, 0x77, 0xef, 0xe0, 0xff, 0x13, 0x43, 0x8f, 0x02, 0xab, 0x60, 0x7c, 0x95,
0x56, 0x0e, 0x9a, 0x84, 0xa6, 0x60, 0x65, 0x08, 0x25, 0x9c, 0x50, 0x3f, 0x20, 0x24, 0xf8, 0x78,
0x84, 0x61, 0xf7, 0x17, 0xb1, 0x0e, 0x4e, 0x49, 0x33, 0x37, 0x96, 0x80, 0x02, 0x15, 0xf5, 0x12,
0x9a, 0xbb, 0x66, 0x89, 0x87, 0xf4, 0x77, 0x00, 0x31,
};

// 8BE8CA6579F8274AF28B7C8CF91AB8943AA8A260
static uint8_t private_key4[] = {
0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x22, 0x12, 0x63, 0x12, 0xef, 0xc9, 0x9f, 0x56, 0x47,
0x20, 0x22, 0xf6, 0x18, 0x26, 0xab, 0xab, 0x50, 0x73, 0x2b, 0x2e, 0xe8, 0xef, 0xb0, 0x18, 0x99,
0xf8, 0x89, 0x55, 0x58, 0xe3, 0x6e, 0x5f, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0xaf, 0x83, 0x08, 0x05, 0x67, 0xe9, 0x37,
0x0f, 0x12, 0x26, 0x80, 0x25, 0x20, 0xc0, 0xd4, 0x05, 0x78, 0x58, 0x59, 0x0e, 0xf8, 0x34, 0xe2,
0xfa, 0x88, 0x02, 0x5d, 0x53, 0xb0, 0x76, 0x2c, 0xd8, 0xea, 0xd6, 0xdb, 0xcb, 0xbd, 0xb5, 0x06,
0x9c, 0xc1, 0x43, 0xf1, 0x45, 0x2a, 0xfa, 0x84, 0x34, 0x12, 0x45, 0x2c, 0xc9, 0x5d, 0xce, 0x5c,
0xd2, 0x06, 0x8a, 0x0a, 0x48, 0x29, 0xba, 0x44, 0x70,
};


// FB5AA52E519D8F49A3FB9D85D495226A3014F627
static uint8_t private_key5[] = {
0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x62, 0xe0, 0xb2, 0x5d, 0x2d, 0xb0, 0x12, 0xf9, 0xa1,
0x23, 0x81, 0xe2, 0x09, 0xae, 0x49, 0x73, 0x45, 0x53, 0x5a, 0xe3, 0xcb, 0xc6, 0xf2, 0x2f, 0x2f,
0x4d, 0xa3, 0x2d, 0xf4, 0xad, 0x65, 0xdc, 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x07, 0xf8, 0xa8, 0xd3, 0x74, 0x8f, 0x1d,
0xb0, 0x92, 0xe5, 0x37, 0x17, 0x04, 0x53, 0x46, 0x48, 0x9f, 0xf6, 0x1b, 0x96, 0x4a, 0x61, 0x4d,
0xf5, 0x27, 0xfb, 0x63, 0x62, 0x3f, 0x18, 0x93, 0xca, 0xbc, 0xc2, 0x1d, 0x40, 0x85, 0xbe, 0x3c,
0x5b, 0xdd, 0x08, 0xa1, 0x49, 0xdd, 0x29, 0x56, 0xe8, 0xab, 0x6c, 0xf8, 0x7d, 0x2a, 0x7b, 0x11,
0x82, 0x6b, 0xe3, 0x88, 0xbd, 0x9f, 0x2d, 0xd9, 0x27,
};

static uint8_t nlri[] = {
		0x18, 0xC0, 0x00, 0x02
};

static struct spki_record *create_record(int ASN,
					 uint8_t *ski,
					 uint8_t *spki)
{
	u_int32_t i;
	struct spki_record *record = malloc(sizeof(struct spki_record));

	memset(record, 0, sizeof(*record));
	record->asn = ASN;
	memcpy(record->ski, ski, SKI_SIZE);
	memcpy(record->spki, spki, SPKI_SIZE);

	record->socket = NULL;
	return record;
}

static void init_openssl_first_val(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 1;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[0].ski		= ski1;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig1;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65536;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);

	spki_table_add_entry(&table, record1);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);*/
	//printf("%d,%f\n", as_hops, total);
}

static void validate_1_bgpsec_path_test(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 1;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[0].ski		= ski1;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig1;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65536;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);

	spki_table_add_entry(&table, record1);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops, total);
}

static void validate_2_bgpsec_path_test(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 2;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[1].ski		= ski1;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig1;

	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 64496;

	ss[0].ski		= ski2;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig2;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65536;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65537;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);
	record2 = create_record(65536, ski2, spki2);

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(record2);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	//printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);
	printf("%d,%f\n", as_hops, total);
}

static void validate_3_bgpsec_path_test(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;
	struct spki_record *record3;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 3;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[2].ski		= ski1;
	ss[2].sig_len		= 72;
	ss[2].signature		= sig1;

	sps[2].pcount		= 1;
	sps[2].conf_seg		= 0;
	sps[2].asn		= 64496;

	ss[1].ski		= ski2;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig2;

	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 65536;

	ss[0].ski		= ski3;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig3;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65537;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65538;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);
	record2 = create_record(65536, ski2, spki2);
	record3 = create_record(65537, ski3, spki3);

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);
	spki_table_add_entry(&table, record3);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(record2);
	free(record3);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	//printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);
	printf("%d,%f\n", as_hops, total);
}

static void validate_4_bgpsec_path_test(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;
	struct spki_record *record3;
	struct spki_record *record4;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 4;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[3].ski		= ski1;
	ss[3].sig_len		= 72;
	ss[3].signature		= sig1;

	sps[3].pcount		= 1;
	sps[3].conf_seg		= 0;
	sps[3].asn		= 64496;

	ss[2].ski		= ski2;
	ss[2].sig_len		= 72;
	ss[2].signature		= sig2;

	sps[2].pcount		= 1;
	sps[2].conf_seg		= 0;
	sps[2].asn		= 65536;

	ss[1].ski		= ski3;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig3;

	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 65537;

	ss[0].ski		= ski4;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig4;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65538;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65539;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);
	record2 = create_record(65536, ski2, spki2);
	record3 = create_record(65537, ski3, spki3);
	record4 = create_record(65538, ski4, spki4);

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);
	spki_table_add_entry(&table, record3);
	spki_table_add_entry(&table, record4);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(record2);
	free(record3);
	free(record4);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	//printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);
	printf("%d,%f\n", as_hops, total);
}

static void validate_5_bgpsec_path_test(int iterations)
{
	clock_t start, end;
	double total;

	struct spki_table table;
	struct spki_record *record1;
	struct spki_record *record2;
	struct spki_record *record3;
	struct spki_record *record4;
	struct spki_record *record5;

	enum bgpsec_rtvals result;
	unsigned int as_hops;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 5;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	ss[4].ski		= ski1;
	ss[4].sig_len		= 72;
	ss[4].signature		= sig1;

	sps[4].pcount		= 1;
	sps[4].conf_seg		= 0;
	sps[4].asn		= 64496;

	ss[3].ski		= ski2;
	ss[3].sig_len		= 72;
	ss[3].signature		= sig2;

	sps[3].pcount		= 1;
	sps[3].conf_seg		= 0;
	sps[3].asn		= 65536;

	ss[2].ski		= ski3;
	ss[2].sig_len		= 72;
	ss[2].signature		= sig3;

	sps[2].pcount		= 1;
	sps[2].conf_seg		= 0;
	sps[2].asn		= 65537;

	ss[1].ski		= ski4;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig4;

	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 65538;

	ss[0].ski		= ski5;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig5;

	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65539;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 65540;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);
	record2 = create_record(65536, ski2, spki2);
	record3 = create_record(65537, ski3, spki3);
	record4 = create_record(65538, ski4, spki4);
	record5 = create_record(65539, ski5, spki5);

	spki_table_add_entry(&table, record1);
	spki_table_add_entry(&table, record2);
	spki_table_add_entry(&table, record3);
	spki_table_add_entry(&table, record4);
	spki_table_add_entry(&table, record5);

	result = 0;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 2 AS hops.
	// (table = duplicate_record, record1, record2)
	start = clock();
	for (int i = 0; i < iterations; i++) {
		result = rtr_bgpsec_validate_as_path(bg, ss, sps, &table, as_hops);
	}
	end = clock();
	assert(result == BGPSEC_VALID);

	free(record1);
	free(record2);
	free(record3);
	free(record4);
	free(record5);
	free(ss);
	free(sps);
	free(bg);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	//printf("It took %f seconds to execute %d validation iterations.\n", total, iterations);
	printf("%d,%f\n", as_hops, total);
}

static void init_openssl_first_sig(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 0;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	as_hops = 0;

	// init the signature_seg and secure_path_seg structs.

	// The own AS information.
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65536;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, NULL, NULL, as_hops,
							own_sp, target_as,
							private_key1, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
}

static void generate_1_signature_test(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 0;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	as_hops = 0;

	// init the signature_seg and secure_path_seg structs.

	// The own AS information.
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65536;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, NULL, NULL, as_hops,
							own_sp, target_as,
							private_key1, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops + 1, total);
}

static void generate_2_signature_test(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 1;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	// AS 64496
	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 64496;

	ss[0].ski		= ski1;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig1;

	// AS 65536
	/*sps[0].pcount		= 1;*/
	/*sps[0].conf_seg		= 0;*/
	/*sps[0].asn		= 65536;*/

	/*ss[0].ski		= ski2;*/
	/*ss[0].sig_len		= 72;*/
	/*ss[0].signature		= sig2;*/

	// AS 65537
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 65536;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65537;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, ss, sps, as_hops,
							own_sp, target_as,
							private_key2, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops + 1, total);
}

static void generate_3_signature_test(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 2;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	// AS 64496
	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 64496;

	ss[1].ski		= ski1;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig1;

	// AS 65536
	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65536;

	ss[0].ski		= ski2;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig2;

	// AS 65537
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 65537;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65538;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, ss, sps, as_hops,
							own_sp, target_as,
							private_key3, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops + 1, total);
}

static void generate_4_signature_test(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 3;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	// AS 64496
	sps[2].pcount		= 1;
	sps[2].conf_seg		= 0;
	sps[2].asn		= 64496;

	ss[2].ski		= ski1;
	ss[2].sig_len		= 72;
	ss[2].signature		= sig1;

	// AS 65536
	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 65536;

	ss[1].ski		= ski2;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig2;
	//
	// AS 65537
	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65537;

	ss[0].ski		= ski3;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig3;

	// AS 65538
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 65538;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65539;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, ss, sps, as_hops,
							own_sp, target_as,
							private_key4, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops + 1, total);
}

static void generate_5_signature_test(int iterations)
{
	clock_t start, end;
	double total;

	unsigned int as_hops;
	unsigned int target_as;
	int sig_len;

	struct signature_seg *ss;
	struct secure_path_seg *sps;
	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	// Allocate memory for the BGPsec data with two AS hops.
	as_hops = 4;
	ss = malloc(sizeof(struct signature_seg) * as_hops);
	sps = malloc(sizeof(struct secure_path_seg) * as_hops);
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.
	
	// The order of the AS path must be reversed!

	// AS 64496
	sps[3].pcount		= 1;
	sps[3].conf_seg		= 0;
	sps[3].asn		= 64496;

	ss[3].ski		= ski1;
	ss[3].sig_len		= 72;
	ss[3].signature		= sig1;

	// AS 65536
	sps[2].pcount		= 1;
	sps[2].conf_seg		= 0;
	sps[2].asn		= 65536;

	ss[2].ski		= ski2;
	ss[2].sig_len		= 72;
	ss[2].signature		= sig2;
	//
	// AS 65537
	sps[1].pcount		= 1;
	sps[1].conf_seg		= 0;
	sps[1].asn		= 65537;

	ss[1].ski		= ski3;
	ss[1].sig_len		= 72;
	ss[1].signature		= sig3;
	
	sps[0].pcount		= 1;
	sps[0].conf_seg		= 0;
	sps[0].asn		= 65538;

	ss[0].ski		= ski4;
	ss[0].sig_len		= 72;
	ss[0].signature		= sig4;

	// AS 65538
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 65539;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65540;

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig = calloc(72, 1);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, ss, sps, as_hops,
							own_sp, target_as,
							private_key5, new_sig);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(ss);
	free(sps);
	free(own_sp);
	free(bg);
	free(new_sig);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	/*printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);*/
	printf("%d,%f\n", as_hops + 1, total);
}

static void originate_signature_test(int iterations)
{
	clock_t start, end;
	double total;


	struct spki_table table;
	struct spki_record *record1;

	unsigned int as_hops;
	unsigned int target_as;
	enum bgpsec_rtvals result;
	int sig_len;

	struct secure_path_seg *own_sp;
	struct bgpsec_data *bg;

	as_hops = 0;
	own_sp = malloc(sizeof(struct secure_path_seg));
	bg = malloc(sizeof(struct bgpsec_data));

	// init the signature_seg and secure_path_seg structs.

	// The own AS information.
	own_sp[0].pcount	= 1;
	own_sp[0].conf_seg	= 0;
	own_sp[0].asn		= 64496;

	// init the bgpsec_data struct.
	bg->alg_suite_id	= 1;
	bg->afi			= 1;
	bg->safi		= 1;
	bg->asn			= 0;
	bg->nlri_len		= 4;
	bg->nlri		= nlri;

	target_as = 65536;

	// init the SPKI table and store two router keys in it.
	spki_table_init(&table, NULL);
	record1 = create_record(64496, ski1, spki1);

	spki_table_add_entry(&table, record1);

	// Pass all data to the validation function. The result is either
	// BGPSEC_VALID or BGPSEC_NOT_VALID.
	// Test with 1 AS hop.

	result = 0;
	sig_len = 0;

	// TODO: allocation with magic numbers is bad...
	uint8_t *new_sig1 = calloc(72, 1);

	if (!new_sig1)
		assert(0);

	start = clock();
	for (int i = 0; i < iterations; i++) {
		sig_len = rtr_bgpsec_generate_signature(bg, NULL, NULL, as_hops,
							own_sp, target_as,
							private_key1, new_sig1);
		assert(sig_len > 0);
	}
	end = clock();

	assert(sig_len > 0);

	// Free all allocated memory.
	free(record1);
	free(own_sp);
	free(bg);
	free(new_sig1);
	spki_table_free(&table);

	total = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("It took %f seconds to execute %d signing iterations.\n", total, iterations);
}

#endif

int main(void)
{
#ifdef BGPSEC
	/*time_t rawtime;*/
	/*struct tm *timeinfo;*/

	/*time (&rawtime);*/
	/*timeinfo = localtime (&rawtime);*/
	/*printf ("Test started at: %s\n", asctime(timeinfo)); */

	/*printf ("Testing validation:\n"); */
	/*init_openssl_first_val(1);*/
	/*validate_1_bgpsec_path_test(1);*/
	/*validate_2_bgpsec_path_test(1);*/
	/*validate_3_bgpsec_path_test(1);*/
	/*validate_4_bgpsec_path_test(1);*/
	/*validate_5_bgpsec_path_test(1);*/
	/*printf ("Done.\n"); */

	/*printf ("Testing generating signature:\n"); */
	init_openssl_first_sig(1);
	generate_1_signature_test(1);
	generate_2_signature_test(1);
	generate_3_signature_test(1);
	generate_4_signature_test(1);
	generate_5_signature_test(1);
	/*printf ("Done.\n"); */

	/*time (&rawtime);*/
	/*timeinfo = localtime (&rawtime);*/
	/*printf ("Test ended at: %s", asctime(timeinfo)); */

	/*printf("Test successful\n");*/
#endif
	return EXIT_SUCCESS;
}
