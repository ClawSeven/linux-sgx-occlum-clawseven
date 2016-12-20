/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _UTIL_ST_H_
#define _UTIL_ST_H_

#include "se_cdefs.h"
#include "se_memcpy.h"
#include <stdio.h>


#define USAGE_STRING \
    "Usage: sgx_sign <commands> [options] file...\n"\
    "Commands:\n"\
    "   sign                Sign the enclave using the private key\n"\
    "   gendata             Generate enclave signing material to be signed\n"\
    "   catsig              Generate the signed enclave with the input signature file, the\n"\
    "                       public key and the enclave signing material\n"\
    "Options:\n"\
    "   -enclave            Specify the enclave file to be signed\n"\
    "                       It is a required option for the three commands\n"\
    "   -key                Specify the key file\n"\
    "                       It is a required option for \"sign\" and \"catsig\"\n"\
    "   -config             Specify the configuration for the enclave\n"\
    "   -out                Specify the output file\n"\
    "                       It is a required option for the three commands\n"\
    "   -sig                Specify the signature file for the enclave signing material\n" \
    "                       It is a required option for \"catsig\"\n"\
    "   -unsigned           Specify the enclave signing material generated by \"gendata\"\n" \
    "                       It is a required option for \"catsig\"\n" \
    "   -ignore-rel-error   By default, sgx_sign provides an error for enclaves with\n" \
    "                       text relocations. You can ignore the error and continue signing\n" \
    "                       by providing this option. But it is recommended you eliminate the\n" \
    "                       text relocations instead of bypassing the error with this option.\n"

// General error message
#define OVERALL_ERROR                       "Error happened while signing the enclave.\n"
#define KEY_FORMAT_ERROR                    "Key file format is not correct.\n"
#define XML_FORMAT_ERROR                    "Configure file format is not correct.\n"
#define NO_MEMORY_ERROR                     "Out of memory.\n"
#define OPEN_FILE_ERROR                     "Failed to open file \"%s\".\n"
#define READ_FILE_ERROR                     "Failed to read file \"%s\".\n"
#define WRITE_FILE_ERROR                    "Failed to write file \"%s\".\n"

// error message for measure_enclave()
#define OUT_OF_EPC_ERROR                    "The required memory is too large. Please check TCSNum/HeapMaxSize/StackMaxSize.\n"
#define META_VERSION_ERROR                  "Metadata version is mismatched between uRTS and sgx_sign.\n"
#define INVALID_ENCLAVE_ERROR               "The input enclave file is not correct.\n"
#define REQUIRED_ENCLAVE_SIZE               "The required memory is 0x%x.\n"
#define TEXT_REL_ERROR                      "The enclave image has text relocations.\n"

// error message for fill_enclave_css()
#define UNSIGNED_FILE_ERROR                 "The unsigned file \"%s\" is not correct.\n"
#define UNSIGNED_FILE_XML_MISMATCH          "The unsigned file content doesn't match the configuration file.\n"

// error message for create_signature()
#define SIG_FILE_ERROR                      "The signature file \"%s\" is not correct.\n"

// error message for cmdline_parse()
#define LACK_PARA_ERROR                     "Lack of parameters.\n"
#define UNREC_CMD_ERROR                     "Cannot recognize the command \"%s\".\nCommand \"sign/gendata/catsig\" is required.\n"
#define REPEAT_OPTION_ERROR                 "Repeatly specified \"%s\" option.\n"
#define INVALID_FILE_NAME_ERROR             "The File name is not correct for \"%s\" option.\n"
#define LACK_REQUIRED_OPTION_ERROR          "Option \"%s\" is required for the command \"%s\".\n"
#define GIVE_INVALID_OPTION_ERROR           "Option \"%s\" is invalid for the command \"%s\".\n"

// error message for generate_output()
#define LACK_PRI_KEY_ERROR                  "Private key is required for the \"sign\" command.\n"
#define LACK_PUB_KEY_ERROR                  "Public key is required for the \"catsig\" command.\n"

// error message for main()
#define INIT_IPP_LIBRARY_ERROR              "Failed to initialize the IPP library.\n"
#define ENCLAVE_ALREADY_SIGNED_ERROR        "The enclave has been signed already.\n"
#define SUCCESS_EXIT                        "Succeed.\n"

// error message for traverser_parameter()
#define LACK_VALUE_FOR_ELEMENT_ERROR        "No value for the element \"%s\".\n"
#define INVALID_VALUE_FOR_ELEMENT_ERROR     "Invalid value for the element\"%s\".\n"
#define UNREC_ELEMENT_ERROR                 "Element is not recognized - \"%s\".\n"
#define REPEATED_DEFINE_ERROR               "Defined \"%s\" too many times.\n"
#define VALUE_OUT_OF_RANGE_ERROR            "The value of \"%s\" is out of range.\n"

// error message for modify_metadata()
#define SET_STACK_SIZE_ERROR                "Stack size setting is not correct.\n"
#define SET_HEAP_SIZE_ERROR                 "Heap size setting is not correct.\n"
#define SET_HW_LE_ERROR                     "Conflicting setting between the 'HW' and 'LaunchKey'.\n"

// error message for compare_enclave()
#define PDB_PATH_ERROR                      "The two enclaves' pdb path are not equal. The pdb path of \"%s\" is \"%s\", while the pdb path of \"%s\" is \"%s\".\n"
#include <stdint.h>
#include <iostream>

#ifdef __cplusplus
extern "C" {
#endif

size_t get_file_size(const char *filename);
bool read_file_to_buf(const char *filename, uint8_t *buffer, size_t bsize);
bool write_data_to_file(const char *filename, std::ios_base::openmode mode, uint8_t *buf, size_t bsize, long offset = 0);
bool copy_file(const char *source_path, const char *dest_path);

#ifdef __cplusplus
}
#endif

#endif
