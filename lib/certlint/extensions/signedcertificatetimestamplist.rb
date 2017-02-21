#!/usr/bin/ruby -Eutf-8:utf-8
# encoding: UTF-8
# Copyright 2015-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License
# is located at
#
#   http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
require_relative 'asn1ext'
require 'openssl'
require 'date'

module CertLint
class ASN1Ext
  class SignedCertificateTimestampList < ASN1Ext
    def self.lint(content, cert, critical = false)
      messages = []
      if critical
        messages << 'E: SignedCertificateTimestampList must not be critical'
      end
      begin
        asn1 = OpenSSL::ASN1.decode content
        value = asn1.value
        offset = 0

        sct_list_len = unpack1(value[0..1], 'S>')
        offset += 2
        any_scts = false

        while offset < value.length
            sct_len = unpack1(value[offset..offset+1], 'S>')
            offset += 2

            messages.concat(parse_sct(value[offset..offset+sct_len-1]))
            offset += sct_len
            any_scts = true
        end

        messages << 'E: No SCTs were found in SignedCertificateTimestampList' if not any_scts
      rescue
        messages << 'E: Parse error occurred when parsing SignedCertificateTimestampList'
      end

      messages
    end

    private

    def self.unpack1(value, fmt)
        value.unpack(fmt)[0]
    end

    def self.parse_sct(sct_octets)
        messages = []
        offset = 0

        version = sct_octets[offset].ord
        offset += 1
        
        if version != 0
            messages << "I: SCT has a non-zero version value (#{version})"
        else
            # skip log ID
            offset += 32

            timestamp = DateTime.strptime(unpack1(sct_octets[offset..offset+7], 'Q>').to_s, '%Q')
            offset += 8
            messages << 'E: SCT timestamp is in the future' if timestamp > DateTime.now

            ext_len = unpack1(sct_octets[offset..offset+1], 'S>')
            offset += 2
            messages << 'E: SCT extension length is non-zero' if ext_len != 0 
            offset += ext_len

            # skip signature hash/signing algorithm
            offset += 2

            sig_len = unpack1(sct_octets[offset..offset+1], 'S>')
            offset += 2

            messages << 'E: SCT contains an incorrect signature length' if sig_len != (sct_octets.length - offset)
        end

        messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('1.3.6.1.4.1.11129.2.4.2', CertLint::ASN1Ext::SignedCertificateTimestampList)
