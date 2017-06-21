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

module CertLint
class ASN1Ext
  class KeyUsage < ASN1Ext
    @pdu = :KeyUsage
    @critical_req = :optional
    @critical_should = true

    def self.lint(content, cert, critical = false)
      messages = []
      messages += super(content, cert, critical)

      v = OpenSSL::X509::Extension.new('2.5.29.15', content, critical).value.split(',').map(&:strip)

      pk = nil
      begin
        pk = cert.public_key
      rescue OpenSSL::PKey::PKeyError
      rescue OpenSSL::X509::CertificateError
        # Do nothing; will error below
      end

      if pk.nil?
        messages << 'E: Unable to parse public key'
      elsif pk.is_a? OpenSSL::PKey::RSA
        allowed = [
          'Digital Signature',
          'Non Repudiation',
          'Key Encipherment',
          'Data Encipherment',
          'Certificate Sign',
          'CRL Sign'
        ]
        if v.any? { |u| !allowed.include? u }
          messages << "E: Unallowed key usage for RSA public key (#{(v-allowed).join(', ')})"
        end
        if (v.include? 'Certificate Sign') || (v.include? 'CRL Sign')
          if (v.include? 'Key Encipherment') || (v.include? 'Data Encipherment')
            messages << 'W: Encipherment usage should not be mixed with Certificate/CRL signing'
          end
        end
      elsif pk.is_a? OpenSSL::PKey::DSA
        allowed = [
          'Digital Signature',
          'Non Repudiation',
          'Certificate Sign',
          'CRL Sign'
        ]
        if v.any? { |u| !allowed.include? u }
          messages << "E: Unallowed key usage for DSA public key (#{(v-allowed).join(', ')})"
        end
      elsif pk.is_a? OpenSSL::PKey::EC
        # A little complex as this can be either for ECDSA or ECDH
        allowed = [
          'Digital Signature',
          'Non Repudiation',
          'Key Agreement',
          'Certificate Sign',
          'CRL Sign',
          'Encipher Only',
          'Decipher Only'
        ]
        if v.any? { |u| !allowed.include? u }
          messages << "E: Unallowed key usage for EC public key (#{(v-allowed).join(', ')})"
        end

        if (v.include? 'Encipher Only') || (v.include? 'Decipher Only')
          unless v.include? 'Key Agreement'
            messages << 'E: Key agreement required with encipher only or decipher only'
          end
        end
        if (v.include? 'Encipher Only') && (v.include? 'Decipher Only')
          messages << 'E: Encipher Only and Decipher Only must not both be set'
        end

        if (v.include? 'Certificate Sign') || (v.include? 'CRL Sign')
          if (v.include? 'Encipher Only') || (v.include? 'Decipher Only') || (v.include? 'Key Agreement')
            messages << 'W: Key agreement should not be included with Certificate/CRL Signing'
          end
        end
      elsif pk.is_a? OpenSSL::PKey::DH
        allowed = [
          'Key Agreement',
          'Encipher Only',
          'Decipher Only'
        ]
        if v.any? { |u| !allowed.include? u }
          messages << "E: Unallowed key usage for DH public key (#{(v-allowed).join(', ')})"
        end
        unless v.include? 'Key Agreement'
          messages << 'E: Key Agreement must be included for DH public keys'
        end
        if (v.include? 'Encipher Only') && (v.include? 'Decipher Only')
          messages << 'E: Encipher Only and Decipher Only must not both be set'
        end
      else
        messages << "I: Key usages not checked for #{cert.public_key.class}"
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.15', CertLint::ASN1Ext::KeyUsage)
