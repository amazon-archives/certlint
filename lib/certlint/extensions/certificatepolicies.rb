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

# Load unf if we don't have native methods
unless String.method_defined?(:unicode_normalize) || String.method_defined?(:to_nfc)
  require 'unf'
end

module CertLint
class ASN1Ext
  class CertificatePolicies < ASN1Ext
    RFC6818_DATE = Time.utc(2013,1,1,0,0,0)

    @pdu = :CertificatePolicies
    @critical_req = :optional

    def self.lint(content, cert, critical = false)
      messages = []
      messages += super(content, cert, critical)

      # If we are busted, don't continue
      if messages.any? { |m| m.start_with? 'F:' }
        return messages
      end

      # the qualifier in PolicyQualifierInfo is
      # defined as ANY, so we have to manually check
      OpenSSL::ASN1.decode(content).value.each do |policy_information|
        if !policy_information.is_a? OpenSSL::ASN1::Sequence
          messages << "E: PolicyInformation is not a sequence"
          next
        end

        # policiyQualifiers are optional
        pq = policy_information.value[1]
        if pq.nil?
          next
        end
        # policiyQualifiers is a sequence of
        # PolicyQualifier Info
        pq.value.each do |pqi|
          if !pqi.is_a? OpenSSL::ASN1::Sequence
            messages << "E: PolicyQualifierInfo is not a sequence"
            next
          end

          qualid = pqi.value[0].oid
          q = pqi.value[1].to_der
          case qualid
          when '1.3.6.1.5.5.7.2.1'
            messages += CertLint.check_pdu(:CPSuri, q)
          when '1.3.6.1.5.5.7.2.2'
            new_messages = CertLint.check_pdu(:UserNotice, q)
            messages += new_messages
            if new_messages.any? { |m| m.start_with? 'F:' }
              next
            end
            user_notice = pqi.value[1].value
            if user_notice[0].is_a? OpenSSL::ASN1::Sequence
              # noticeRef
              messages << 'W: Certificate Policies should not contain notice references'
              user_notice.shift
            end
            if user_notice[0].nil?
              next
            end
            # See RFC 6818 section 3 which updates RFC 5280, as of Jan 2013
            # user_notice[0] is explicitText
            txt = ''
            if user_notice[0].tag == 12 # UTF8String
              txt = user_notice[0].value.force_encoding('UTF-8')
            elsif user_notice[0].tag == 12 # BMPString
              txt = user_notice[0].value.encode('UTF-8', 'UTF-16BE')
            elsif user_notice[0].tag == 22 # IA5String
              if cert.not_before > RFC6818_DATE
                messages << 'E: Certificate Policy explicit text must not be IA5String'
              end
              txt = user_notice[0].value.encode('UTF-8', 'ISO-8859-1')
            elsif user_notice[0].tag == 26 # VisibleString
              txt = user_notice[0].value.encode('UTF-8', 'ISO-8859-1')
            end
            txt_nfc = nil
            if txt.respond_to? :unicode_normalize
              txt_nfc = txt.unicode_normalize(:nfc)
            else
              txt_nfc = txt.to_nfc
            end
            if txt != txt_nfc
              messages << 'W: Certificate policy explicit text should be in unicode normalization form C'
            end
            if txt.codepoints.any? { |c| (c >= 0x00 && c <= 0x1f) || (c >= 0x7f && c <= 0x9f) }
              messages << 'W: Certificate policy explicit text should not contain control characters'
            end
          else
            messages << 'E: Bad policy qualifier id'
          end
        end
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.32', CertLint::ASN1Ext::CertificatePolicies)
