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
  class CertificatePolicies < ASN1Ext
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
      begin
        a = OpenSSL::ASN1.decode(content)
      rescue OpenSSL::ASN1::ASN1Error
        messages << 'E: ASN.1 broken in CertificatePolicies'
        return messages
      end
      a.value.each do |policy_information|
        # policiyQualifiers are optional
        pq = policy_information.value[1]
        if pq.nil?
          next
        end
        # policiyQualifiers is a sequence of
        # PolicyQualifier Info
        pq.value.each do |pqi|
          qualid = pqi.value[0].oid
          q = pqi.value[1].to_der
          case qualid
          when '1.3.6.1.5.5.7.2.1'
            messages += CertLint.check_pdu(:CPSuri, q)
          when '1.3.6.1.5.5.7.2.2'
            messages += CertLint.check_pdu(:UserNotice, q)
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
