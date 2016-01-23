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
  class SubjectAltName < ASN1Ext
    @pdu = :SubjectAltName
    @critical_req = :optional

    def self.lint(content, cert, critical = false)
      messages = []
      messages += super(content, cert, critical)
      if cert.subject.to_a.empty?
        unless critical
          messages << 'E: subjectAltName must be critical if subject is empty'
        end
      else
        if critical
          messages << 'W: subjectAltName should not be critical'
        end
      end
      # If we are busted, don't continue
      if messages.any? { |m| m.start_with? 'F:' }
        return messages
      end
      # Content is a SEQUENCE of GeneralName (which is explicitly tagged)
      at_least_one = false
      OpenSSL::ASN1.decode(content).value.each do |genname|
          at_least_one = true
          messages += CertLint::GeneralNames.lint(genname)
      end
      unless at_least_one
        messages << 'E: subjectAltName extension must include at least one name'
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.17', CertLint::ASN1Ext::SubjectAltName)
