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
  class BasicConstraints < ASN1Ext
    @pdu = :BasicConstraints
    @critical_req = :optional

    def self.lint(content, cert, critical = false)
      messages = []
      messages += super(content, cert, critical)
      v = OpenSSL::X509::Extension.new('2.5.29.19', content, critical).value
      if v.include? 'CA:TRUE'
        unless critical
          messages << 'E: basicConstraints must be critical in CA certificates'
        end
      else
        begin
          a = OpenSSL::ASN1.decode(content)
        rescue OpenSSL::ASN1::ASN1Error
          messages << 'E: ASN.1 broken in BasicConstraints'
          return messages
        end
        if a.value.last.is_a? OpenSSL::ASN1::Integer
          messages << 'E: Must not include pathLenConstraint on certificates that are not CA:TRUE'
        end
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.19', CertLint::ASN1Ext::BasicConstraints)
