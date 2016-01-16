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
  class NameConstraints < ASN1Ext
    @pdu = :NameConstraints
    # Explicitly violating RFC 5280 sect. 4.2.1.10
    @critical_req = :optional

    def self.lint(content, cert, critical = false)
      messages = []
      messages += super(content, cert, critical)
      # Content is a SEQUENCE of GeneralSubtrees which is tagged
      OpenSSL::ASN1.decode(content).value.each do |subtree_parent|
        subtrees = subtree_parent.value
        subtrees.each do |subtree|
          genname = subtree.value.first
          messages += CertLint::GeneralNames.lint(genname, false)
        end
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.30', CertLint::ASN1Ext::NameConstraints)
