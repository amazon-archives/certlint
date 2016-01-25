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
      # If we are busted, don't continue
      if messages.any? { |m| m.start_with? 'F:' }
        return messages
      end
      # Content is a SEQUENCE of GeneralSubtrees which is tagged
      # X.509 says "At least one of permittedSubtrees and excludedSubtrees components shall be present."
      subtree_count = 0
      OpenSSL::ASN1.decode(content).value.each do |subtree_parent|
        subtree_count += 1
        at_least_one = false
        subtrees = subtree_parent.value
        subtrees.each do |subtree|
          at_least_one = true
          genname = subtree.value.first
          messages += CertLint::GeneralNames.lint(genname, false)
        end
        unless at_least_one
          messages << 'E: NameConstriants must contain at least one subtree'
        end
      end
      if subtree_count == 0
        messages << 'E: NameConstraints must include either permitted or excluded Subtrees'
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('2.5.29.30', CertLint::ASN1Ext::NameConstraints)
