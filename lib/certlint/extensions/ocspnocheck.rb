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
  class OcspNocheck < ASN1Ext
    @pdu = nil
    @critical_req = :optional
    @critical_should = false

    def self.lint(content, cert, critical = false)
      messages = []
      if content != "\x05\x00"
        messages << 'E: OCSP NoCheck extension must be null'
      end
      if critical != false
        messages << "W: Extension should not be critical for #{self}"
      end
      messages
    end
  end
end
end

CertLint::CertExtLint.register_handler('1.3.6.1.5.5.7.48.1.5', CertLint::ASN1Ext::OcspNocheck)
