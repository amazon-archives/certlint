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
require 'rubygems'
require 'openssl'

module CertLint
class ASN1Ext
  def self.lint(content, _cert, critical = false)
    messages = []

    if !@pdu.nil?
      messages += CertLint.check_pdu(@pdu, content)
    else
      messages << 'E: No PDU defined'
    end
    if @critical_req != :optional
      if @critical_req != critical
        messages << "E: Extension criticality not allowed for #{self.to_s.split(':').last}"
      end
    end
    unless @critical_should.nil?
      if @critical_should != critical
        messages << "W: Extension should#{@critical_should ? '' : ' not'} be critical for #{self.to_s.split(':').last}"
      end
    end

    messages
  end
end
end
