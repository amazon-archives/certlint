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
  class CertExtLint
    UNSUPPORTED_EXTENSIONS = [
      '1.2.156.1.8888',
      '1.2.840.113533.7.65.0',
      '1.3.6.1.4.1.18332.19.1',
      '1.3.6.1.4.1.18332.42.6',
      '2.5.29.1',
      '2.5.29.10',
      '2.16.840.1.113732.4',
      '2.23.42.7.0'
    ]

    @@extension_handlers = {}

    def self.register_handler(oid, klass)
      if @@extension_handlers.key? oid
        fail 'Duplicate Extension registration'
      end
      @@extension_handlers[oid] = klass
    end

    # oid as string, critical as boolean, value as der, cert as OpenSSL::X509::Certificate
    def self.lint(oid, value, cert, critical = false)
      messages = []

      if @@extension_handlers.key? oid
        messages += @@extension_handlers[oid].lint(value, cert, critical)
        return messages
      end

      if critical
        messages << "E: Opaque or unknown extension (#{oid}) marked as critical"
      end

      if UNSUPPORTED_EXTENSIONS.include? oid
        messages << "W: Extension #{oid} is treated as opaque extension"
        return messages
      end

      if oid.start_with? '2.16.840.1.113730.'
        messages << "W: Deprecated Netscape extension #{oid} treated as opaque extension"
        return messages
      end
      if oid.start_with? '1.3.6.1.4.1.311.'
        messages << "W: Microsoft extension #{oid} treated as opaque extension"
        return messages
      end

      messages << "W: Unknown Extension: #{oid}"

      messages
    end
  end
end
