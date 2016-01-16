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
require 'base64'

module CertLint
  class PEMLint
    def self.lint(pem, type)
      messages = []
      in_body = false
      last_line = false
      b64 = ''
      type.upcase!
      pem.force_encoding('BINARY')
      pem.split(/\n/).each do |line|
        line.strip!
        if in_body
          if line =~ /-END #{type}-/i
            if line !~ /^-/
              messages << 'W: PEM boundaries should not have whitespace or characters before the boundary start'
            end
            if line !~ /^-----END /i
              messages << "W: PEM boundaries should start with five '-' characters"
            end
            m = /(-+)(END #{type})(-+)/i.match(line)
            if m[1] != m[3]
              messages << 'E: PEM boundary must have same number of - at start and end'
            end
            if m[2].upcase != m[2]
              messages << 'W: PEM boundary should be in all caps'
            end
            if line != m[0]
              messages << 'E: PEM boundary should be alone on line'
            end
            break
          end

          # Not boundary
          if last_line
            messages << 'W: Only the last PEM encoded line may be less than 64 characters'
            last_line = false
          end
          if line.length > 64
            messages << 'W: PEM encoded lines must be 64 characters or less'
          end
          if line.length < 64
            last_line = true
          end
          if line !~ %r{\A[A-Za-z0-9/+=]+\z}
            messages << 'E: PEM encoded lines may only contain base64 characters'
          end
          b64 += line
          next
        end
        if line =~ /-BEGIN #{type}-/i
          in_body = true
          if line !~ /^-/
            messages << 'W: PEM boundaries should not have whitespace or characters before the boundary start'
          end
          if line !~ /^-----BEGIN /i
            messages << "W: PEM boundaries should start with five '-' characters"
          end
          m = /(-+)(BEGIN #{type})(-+)/i.match(line)
          if m[1] != m[3]
            messages << 'E: PEM boundary must have same number of - at start and end'
          end
          if m[2].upcase != m[2]
            messages << 'W: PEM boundary should be in all caps'
          end
          if line != m[0]
            messages << 'E: PEM boundary should be alone on line'
          end
        end
      end
      der = nil
      begin
        der = Base64.strict_decode64(b64)
      rescue ArgumentError
        messages << 'E: Incorrect base64 encoding'
      end
      [messages, der]
    end
  end
end
