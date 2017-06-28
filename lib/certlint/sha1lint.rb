#!/usr/bin/ruby -Eutf-8:utf-8
# encoding: UTF-8
# Copyright 2017 Matt Palmer <mpalmer@hezmatt.org>. All Rights Reserved.
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

module CertLint
  class SHA1Lint
    def self.lint(der)
      messages = []

      if CertLint.sha1_collision?(der.to_s)
        messages << 'E: SHA1 collision attempt detected'
      end

      messages
    end
  end
end
