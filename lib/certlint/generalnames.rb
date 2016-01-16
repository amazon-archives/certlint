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

module CertLint
  class GeneralNames
    # Allow RFC defying '*' and '_'
    DLABEL = '((?!-)[A-Za-z0-9*_-]{1,63}(?<!-))'
    FQDN = /\A(#{DLABEL}\.)*#{DLABEL}\z/

    # Email addresses don't have '*' or '_'
    EMAIL_SPLITTER = /\A(.*)@([^@]*)\z/
    EMAIL_DLABEL = '((?!-)[A-Za-z0-9-]{1,63}(?<!-))'
    EMAIL_DOMAIN = /\A(#{EMAIL_DLABEL}\.)*#{EMAIL_DLABEL}\z/
    EMAIL_ATOM = "[A-Za-z0-9!#\$%&'*+/=?^_`{|}~-]+"
    EMAIL_LOCAL_PART = /\A(#{EMAIL_ATOM})(\.#{EMAIL_ATOM})*\z/

    def self.lint(genname, allow_dnsname_wildcard = true)
      messages = []
      case genname.tag
      when 0 # OtherName
        # Sequence of oid, value
        # oid = genname.value.first.oid
        # No checks
      when 1 # RFC822Name
        orig_addr = genname.value
        if orig_addr.nil? || orig_addr.empty?
          messages << 'E: RFC822Name has empty value'
          return messages # Fatal to this entry
        end
        if orig_addr.include? "\0"
          messages << 'E: RFC822Name includes null'
        end
        addr = orig_addr.strip.chomp('.')
        if orig_addr != addr
          messages << 'E: Invalid padding in RFC822Name'
        end
        unless addr.include? '@'
          messages << 'E: RFC822Name without @'
          return messages # Fatal to this entry
        end
        p = EMAIL_SPLITTER.match(addr)
        local_part = p[1]
        domain_part = p[2]

        if domain_part.empty?
          messages << 'E: RFC822Name without domain'
        elsif EMAIL_DOMAIN !~ domain_part
          messages << 'E: RFC822Name with invalid domain'
        end
        if local_part.empty?
          messages << 'E: RFC822Name without local part'
        elsif local_part.include? '"'
          messages << 'W: RFC822Name with quoted local part'
        elsif EMAIL_LOCAL_PART !~ local_part
          messages << 'E: RFC822Name with invalid local part'
        end
      when 2 # DNSName
        orig_fqdn = genname.value
        if orig_fqdn.nil? || orig_fqdn.empty?
          messages << 'E: DNSName is empty'
          return messages # Fatal to this entry
        end
        if orig_fqdn.include? "\0"
          messages << 'E: DNSName includes null'
        end
        fqdn = orig_fqdn.strip.chomp('.')
        if orig_fqdn != fqdn
          messages << 'E: DNSName is not in preferred syntax'
        end
        unless FQDN.match(fqdn)
          messages << 'E: DNSName is not FQDN'
        end
        if fqdn.length > 253
          messages << 'E: FQDN in DNSName is too long'
        end
        unless allow_dnsname_wildcard
          if fqdn.include?('*')
            messages << 'E: Wildcard in FQDN'
          end
        end
      when 3 # X400Address
      when 4 # DirectoryName
      when 5 # EDIPartyName
      when 6 # URI
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << "E: GeneralName(#{genname.tag}) is empty"
        end
        # No checks
      when 7 # IPAddress
        case genname.value.length
        when 4, 16 # IPv4, IPv6
          # n = IPAddr.new_ntoh(genname.value)
        else
          messages << 'E: Invalid IP addess in SAN'
        end
      when 8 # RegisteredId
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << 'E: RegisteredId is empty'
        end
        # No checks
      else
        messages << 'E: Unknown type of name in subjectAltName'
      end
      messages
    end
  end
end
