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
    DLABEL = '((?!-)[A-Za-z0-9*_-]{1,63}(?<!-))'.freeze
    FQDN = /\A(#{DLABEL}\.)*#{DLABEL}\z/

    # Email addresses don't have '*' or '_'
    EMAIL_SPLITTER = /\A(.*)@([^@]*)\z/
    EMAIL_DLABEL = '((?!-)[A-Za-z0-9-]{1,63}(?<!-))'.freeze
    EMAIL_DOMAIN = /\A(#{EMAIL_DLABEL}\.)*#{EMAIL_DLABEL}\z/
    EMAIL_ATOM = "[A-Za-z0-9!#\$%&'*+/=?^_`{|}~-]+".freeze
    EMAIL_LOCAL_PART = /\A(#{EMAIL_ATOM})(\.#{EMAIL_ATOM})*\z/

    OTHERNAMES = {
      '1.2.410.200004.10.1.1' => nil,
      '1.3.6.1.2.1.32' => nil,
      '1.3.6.1.4.1.11801.2.1' => nil,
      '1.3.6.1.4.1.311.20.2.3' => nil,
      '1.3.6.1.4.1.311.25.1' => nil,
      '1.3.6.1.4.1.8321.1' => nil,
      '1.3.6.1.5.5.7' => nil,
      '1.3.6.1.5.5.7.8.5' => nil,
      '1.3.6.1.5.5.7.8.7' => nil,
      '2.16.76.1.3.2' => nil,
      '2.16.76.1.3.3' => nil,
      '2.16.76.1.3.4' => nil,
      '2.16.76.1.3.7' => nil,
      '2.16.76.1.3.8' => nil,
      '2.16.862.2.1' => nil,
      '2.16.862.2.2' => nil,
      '2.16.862.2.3' => nil,
      '2.16.862.2.4' => nil,
      '2.16.862.2.5' => nil,
      '2.16.862.2.6' => nil,
      '2.5.4.13' => nil,
      '2.5.5.5' => nil
    }

    def self.othername(value, is_constraint = false)
      messages = []

      # Sequence of oid, value
      oid = value.first.oid
      if OTHERNAMES.key?(oid)
        checker = OTHERNAMES[oid]
        case checker
        when nil
          messages << "I: No checks for OtherName type #{oid}"
        else
          messages << "I: Missing check for OtherName #{checker}"
        end
      else
        messages << "I: No checks for unknown OtherName type #{oid}"
      end
      messages
    end

    def self.rfc822name(orig_addr, is_constraint = false)
      messages = []
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
      if addr.include? '@'
        p = EMAIL_SPLITTER.match(addr)
        local_part = p[1]
        domain_part = p[2]
      else
        if !is_constraint
          messages << 'E: RFC822Name without @'
        end
        local_part = nil
        domain_part = addr
      end

      # From RFC 5280 section 4.2.1.10
      # To specify any address within a domain, the constraint is specified
      # with a leading period (as with URIs).  For example, ".example.com"
      # indicates all the Internet mail addresses in the domain "example.com",
      # but not Internet mail addresses on the host "example.com"
      if domain_part.start_with?('.')
        if !is_constraint
          messages << 'E: RFC822Name domain must not start with .'
        end
        domain_part = domain_part[1..-1]
      end

      if domain_part.empty?
        messages << 'E: RFC822Name without domain'
      elsif EMAIL_DOMAIN !~ domain_part
        messages << 'E: RFC822Name with invalid domain'
      end

      # Check for IDNs; https://tools.ietf.org/html/rfc5891#section-5.4
      domain_part.split('.').each do |label|
        next unless label.start_with? 'xn--'
        begin
          ulabel = SimpleIDN.to_unicode(label.encode("UTF-8"))
        rescue SimpleIDN::ConversionError
          messages << 'W: Bad IDN A-label in Email Address'
          next
        end
        if ulabel.respond_to? :unicode_normalize
          ulabel_nfc = ulabel.unicode_normalize(:nfc)
        else
          ulabel_nfc = ulabel.to_nfc
        end
        if ulabel != ulabel_nfc
          messages << 'E: Internationalized domain names must be in unicode normalization form C'
        end
      end

      # If the local part is nil (e.g. name constraint)
      # don't do checks on it
      if local_part.nil?
        return messages
      end

      if local_part.empty?
        # Empty can happen if the addr is "@example.com"
        messages << 'E: RFC822Name without local part'
      elsif local_part.include? '"'
        messages << 'W: RFC822Name with quoted local part'
      elsif EMAIL_LOCAL_PART !~ local_part
        messages << 'E: RFC822Name with invalid local part'
      end

      messages
    end

    def self.dnsname(orig_fqdn, is_constraint = false)
      messages = []
      if orig_fqdn.nil? || orig_fqdn.empty?
        messages << 'E: DNSName is empty'
        return messages # Fatal to this entry
      end
      if !orig_fqdn.is_a? String
        messages << 'F: DNSName is not a string'
        return messages # Fatal to this entry
      end
      if orig_fqdn.include? "\0"
        messages << 'E: DNSName includes null'
      end
      fqdn = orig_fqdn.strip.chomp('.')
      if orig_fqdn != fqdn
        messages << 'E: DNSName is not in preferred syntax'
      end
      # Name Constraints, like other dNSNames must not start with '.'
      if fqdn.start_with?('.')
        messages << 'E: DNSName must not start with .'
        fqdn = fqdn[1..-1]
      end
      unless FQDN.match(fqdn)
        messages << 'E: DNSName is not FQDN'
      end
      if fqdn.length > 253
        messages << 'E: FQDN in DNSName is too long'
      end
      if is_constraint
        if fqdn.include?('*')
          messages << 'E: Wildcard in FQDN'
        end
      end
      if fqdn.include?('_')
        messages << 'W: Underscore should not appear in DNS names'
      end
      # Check for IDNs; https://tools.ietf.org/html/rfc5891#section-5.4
      fqdn.split('.').each do |label|
        next unless label.start_with? 'xn--'
        begin
          ulabel = SimpleIDN.to_unicode(label.encode("UTF-8"))
        rescue SimpleIDN::ConversionError
          messages << 'W: Bad IDN A-label in DNS Name'
          next
        end
        if ulabel.respond_to? :unicode_normalize
          ulabel_nfc = ulabel.unicode_normalize(:nfc)
        else
          ulabel_nfc = ulabel.to_nfc
        end
        if ulabel != ulabel_nfc
          messages << 'E: Internationalized domain names must be in unicode normalization form C'
        end
      end
      messages
    end

    # set is_san to true for SubjectAltName entries, false for Name Contstraints
    def self.lint(genname, is_san = true)
      messages = []
      case genname.tag
      when 0 # OtherName
        messages += othername(genname.value, !is_san)
      when 1 # RFC822Name
        if !genname.value.is_a? String
          messages << 'F: RFC822Name is not a String'
          return messages # Fatal
        end
        messages += rfc822name(genname.value, !is_san)
      when 2 # DNSName
        if !genname.value.is_a? String
          messages << 'F: DNS Name is not a String'
          return messages # Fatal
        end
        messages += dnsname(genname.value, !is_san)
      when 3 # X400Address
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << "E: X400Address is empty"
          return messages # Fatal to this entry
        end
        messages << "I: No checks for X400Address"
      when 4 # DirectoryName
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << "E: DirectoryName is empty"
          return messages # Fatal to this entry
        end
        messages << "I: No checks for DirectoryName"
      when 5 # EDIPartyName
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << "E: EDIPartyName is empty"
          return messages # Fatal to this entry
        end
        messages << "I: No checks for EDIPartyName"
      when 6 # URI
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << "E: URI is empty"
          return messages # Fatal to this entry
        end
        messages << "I: No checks for URI"
        # No checks
      when 7 # IPAddress
        len = genname.value.length
        if is_san
          unless len == 4 || len == 16
            messages << 'E: Invalid IP address in SAN'
          end
        else # constraint
          unless len == 8 || len == 32
            messages << 'E: Invalid IP address in constraint'
          end
        end
      when 8 # RegisteredId
        orig = genname.value
        if orig.nil? || orig.empty?
          messages << 'E: RegisteredId is empty'
          return messages # Fatal to this entry
        end
        messages << "I: No checks for RegisteredId"
        # No checks
      else
        messages << 'E: Unknown type of name in subjectAltName'
      end
      messages
    end
  end
end
