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
require 'simpleidn'
require 'public_suffix'
PUBLIC_SUFFIX_LIST_DAT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'data', 'public_suffix_list.dat'))
if PublicSuffix::List.respond_to?(:private_domains=)
  PublicSuffix::List.private_domains = false
  PublicSuffix::List.default_definition = File.new(PUBLIC_SUFFIX_LIST_DAT, "r:utf-8")
else
  PublicSuffix::List.default = PublicSuffix::List.parse(File.read(PUBLIC_SUFFIX_LIST_DAT, encoding: "utf-8"), private_domains: false)
end

module CertLint
  class IANANames
    @iana_tlds = nil
    @special_domains = nil
    def self.load_domains
      @iana_tlds = {}
      @special_domains = []
      spec_domains = {}

      # Load public domains from current root zone and from
      # ICANN's new gtlds list (some new gtlds are approved
      # but not yet in the root zone)

      datadir = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', 'data'))

      # from https://newgtlds.icann.org/newgtlds.csv
      File.open(File.join(datadir,'newgtlds.csv'), 'r:utf-8') do |f|
        lineno = 0
        f.each_line do |l|
          lineno += 1
          if lineno < 3
            next
          end
          @iana_tlds[l.split(',').first.downcase] = :public
        end
      end

      # from http://www.internic.net/domain/root.zone
      File.open(File.join(datadir,'root.zone')) do |f|
        f.each_line do |l|
          owner = l.split(/\s+/).first.downcase
          tld = owner.split('.').last
          next if tld.nil?
          @iana_tlds[tld] = :public
        end
      end

      # from http://www.iana.org/assignments/special-use-domain-names/special-use-domain.csv
      File.open(File.join(datadir, 'special-use-domain.csv')) do |f|
        lineno = 0
        f.each_line do |l|
          lineno += 1
          if lineno < 2
            next
          end
          dom = l.split(',').first.chomp('.')
          unless dom.include? '.'
            @iana_tlds[dom] = :special
          end
          spec_domains[dom] = true
        end
      end
      @special_domains = spec_domains.keys.sort.map { |d| '.' + d }
    end

    def self.lint(fqdn)
      if @iana_tlds.nil?
        load_domains
      end
      messages = []

      # FQDNs are case insensitive
      # Normalize to lower case
      fqdn.downcase!

      # We can't do much with domains that are not fqdns
      unless fqdn.include? '.'
        messages << 'E: Unqualified domain name'
        return messages
      end

      tld = fqdn.split('.').last
      tld_type = @iana_tlds[tld]
      if tld_type.nil?
        messages << 'E: Unknown TLD'
        return messages
      elsif tld_type == :special
        if tld == 'onion'
          messages << 'I: Tor Service Descriptor in SAN'
        else
          messages << 'W: Special name'
        end
        return messages
      elsif tld_type != :public
        messages << 'E: Unknown type of TLD'
      end

      if ('.' + fqdn).end_with?(*@special_domains)
        messages << 'E: FQDN under reserved or special domain'
      end

      if fqdn.include? 'xn--'
        begin
          u = SimpleIDN.to_unicode(fqdn.encode("UTF-8"))
        rescue SimpleIDN::ConversionError
          messages << 'W: Bad IDN A-label in DNS Name'
          u = fqdn
        end
      else
        u = fqdn
      end

      d = nil
      begin
        d = PublicSuffix.parse(u)
      rescue PublicSuffix::DomainInvalid
        # We got this far, so assume this is a new tld
        # Check for wildcard rule
        parts = fqdn.split('.')
        if parts.count == 2 && (parts[0].include? '*')
          messages << 'E: Wildcard to immediate left of public suffix'
        end
      rescue PublicSuffix::DomainNotAllowed
        messages << 'W: Domain is bare public suffix'
      end
      unless d.nil?
        if !d.sld.nil? && d.sld.include?('*')
          messages << 'E: Wildcard to immediate left of public suffix'
        end
        if !d.domain.nil? && d.domain.include?('_')
          messages << 'W: Underscore in base domain'
        end
      end
      messages
    end
  end
end
