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
require_relative 'dn_attrs'
require 'simpleidn'
# Load unf if we don't have native methods
unless String.method_defined?(:unicode_normalize) || String.method_defined?(:to_nfc)
  require 'unf'
end


module CertLint
  # Validate DirectoryNames
  class NameLint
    # ISO 3166-1 alpha-2 countries plus 'XX'
    COUNTRIES = [
      'AD', 'AE', 'AF', 'AG', 'AI', 'AL', 'AM', 'AN', 'AO', 'AQ', 'AR',
      'AS', 'AT', 'AU', 'AW', 'AX', 'AZ', 'BA', 'BB', 'BD', 'BE', 'BF', 'BG',
      'BH', 'BI', 'BJ', 'BL', 'BM', 'BN', 'BO', 'BQ', 'BR', 'BS', 'BT', 'BV',
      'BW', 'BY', 'BZ', 'CA', 'CC', 'CD', 'CF', 'CG', 'CH', 'CI', 'CK', 'CL',
      'CM', 'CN', 'CO', 'CR', 'CU', 'CV', 'CW', 'CX', 'CY', 'CZ', 'DE', 'DJ',
      'DK', 'DM', 'DO', 'DZ', 'EC', 'EE', 'EG', 'EH', 'ER', 'ES', 'ET', 'FI',
      'FJ', 'FK', 'FM', 'FO', 'FR', 'GA', 'GB', 'GD', 'GE', 'GF', 'GG', 'GH',
      'GI', 'GL', 'GM', 'GN', 'GP', 'GQ', 'GR', 'GS', 'GT', 'GU', 'GW', 'GY',
      'HK', 'HM', 'HN', 'HR', 'HT', 'HU', 'ID', 'IE', 'IL', 'IM', 'IN', 'IO',
      'IQ', 'IR', 'IS', 'IT', 'JE', 'JM', 'JO', 'JP', 'KE', 'KG', 'KH', 'KI',
      'KM', 'KN', 'KP', 'KR', 'KW', 'KY', 'KZ', 'LA', 'LB', 'LC', 'LI', 'LK',
      'LR', 'LS', 'LT', 'LU', 'LV', 'LY', 'MA', 'MC', 'MD', 'ME', 'MF', 'MG',
      'MH', 'MK', 'ML', 'MM', 'MN', 'MO', 'MP', 'MQ', 'MR', 'MS', 'MT', 'MU',
      'MV', 'MW', 'MX', 'MY', 'MZ', 'NA', 'NC', 'NE', 'NF', 'NG', 'NI', 'NL',
      'NO', 'NP', 'NR', 'NU', 'NZ', 'OM', 'PA', 'PE', 'PF', 'PG', 'PH', 'PK',
      'PL', 'PM', 'PN', 'PR', 'PS', 'PT', 'PW', 'PY', 'QA', 'RE', 'RO', 'RS',
      'RU', 'RW', 'SA', 'SB', 'SC', 'SD', 'SE', 'SG', 'SH', 'SI', 'SJ', 'SK',
      'SL', 'SM', 'SN', 'SO', 'SR', 'SS', 'ST', 'SV', 'SX', 'SY', 'SZ', 'TC',
      'TD', 'TF', 'TG', 'TH', 'TJ', 'TK', 'TL', 'TM', 'TN', 'TO', 'TR', 'TT',
      'TV', 'TW', 'TZ', 'UA', 'UG', 'UM', 'US', 'UY', 'UZ', 'VA', 'VC', 'VE',
      'VG', 'VI', 'VN', 'VU', 'WF', 'WS', 'YE', 'YT', 'ZA', 'ZM', 'ZW', 'XX'
    ]

    RDN_ATTRIBUTES = {
      # COSINE / RFC 4524
      '0.9.2342.19200300.100.1.1' => [:DirectoryString, 256], # UID
      '0.9.2342.19200300.100.1.4' => [:DirectoryString, 2048], # info
      '0.9.2342.19200300.100.1.25' => [:DomainComponent, :DNS], # DC
      # PKCS#9 / RFC 2985
      '1.2.840.113549.1.9.1' => :EmailAddress, # emailAddress
      '1.2.840.113549.1.9.2' => [:PKCS9String, :PKCS9], # unstructuredName
      '1.2.840.113549.1.9.8' => [:DirectoryString, 255], # unstructuredAddress
      # CA/Browser Forum EV Gudelines
      '1.3.6.1.4.1.311.60.2.1.1' => :X520LocalityName, # jurisdictionOfIncorporationLocalityName
      '1.3.6.1.4.1.311.60.2.1.2' => :X520StateOrProvinceName, # jurisdictionOfIncorporationStateOrProvinceName
      '1.3.6.1.4.1.311.60.2.1.3' => [:X520countryName, :Country], # jurisdictionOfIncorporationCountryName
      # Attributes are taken from RFC 5280 if possible
      # Otherwise from X.520 using Annex C for upper bounds
      '2.5.4.3' => :X520CommonName, # CN
      '2.5.4.4' => :X520name, # SN
      '2.5.4.5' => :X520SerialNumber, # serialNumber
      '2.5.4.6' => [:X520countryName, :Country], # C
      '2.5.4.7' => :X520LocalityName, # L
      '2.5.4.8' => :X520StateOrProvinceName, # ST
      '2.5.4.9' => :X520StateOrProvinceName, # streetAddress
      '2.5.4.10' => :X520OrganizationName, # O
      '2.5.4.11' => :X520OrganizationalUnitName, # OU
      '2.5.4.12' => :X520Title, # title
      '2.5.4.13' => [:DirectoryString, 1024], # description
      '2.5.4.15' => :X520LocalityName, # businessCategory
      '2.5.4.16' => :PostalAddress, # postalAddress
      '2.5.4.17' => [:DirectoryString, 40], # postalCode
      '2.5.4.18' => [:DirectoryString, 40], # postOfficeBox
      '2.5.4.20' => :OrganizationalUnitName, # telephoneNumber
      '2.5.4.41' => :X520name, # name
      '2.5.4.42' => :X520name, # GN
      '2.5.4.43' => :X520name, # initials
      '2.5.4.45' => :UniqueIdentifier,
      '2.5.4.46' => :X520dnQualifier, # dnQualifier
      '2.5.4.51' => :DirectoryString, # houseIdentifier
      '2.5.4.54' => :DirectoryString, # dmdName
    }

    # List of attributes that are known deprecated
    DEPRECATED_ATTRIBUTES = [
      '1.2.840.113549.1.9.1' # EmailAddress, Per RFC 5280 section 4.1.2.6
    ]

    DLABEL = /\A((?!-)[A-Za-z0-9-]{1,63}(?<!-))\z/

    def self.attr_name(oid)
      name = oid
      s = CertLint::DNAttrs::ATTRS[oid]
      unless s.nil?
        name = s
      end
      name
    end

    def self.lint(name)
      messages = []
      unless name.is_a? OpenSSL::X509::Name
        return nil
      end

      dn = OpenSSL::ASN1.decode(name.to_der)

      attr_types = []
      # DN is a SEQUENCE OF (SET OF (Attributes))
      dn.value.each do |rdn|
        if rdn.value.length > 1
          messages << 'W: Multiple attributes in a single RDN in the subject Name'
        end
        rdn.value.each do |attr|
          attr_messages = []

          type = attr.value[0].oid
          attr_types << type
          value = attr.value[1]
          attrname = attr_name(type)

          validator = nil
          pdu = RDN_ATTRIBUTES[type]
          if pdu.nil?
            attr_messages << "W: Name has unknown attribute #{attrname}"
            messages += attr_messages
            next
          end
          if pdu.is_a? Array
            validator = pdu[1]
            pdu = pdu[0]
          end

          if DEPRECATED_ATTRIBUTES.include? type
            attr_messages << "W: Name has deprecated attribute #{attrname}"
          end

          attr_messages += CertLint.check_pdu(pdu, value.to_der)
          if attr_messages.any? { |m| m.start_with? 'F:' }
            messages += attr_messages
            next
          end

          # If explicitly tagged, then nothing we can really check
          # (no known attributes use explicitly tagged values)
          if value.tag_class != :UNIVERSAL
            messages += attr_messages
            next
          end

          # Warn about strings that allow escape sequences and
          # Unicode strings that are not UTF-8
          check_padding = false
          tag = value.tag
          case tag
          when 12 # UTF8
            value = value.value
            check_padding = true
          when 18 # Numeric (7-bit)
            value = value.value
            check_padding = true
          when 19 # Printable (7-bit)
            value = value.value
            check_padding = true
          when 20 # Teletex (7-bit)
            value = value.value
            check_padding = true
            attr_messages << "W: #{attrname} is using deprecated TeletexString"
          when 21 # Videotex
            value = value.value
            check_padding = true
            attr_messages << "W: #{attrname} is using deprecated VideoexString"
          when 22 # IA5
            value = value.value
            check_padding = true
          when 25 # Graphic
            value = value.value
            check_padding = true
            attr_messages << "W: #{attrname} is using deprecated GraphicString"
          when 26 # Visible
            value = value.value
            check_padding = true
          when 27 # General
            value = value.value
            check_padding = true
            attr_messages << "W: #{attrname} is using deprecated GeneralString"
          when 28 # Universal
            check_padding = true
            attr_messages << "W: Unicode #{attrname} is using deprecated UniversalString"
            value = value.value.force_encoding('UTF-32BE').encode('UTF-8')
          when 30 # BMP
            check_padding = true
            attr_messages << "W: Unicode #{attrname} is using deprecated BMPString"
            value = value.value.force_encoding('UTF-16BE').encode('UTF-8')
          end

          if check_padding
            if value =~ /\A\s+/
              attr_messages << "W: Leading whitepsace in #{attrname}"
            end
            if value =~ /\s+\z/
              attr_messages << "W: Trailing whitespace in #{attrname}"
            end
          end

          case validator
          when Integer
            # Measured in characters not octets
            if value.length > validator
              attr_messages << "E: #{attrname} is too long"
            end
          when :Country
            unless COUNTRIES.include? value.upcase
              attr_messages << "E: Invalid country in #{attrname}"
            end
          when :DNS
            unless value =~ DLABEL
              attr_messages << "E: Invalid label in #{attrname}"
            end
            if value.start_with? 'xn--'
              begin
                ulabel = SimpleIDN.to_unicode(value.encode("UTF-8"))
              rescue SimpleIDN::ConversionError
                messages << 'W: Bad IDN A-label in DNS Name'
                ulabel = value
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
          when :PKCS9
            if value.length > 255
              attr_messages << "E: #{attrname} is too long"
            end
            if value.codepoints.all? { |c| c <= 0x7e }
              unless tag == 22
                attr_messages << "W: #{attrname} should be encoded as IA5String"
              end
            else
              unless tag == 12
                attr_messages << "W: #{attrname} should be encoded as UF8String"
              end
            end
          end
          messages += attr_messages
        end
      end

      dup = attr_types.select { |el| attr_types.count(el) > 1 }.uniq
      # streetAddress, OU, and DC can reasonably appear multiple times
      dup.delete('2.5.4.9')
      dup.delete('2.5.4.11')
      dup.delete('0.9.2342.19200300.100.1.25')
      # There are people with multiple given names and surnames
      dup.delete('2.5.4.42')
      dup.delete('2.5.4.4')
      dup.each do |type|
        attrname = attr_name(type)
        messages << "W: Name has multiple #{attrname} attributes"
      end

      # Empty names are valid but cause an exception when converting to a string
      if name.to_a.length > 0
        # Can OpenSSL handle the name?
        begin
          name.to_s(OpenSSL::X509::Name::RFC2253 & ~4)
        rescue OpenSSL::X509::NameError => e
          messages << "E: Unparsable name: #{e.message}"
        end
      end

      messages
    end
  end
end
