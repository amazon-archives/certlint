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
gem 'iconv'
require 'iconv'

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

    PRINTABLE_CHARS = %r{\A[A-Za-z0-9 '()+,.:=?/-]*\z}

    # IA5 isn't quite ASCII
    # http://www.zytrax.com/tech/ia5.html
    # Only recommend IA5 when characters are unambigious
    IA5_CHARS = /\A[\x20-\x23\x25-\x7d]*\z/

    RDN_ATTRIBUTES = {
      'C' => :Country,
      'CN' => [:DirectoryString, 64],
      'DC' => [:IA5String, 63], # DNS rules
      'GN' => [:DirectoryString, 32768], # OpenSSLism for givenName
      'L' => [:DirectoryString, 128],
      'O' => [:DirectoryString, 64],
      'OU' => [:DirectoryString, 64],
      'SN' => [:DirectoryString, 32768],
      'ST' => [:DirectoryString, 128],
      'UID' => :DirectoryString,
      'businessCategory' => [:DirectoryString, 128],
      'description' => [:DirectoryString, 1024],
      'dmdName' => :DirectoryString,
      'dnQualifier' => :PrintableString,
      'emailAddress' => [:IA5String, 255],
      'houseIdentifier' => :DirectoryString,
      'info' => :DirectoryString,
      'initials' => [:DirectoryString, 32768],
      'name' => [:DirectoryString, 32768],
      # TBD how to handle this unique value type
      # 'postalAddress"'=> :SequenceOfDirectoryString,
      'postalCode' => [:DirectoryString, 16],
      'postOfficeBox' => [:DirectoryString, 40],
      'serialNumber' => [:PrintableString, 64],
      'street' => [:DirectoryString, 128],
      'telephoneNumber' => [:PrintableString, 32],
      'title' => [:DirectoryString, 64],
      'unstructuredAddress' => :DirectoryString,
      'unstructuredName' => :IA5orDS,
      'x500UniqueIdentifier' => :BitString,
      '1.3.6.1.4.1.311.60.2.1.1' => [:DirectoryString, 128], # jurisdictionOfIncorporationLocalityName
      '1.3.6.1.4.1.311.60.2.1.2' => [:DirectoryString, 128], # jurisdictionOfIncorporationStateOrProvinceName
      '1.3.6.1.4.1.311.60.2.1.3' => :Country, # jurisdictionOfIncorporationCountryName
      'jurisdictionL' => [:DirectoryString, 128], # OpenSSL 1.0.2 name
      'jurisdictionST' => [:DirectoryString, 128], # OpenSSL 1.0.2 name
      'jurisdictionC' => :Country, # OpenSSL 1.0.2 name
    }

    # List of attributes that are known deprecated
    DEPRECATED_ATTRIBUTES = [
      'emailAddress',
      'unstructuredAddress',
      'unstructuredName'
    ]

    ASN1_TYPES = {
      12 => 'UTF8String',
      19 => 'PrintableString',
      18 => 'NumericString',
      20 => 'TeletexString',
      22 => 'IA5String',
      28 => 'UniversalString',
      30 => 'BMPString',
      36 => 'VisibileString'
    }

    def self.lint(name)
      messages = []
      unless name.is_a? OpenSSL::X509::Name
        return nil
      end

      # Check for multiple attributes in a single RDN
      begin
        s2253 = name.to_s(OpenSSL::X509::Name::RFC2253 & ~4)
        if (s2253.include? '+') && (s2253 =~ /(?<!\\)\+/)
          messages << 'W: Multiple attributes in a single RDN in the subject Name'
        end
      rescue OpenSSL::X509::NameError => e
        messages << 'E: Unparsable name'
      end

      s_array = name.to_a
      dup = s_array.map { |rdn| rdn[0] }.select { |el| s_array.count(el) > 1 }.uniq
      # OU can reasonably appear multiple times
      dup.delete('OU')
      unless dup.empty?
        messages << 'W: Name has multiple attributes of the same type'
      end
      s_array.each do |rdn|
        max_len = nil

        # 0: oid, 1: value, 2: type
        validator = RDN_ATTRIBUTES[rdn[0]]
        if validator.nil?
          messages << "E: Name has unknown attribute #{rdn[0]}"
        end
        if validator.is_a? Array
          max_len = validator[1]
          validator = validator[0]
        end

        if DEPRECATED_ATTRIBUTES.include? rdn[0]
          messages << "W: Name has deprecated attribute #{rdn[0]}"
        end

        begin
          # Covent strings to UTF8
          case rdn[2]
          # first four: Printable, IA5, Numeric, Visible String
          # These should all be 7-bit, but convert to ensure
          when 19
            if rdn[1] !~ PRINTABLE_CHARS
              messages << "E: #{rdn[0]} has invalid characters for type"
            end
            value = rdn[1].force_encoding('ISO-8859-1').encode('UTF-8')
          when 22
            if rdn[1] !~ IA5_CHARS
              messages << "E: #{rdn[0]} has invalid characters for type"
            end
            value = rdn[1].force_encoding('ISO-8859-1').encode('UTF-8')
          when 18
            if rdn[1] !~ /\A[0-9 ]*\z/
              messages << "E: #{rdn[0]} has invalid characters for type"
            end
            value = rdn[1].force_encoding('ISO-8859-1').encode('UTF-8')
          when 36

            if rdn[1] !~ /\A[\x20-\x7e]*\z/
              messages << "E: #{rdn[0]} has invalid characters for type"
            end
            value = rdn[1].force_encoding('ISO-8859-1').encode('UTF-8')
          when 12 # UTF-8
            value = rdn[1].force_encoding('UTF-8')
          when 30 # BMPString
            value = rdn[1].force_encoding('UTF-16BE').encode('UTF-8')
          when 28 # UniversalString
            value = rdn[1].force_encoding('UTF-32BE').encode('UTF-8')
          when 20 # T.61/TeletexString
            begin
              value = Iconv.iconv('UTF-8', 'T.61-8BIT', rdn[1])[0]
            rescue Iconv::InvalidEncoding
              # OS X doesn't have T.61-8BIT, use a poor placeholder
              # FIXME: Find a T.61-bit library that is cross platform
              value = rdn[1].force_encoding('ISO-8859-1').encode('UTF-8')
            end
          else
            value = rdn[1]
          end
        rescue Iconv::IllegalSequence => e
          messages << "E: #{rdn[0]} contains characters not compatible with type"
          value = rdn[1]
        rescue Iconv::InvalidCharacter => e
          messages << "E: #{rdn[0]} contains a character not compatible with type"
          value = rdn[1]
        end

        # Measured in characters not octets
        if !max_len.nil? && value.length > max_len
          messages << "W: #{rdn[0]} is too long"
        end
        if value =~ /\A\s+/
          messages << "W: Leading whitepsace in #{rdn[0]}"
        end
        if value =~ /\s+\z/
          messages << "W: Trailing whitespace in #{rdn[0]}"
        end

        case validator
        when :Country
          if rdn[2] != 19
            messages << "E: #{rdn[0]} must be PrintableString"
          end
          if value != value.upcase
            messages << "W: #{rdn[0]} should be in upper case"
          end
          unless COUNTRIES.include? value.upcase
            messages << "E: Invalid country in #{rdn[0]}"
          end
        when :PrintableString
          if rdn[2] != 19
            messages << "E: #{rdn[0]} must be PrintableString"
          end
          if value !~ PRINTABLE_CHARS
            messages << "E: Invalid character in #{rdn[0]}"
          end
        when :DirectoryString
          # Telex, Printable, BMP, Universal, UTF8
          unless [20, 19, 30, 28, 12].include? rdn[2]
            messages << "E: Invalid type (#{rdn[2]}) for #{rdn[0]}"
          end
          if (rdn[2] != 12) && (rdn[2] != 19)
            messages << "W: #{rdn[0]} is using deprecated #{ASN1_TYPES[rdn[2]]}"
          end
          ideal = 12 # UTF-8
          if value =~ PRINTABLE_CHARS
            ideal = 19 # PrintableString
          end
          if rdn[2] != ideal
            messages << "W: #{rdn[0]} should be type #{ASN1_TYPES[ideal]}"
          end
        when :IA5String
          if rdn[2] != 22
            messages << "E: #{rdn[0]} must be IA5String"
          end
          if value !~ IA5_CHARS
            messages << "E: Invalid character in #{rdn[0]}"
          end
        when :BitString
          if rdn[2] != 3
            messages << "E: #{rdn[0]} must be Bit String"
          end
        when :IA5orDS
          unless [20, 19, 30, 28, 12, 22].include? rdn[2]
            messages << "E: Invalid type (#{rdn[2]}) for #{rdn[0]}}"
          end
          if [20, 39, 28].include? rdn[2]
            messages << "W: #{rdn[0]} is using deprecated #{ASN1_TYPES[rdn[2]]}"
          end
          # RFC 2985 says use IA5 unless disallowed chars
          # Then use UTF8
          ideal = 12 # UTF-8
          if value =~ IA5_CHARS
            ideal = 22 # IA5String
          end
          if rdn[2] != ideal
            messages << "W: #{rdn[0]} should be type #{ASN1_TYPES[ideal]}"
          end
        end
      end
      messages
    end
  end
end
