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
require 'ipaddr'
require 'simpleidn'
require_relative 'certlint'
require_relative 'iananames'
require_relative 'pemlint'

module CertLint
  class CABLint
    BR_EFFECTIVE = Time.utc(2012, 7, 1)
    MONTHS_39 = Time.utc(2015, 4, 2)
    BR_825 = Time.utc(2018, 3, 1) # After (greater than), not on or after
    EV_825 = Time.utc(2017, 4, 22)
    NO_SHA1 = Time.utc(2016, 1, 1)

    # Allowed algorithms
    SIGNATURE_ALGORITHMS = {
      'sha1WithRSAEncryption' => :weak,
      'sha256WithRSAEncryption' => :good,
      'sha384WithRSAEncryption' => :good,
      'sha512WithRSAEncryption' => :good,
      'rsassaPss' => :pss,
      'dsaWithSHA1' => :weak,
      'dsa_with_SHA256' => :good,
      'ecdsa-with-SHA1' => :weak,
      'ecdsa-with-SHA256' => :good,
      'ecdsa-with-SHA384' => :good,
      'ecdsa-with-SHA512' => :good
    }

    LETTERS_NUMBERS = /\p{L}|\p{N}/

    def self.lint(der)
      messages = []
      messages += CertLint.lint(der)

      if messages.any? { |m| m.start_with? 'F:' }
        messages << 'W: Cowardly refusing to run CAB check due to previous errors'
        return messages
      end

      begin
        c = OpenSSL::X509::Certificate.new(der)
      rescue
        # Catch anything and move along
        # CertLint will already be full of errors
        messages << 'E: Skipping CAB checks due to previous errors'
        return messages
      end

      sa = SIGNATURE_ALGORITHMS[c.signature_algorithm]
      if sa.nil?
        messages << "E: #{c.signature_algorithm} is not allowed for signing certificates"
      else
        if sa == :weak && c.not_before >= NO_SHA1
          messages << 'E: SHA-1 not allowed for signing certificates'
        end
        if sa == :weak && c.serial.num_bytes < 8
          messages << 'W: Serial numbers for certificates using weaker hashes should have at least 64 bits of entropy'
        elsif sa == :pss
          messages << 'W: PSS is not supported by most browsers'
        end
      end

      if sa != :weak && c.serial.num_bits < 20
        messages << 'W: Serial numbers should have at least 20 bits of entropy'
      end

      begin
        key = c.public_key
      rescue OpenSSL::PKey::PKeyError
        messages << 'E: Invalid subject public key'
        key = nil
      rescue OpenSSL::X509::CertificateError
        messages << 'E: Invalid subject public key'
        key = nil
      end
      if key.is_a? OpenSSL::PKey::RSA
        if key.n.num_bits < 2048
          messages << 'E: RSA subject key modulus must be at least 2048 bits'
        end
        unless key.e.odd?
          messages << 'E: RSA subject key exponent must be odd'
        end
      elsif key.is_a? OpenSSL::PKey::DSA
        l = key.params["p"].num_bits
        n = key.params["q"].num_bits
        if l < 2048
          messages << 'E: DSA subject key p must be at least 2048 bits'
        elsif !(
          (l == 2048 && n == 224) ||
          (l == 2048 && n == 256) ||
          (l == 3072 && n == 256)
        )
          messages << 'E: DSA subject key must have FIPS 186-4 compliant parameters'
        end
      elsif key.is_a? OpenSSL::PKey::EC
        curve = key.group.curve_name
        unless ['prime256v1', 'secp384r1', 'secp521r1'].include? curve
          messages << 'E: EC subject key is not on allowed curve'
        end
      elsif !key.nil?
        messages << 'E: Subject key must be RSA, DSA, or EC'
      end

      is_ca = false
      bc = c.extensions.find { |ex| ex.oid == 'basicConstraints' }
      unless bc.nil?
        is_ca = (bc.value.include? 'CA:TRUE')
      end

      subjectarr = c.subject.to_a.map do |a|
        case a[2]
        when 19, 22, 18, 36
          # Printable, IA5, Numeric, Visible String
          # These should all be 7-bit, but convert to ensure
          a[1] = a[1].encode('UTF-8', 'ISO-8859-1')
        when 12
          # UTF8
          a[1].force_encoding('UTF-8')
        when 30 # BMP String
          a[1] = a[1].encode('UTF-8', 'UCS-2BE')
        when 28
          # Universal String
          a[1] = a[1].encode('UTF-8', 'UCS-4BE')
        when 20
          # T.61/Teletex string
          # Ruby doesn't have T.61, but US-ASCII is super set
          try_iso_8859_1 = false
          begin
            a[1] = a[1].encode('UTF-8', 'US-ASCII')
            # Some certs have high bit data in T.61 strings
            # We assume ISO-8859-1 for backwards compat
          rescue Encoding::InvalidByteSequenceError
            try_iso_8859_1 = true
          end
          if try_iso_8859_1
            a[1] = a[1].encode('UTF-8', 'ISO-8859-1')
          end
        when 3
          # Bit String (binary data)
          # The Ruby OpenSSL module does not allow reading the entry flags
          # which contain info on how many bits in the first byte are to be ignored
          # so we have no way to know how long the bit string really is
          # For now, just use the binary data as-is
          a[1].force_encoding('BINARY')
        end
        a
      end

      # BR section 7.1.4.2.2 (i)
      subjectarr.each do |d|
        if Encoding.compatible?(d[1], LETTERS_NUMBERS)
          if d[1] !~ /\p{L}|\p{N}/
            messages << "E: #{d[0]} appears to only include metadata"
          end
        else d[1] !~ /[A-Za-z0-9]/
          $stderr.puts "WARNING: Invalid encoding"
          messages << "E: #{d[0]} appears to only include metadata"
        end
      end

      # Find key usage and save for future use
      # Per 5280, not present == any, no bits set == none
      ku = c.extensions.find { |ex| ex.oid == 'keyUsage' }
      ku_critical = nil
      if !ku.nil?
        ku_critical = ku.critical?
        ku = ku.value.split(',').map(&:strip)
      end


      # First check CA certs
      if is_ca
        messages << 'I: CA certificate identified'
        unless subjectarr.any? { |d| d[0] == 'C' }
          messages << 'E: CA certificates must include countryName in subject'
        end
        unless subjectarr.any? { |d| d[0] == 'O' }
          messages << 'E: CA certificates must include organizationName in subject'
        end
        unless subjectarr.any? { |d| d[0] == 'CN' }
          messages << 'N: Some applications require CA certificates to include commonName in subject'
        end
        if (c.not_after.year - c.not_before.year) > 25
          messages << 'W: CA certificates should not have a validity period greater than 25 years'
        elsif (c.not_after.year - c.not_before.year) == 25
          if c.not_after.month > c.not_before.month
            messages << 'W: CA certificates should not have a validity period greater than 25 years'
          elsif c.not_after.month == c.not_before.month
            if c.not_after.day > c.not_before.day
              messages << 'W: CA certificates should not have a validity period greater than 25 years'
            end
          end
        end

        if ku.nil?
          messages << 'E: CA certificates must include keyUsage extension'
        else
          unless ku_critical
            messages << 'E: CA certificates must set keyUsage extension as critical'
          end
          unless ku.include? 'CRL Sign'
            messages << 'E: CA certificates must include CRL Signing'
          end
          unless ku.include? 'Digital Signature'
            messages << 'N: CA certificates without Digital Signature do not allow direct signing of OCSP responses'
          end
       end

        if c.extensions.find { |ex| ex.oid == 'subjectAltName' }
          messages << 'W: CA certificates should not include subject alternative names'
        end

        return messages
      end

      # Things left are subscriber certificates
      cert_type_identified = false

      # Use EKUs and Subject attribute types to guess the cert type
      eku = c.extensions.find { |ex| ex.oid == 'extendedKeyUsage' }
      if eku.nil?
        eku = []
      else
        eku = eku.value.split(',').map(&:strip).sort
      end
      subjattrs = subjectarr.map { |a| a[0] }.uniq

      if subjattrs.include?('1.3.6.1.4.1.311.60.2.1.3') || subjattrs.include?('jurisdictionC')
        # EV
        messages << 'I: EV certificate identified'
        cert_type_identified = true
        unless subjattrs.include? 'O'
          messages << 'E: EV certificates must include organizationName in subject'
        end
        unless subjattrs.include? 'businessCategory'
          messages << 'E: EV certificates must include businessCategory in subject'
        end
        unless subjattrs.include? 'serialNumber'
          messages << 'E: EV certificates must include serialNumber in subject'
        end
        if !(subjattrs.include? 'L') && !(subjattrs.include? 'ST')
            messages << 'E: EV certificates must include either localityName or stateOrProvinceName'
        end
        unless subjattrs.include? 'C'
          messages << 'E: EV certificates must include countryName in subject'
        end
      end

      # Poke at keyUsage if eku is empty to see if this usable with TLS
      # If so, add a temporary value to check below
      # RFC 5280 #4.2.1.12 says serverAuth is "consistent" with
      #   digitalSignature, keyEncipherment or keyAgreement
      # RFC 5246 #7.4.2 sets further reqs for RSA
      # EC keys could be for ECDSA or ECDH so check for both
      if eku.empty? && !ku.nil?
        if key.is_a? OpenSSL::PKey::RSA
          if ku.include?('Digital Signature') || ku.include?('Key Encipherment')
            eku << 'tmp-serverauth-usable'
          end
        elsif key.is_a? OpenSSL::PKey::DSA
          if ku.include?('Digital Signature')
            eku << 'tmp-serverauth-usable'
          end
        elsif key.is_a? OpenSSL::PKey::EC
          if ku.include?('Digital Signature') || ku.include?('Key Agreement')
            eku << 'tmp-serverauth-usable'
          end
        end
      # If the certificate has neither keyUsage nor extendedKeyUsage, it is unrestricted
      # so it can be used for anything, including server authentication
      elsif eku.empty? && ku.nil?
          eku << 'tmp-serverauth-usable'
      end

      # So many ways to indicate an in-scope certificate
      if eku.include?('tmp-serverauth-usable') || \
          eku.include?('TLS Web Server Authentication') || \
          eku.include?('Any Extended Key Usage') || \
          eku.include?('Netscape Server Gated Crypto') || \
          eku.include?('Microsoft Server Gated Crypto')
        messages << 'I: TLS Server certificate identified'
        if !eku.include?('TLS Web Server Authentication')
          messages << "W: TLS Server certificates must include serverAuth key purpose in extended key usage"
        end
        cert_type_identified = true
        # Delete our temp key purpose
        eku.delete('tmp-serverauth-usable')
        # OK, we have an "SSL" certificate
        # Allowed to contain these three EKUs
        eku.delete('TLS Web Server Authentication')
        eku.delete('TLS Web Client Authentication')
        eku.delete('E-mail Protection')
        # Also implicitly allowed
        eku.delete('Any Extended Key Usage')
        # Intel AMT/vPro: https://software.intel.com/sites/manageability/AMT_Implementation_and_Reference_Guide/default.htm?turl=WordDocuments%2Facquiringanintelvprocertificate.htm
        if eku.include?('2.16.840.1.113741.1.2.3')
          messages << 'I: Intel AMT/vPro certificate identified'
          eku.delete('2.16.840.1.113741.1.2.3')
        end
        eku.each do |e|
          messages << "W: TLS Server auth certificates should not contain #{e} usage"
        end

        # 24 hours per day, 60 minutes per hour 60 seconds per minute
        # Round to 1/1000, which will be fine for durations <= 42.5 years
        days = ((c.not_after.utc - c.not_before.utc)/(24*60*60)).round(3)

        # For all of these, use the longest possible options (e.g. leap years, July/Aug/Sept 3 month seq)

        if subjattrs.include?('1.3.6.1.4.1.311.60.2.1.3') || subjattrs.include?('jurisdictionC')
          if c.not_before >= EV_825
            if days > 825
              messages << 'E: EV certificates must be 825 days in validity or less'
            end
          elsif days > (366 + 365 + 31 + 31 + 30 + 1)
            # EV: 27 months
            messages << 'E: EV certificates must be 27 months in validity or less'
          end
        elsif c.not_before > BR_825
          if days > 825
            messages << 'E: BR certificates must be 825 days in validity or less'
          end
        elsif c.not_before < BR_EFFECTIVE
          if days > (366 + 365 + 365 + 365 + 366 + 365 + 365 + 365 + 366 + 365 + 1)
            messages << 'W: Pre-BR certificates should not be more than 120 months in validity'
          end
        elsif c.not_before >= MONTHS_39
          if days > (366 + 365 + 365 + 31 + 31 + 30 + 1)
            messages << 'E: BR certificates must be 39 months in validity or less'
          end
        else
          if days > (366 + 365 + 365 + 365 + 366 + 1)
            messages << 'E: BR certificates must be 60 months in validity or less'
          end
        end
        if (subjattrs & ['O', 'GN', 'SN']).empty?
          if subjattrs.include? 'L'
            messages << 'E: BR certificates without organizationName must not include localityName'
          end
          if subjattrs.include? 'ST'
            messages << 'E: BR certificates without organizationName must not include stateOrProvinceName'
          end
          if subjattrs.include? 'street'
            messages << 'E: BR certificates without organizationName must not include streetAddress'
          end
          if subjattrs.include? 'postalCode'
            messages << 'E: BR certificates without organizationName must not include postalCode'
          end
        else
          if !(subjattrs.include? 'L') && !(subjattrs.include? 'ST')
            messages << 'E: BR certificates with organizationName must include either localityName or stateOrProvinceName'
          end
          unless subjattrs.include? 'C'
            messages << 'E: BR certificates with organizationName must include countryName'
          end
        end

        aia = c.extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
        if aia.nil?
          messages << 'W: Certificate does not include authorityInformationAccess. BRs require OCSP stapling for this certificate.'
        else
          aia_info = aia.value.split(/\n/)
          unless aia_info.any? { |i| i.start_with? 'OCSP - URI:http://' }
            messages << 'E: BR certificates must include an HTTP URL of the OCSP responder'
          end
          unless aia_info.any? { |i| i.start_with? 'CA Issuers - URI:http://' }
            messages << 'W: BR certificates should include an HTTP URL of the issuing CA\'s certificate'
          end
        end

        certpolicies = c.extensions.find { |ex| ex.oid == 'certificatePolicies' }
        if certpolicies.nil?
          messages << 'E: BR certificates must include certificatePolicies'
        else
          unless certpolicies.value.start_with? 'Policy: '
            messages << 'E: BR certificates must contain at least one policy'
          end
        end

        crldp = c.extensions.find { |ex| ex.oid == 'crlDistributionPoints' }
        unless crldp.nil?
          dps = crldp.value.strip.split(/\n/).map(&:strip)
          unless dps.any? { |dp| dp.start_with?('URI:http://') }
            messages << 'E: BR certificates with CRL Distribution Point must include HTTP URL'
          end
        end

        unless ku.nil?
          if ku.include? 'CRL Sign'
            messages << 'E: BR certificates must not include CRL Signing'
          end
          if ku.include? 'Certificate Sign'
            messages << 'E: BR certificates must not include Certificate Signing'
          end
        end

        san = c.extensions.find { |ex| ex.oid == 'subjectAltName' }
        names = []
        if san.nil?
          messages << 'E: BR certificates must have subject alternative names extension'
        else
          # See certlint.rb and asn1ext.rb to sort out the next two lines
          # This gets the extnValue (which is DER)
          der = OpenSSL::ASN1.decode(san.to_der).value.last.value
          # Now decode the extnValue to get a sequence of general names
          OpenSSL::ASN1.decode(der).value.each do |genname|
            nameval = nil
            case genname.tag
            when 0
              messages << 'E: BR certificates must not contain otherName type alternative name'
              next
            when 1
              messages << 'E: BR certificates must not contain rfc822Name type alternative name'
              next
            when 2
              val = genname.value
              if val.include? '*'
                x = val.split('.', 2)
                if (x.length > 1) && (x[1].include? '*')
                  messages << 'E: Wildcard not in first label of FQDN'
                elsif x.length == 1
                  messages << 'E: Bare wildcard'
                end
                unless val.start_with? '*.'
                  messages << 'W: Wildcard other than *.<fqdn> in SAN'
                end
              end
              messages += CertLint::IANANames.lint(val).map { |m| m + ' in SAN' }
              nameval = val.downcase.force_encoding('US-ASCII') # A-label
            when 3
              messages << 'E: BR certificates must not contain x400Address type alternative name'
              next
            when 4
              messages << 'E: BR certificates must not contain directoryName type alternative name'
              next
            when 5
              messages << 'E: BR certificates must not contain ediPartyName type alternative name'
              next
            when 6
              messages << 'E: BR certificates must not contain uniformResourceIdentifier type alternative name'
              next
            when 7
              if genname.value.length == 4 || genname.value.length == 16
                n = IPAddr.new_ntoh(genname.value)
                nameval = n.to_s.downcase
              else
                # Certlint already added an error for wrong size, so just skip here
                next
              end
            when 8
              messages << 'E: BR certificates must not contain registeredID type alternative name'
              next
            end
            if names.include? nameval
              messages << 'W: Duplicate SAN entry'
            else
              names << nameval
            end
          end
        end

        # This assumes the strings in names[]  are either IPv4/IPv6 or DNS Names
        # If the BRs are ever updated to allow other things, this needs to be updated
        # to handle IDNs that are not the fulll strings
        idn_san = names.select{ |s| s.include?('xn--') }.map do |a|
          begin
            SimpleIDN.to_unicode(a.encode("UTF-8"))
          rescue SimpleIDN::ConversionError
            nil
          end
        end.compact

        # To check that the CN matches a SAN entry, first check for case insensitive direct match
        # Then check for case sensitive match in UTF-8 encoded IDNs
        # RFC 5891 section 3.1.2 makes this clear:
        #  A pair of A-labels MUST be compared as case-insensitive ASCII (as with
        #  all comparisons of ASCII DNS labels).  U-labels MUST be compared
        #  as-is, without case folding or other intermediate steps.
        subjectarr.select { |rdn| rdn[0] == 'CN' }.each do |rdn|
          val = rdn[1]
          unless names.include? val.downcase
            if idn_san.include? val
              messages << 'W: commonNames in BR certificate contains U-labels'
            else
              messages << 'E: commonNames in BR certificates must be from SAN entries'
            end
          end
        end
      end

      unless cert_type_identified
        messages << 'I: No certificate type identified'
      end

      messages
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  ARGV.each do |file|
    fn = File.basename(file)
    raw = File.read(file)

    if raw.include? '-BEGIN CERTIFICATE-'
      m, der = PEMLint.lint(raw, 'CERTIFICATE')
    else
      m  = []
      der = raw
    end

    m += CABLint.lint(der)
    m.each do |msg|
      puts "#{msg}\t#{fn}"
    end
  end
end
