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
require_relative 'certlint'
require_relative 'iananames'
require_relative 'pemlint'

module CertLint
  class CABLint
    BR_EFFECTIVE = Time.new(2012, 7, 1)
    MONTHS_39 = Time.new(2015, 4, 1)

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
        if sa == :weak && c.serial.num_bytes < 8
          messages << 'W: Serial numbers for certificates using weaker hashes should have at least 64 bits of entropy'
        elsif sa == :pss
          messages << 'W: PSS is not suppported by most browsers'
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
        l = key.p.num_bits
        n = key.q.num_bits
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

      # First check CA certs
      if is_ca
        messages << 'I: CA certificate identified'
        unless c.subject.to_a.any? { |d| d[0] == 'C' }
          messages << 'E: CA certificates must include countryName in subject'
        end
        unless c.subject.to_a.any? { |d| d[0] == 'O' }
          messages << 'E: CA certificates must include organizationName in subject'
        end
        unless c.subject.to_a.any? { |d| d[0] == 'CN' }
          messages << 'E: CA certificates must include commonName in subject'
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

        ku = c.extensions.find { |ex| ex.oid == 'keyUsage' }
        if ku.nil?
          messages << 'E: CA certificates must include keyUsage extension'
          ku = []
        else
          unless ku.critical?
            messages << 'E: CA certificates must set keyUsage extension as critical'
          end
          ku = ku.value.split(',').map(&:strip)
        end

        unless ku.include? 'CRL Sign'
          messages << 'E: CA certificates must include CRL Signing'
        end
        unless ku.include? 'Digital Signature'
          messages << 'W: CA certificates should include Digital Signature to allow signing OCSP responses'
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
      subjattrs = c.subject.to_a.map { |a| a[0] }.uniq

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
        unless subjattrs.include? 'L'
          messages << 'E: EV certificates must include localityName in subject'
        end
        unless subjattrs.include? 'C'
          messages << 'E: EV certificates must include countryName in subject'
        end
      end

      if eku.empty? || eku.include?('TLS Web Server Authentication') || eku.include?('Any Extended Key Usage')
        messages << 'I: TLS Server certificate identified'
        cert_type_identified = true
        # OK, we have a "SSL" certificate
        # Allowed to contain these three EKUs
        eku.delete('TLS Web Server Authentication')
        eku.delete('TLS Web Client Authentication')
        eku.delete('E-mail Protection')
        # Also implicitly allowed
        eku.delete('Any Extended Key Usage')
        eku.each do |e|
          messages << "W: TLS Server auth certificates should not contain #{e} usage"
        end

        months = (c.not_after.year - c.not_before.year) * 12
        months += (c.not_after.month - c.not_before.month)
        if c.not_after.day > c.not_before.day
          months += 1
        end

        if subjattrs.include?('1.3.6.1.4.1.311.60.2.1.3') || subjattrs.include?('jurisdictionC')
          # EV
          if months > 27
            messages << 'E: EV certificates must be 27 months in validity or less'
          end
        elsif c.not_before < BR_EFFECTIVE
          if months > 120
            messages << 'W: Pre-BR certificates should not be more than 120 months in validity'
          end
        elsif (c.not_before < MONTHS_39) && (c.not_before >= BR_EFFECTIVE)
          if months > 60
            messages << 'E: BR certificates must be 60 months in validity or less'
          end
        elsif c.not_before >= MONTHS_39
          if months > 39
            messages << 'E: BR certificates must be 39 months in validity or less'
          end
        end
        if subjattrs.include? 'O'
          if !(subjattrs.include? 'L') && !(subjattrs.include? 'ST')
            messages << 'E: BR certificates with organizationName must include either localityName or stateOrProvinceName'
          end
          unless subjattrs.include? 'C'
            messages << 'E: BR certificates with organizationName must include countryName'
          end
        else
          if subjattrs.include? 'L'
            messages << 'E: BR certificates without organizationName may not include localityName'
          end
          if subjattrs.include? 'ST'
            messages << 'E: BR certificates without organizationName may not include stateOrProvinceName'
          end
          if subjattrs.include? 'street'
            messages << 'E: BR certificates without organizationName may not include streetAddress'
          end
          if subjattrs.include? 'postalCode'
            messages << 'E: BR certificates without organizationName may not include postalCode'
          end
        end

        aia = c.extensions.find { |ex| ex.oid == 'authorityInfoAccess' }
        if aia.nil?
          messages << 'E: BR certificates must include authorityInformationAccess'
        else
          aia_info = aia.value.split(/\n/)
          unless aia_info.any? { |i| i.start_with? 'OCSP - URI:http://' }
            messages << 'E: BR certificates must include a HTTP URL of the OCSP responder'
          end
          unless aia_info.any? { |i| i.start_with? 'CA Issuers - URI:http://' }
            messages << 'W: BR certificates should include a HTTP URL of the issuing CA\'s certificate'
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

        ku = c.extensions.find { |ex| ex.oid == 'keyUsage' }
        unless ku.nil?
          ku = ku.value.split(',').map(&:strip)
          if ku.include? 'CRL Sign'
            messages << 'E: BR certificates must not include CRL Signing'
          end
          if ku.include? 'Certificate Sign'
            messages << 'E: BR certificates must not include Certificate Signing'
          end
        end

        san = c.extensions.find { |ex| ex.oid == 'subjectAltName' }
        if san.nil?
          messages << 'E: BR certificates must have subject alternative names extension'
          san = []
        else
          names = []
          # See certlint.rb and asn1ext.rb to sort out the next two lines
          # This gets the extnValue (which is DER)
          der = OpenSSL::ASN1.decode(san.to_der).value.last.value
          # Now decode the extnValue to get a sequence of general names
          OpenSSL::ASN1.decode(der).each do |genname|
            nameval = nil
            case genname.tag
            when 0
              messages << 'E: BR certificates may not contain otherName type alternative name'
              next
            when 1
              messages << 'E: BR certificates may not contain rfc822Name type alternative name'
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
              nameval = val.downcase
            when 3
              messages << 'E: BR certificates may not contain x400Address type alternative name'
              next
            when 4
              messages << 'E: BR certificates may not contain directoryName type alternative name'
              next
            when 5
              messages << 'E: BR certificates may not contain ediPartyName type alternative name'
              next
            when 6
              messages << 'E: BR certificates may not contain uniformResourceIdentifier type alternative name'
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
              messages << 'E: BR certificates may not contain registeredID type alternative name'
              next
            end
            if names.include? nameval
              messages << 'E: Duplicate SAN entry'
            else
              names << nameval
            end
          end
          san = names
        end
        c.subject.to_a.select { |rdn| rdn[0] == 'CN' }.map { |rdn| rdn[1] }.each do |val|
          unless san.include? val.downcase
            messages << 'E: commonNames in BR certificates must be from SAN entries'
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
