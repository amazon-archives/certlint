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
require 'asn1validator'
require 'openssl'

require_relative 'namelint'
require_relative 'certextlint'
require_relative 'extensions/authorityinfoaccesssyntax'
require_relative 'extensions/authoritykeyidentifier'
require_relative 'extensions/basicconstraints'
require_relative 'extensions/certificatepolicies'
require_relative 'extensions/crldistributionpoints'
require_relative 'extensions/ctpoison'
require_relative 'extensions/extkeyusagesyntax'
require_relative 'extensions/features'
require_relative 'extensions/freshestcrl'
require_relative 'extensions/inhibitanypolicy'
require_relative 'extensions/issueraltname'
require_relative 'extensions/keyusage'
require_relative 'extensions/logotypeextn'
require_relative 'extensions/nameconstraints'
require_relative 'extensions/ocspnocheck'
require_relative 'extensions/policyconstraints'
require_relative 'extensions/policymappings'
require_relative 'extensions/privatekeyusageperiod'
require_relative 'extensions/qcstatements'
require_relative 'extensions/signedcertificatetimestamplist'
require_relative 'extensions/smimecapabilities'
require_relative 'extensions/subjectaltname'
require_relative 'extensions/subjectdirectoryattributes'
require_relative 'extensions/subjectinfoaccesssyntax'
require_relative 'extensions/subjectkeyidentifier'

module CertLint
  SIG_STRUCTS = {
    '1.2.840.113549.1.1.2' => :rsa,
    '1.2.840.113549.1.1.3' => :rsa,
    '1.2.840.113549.1.1.4' => :rsa,
    '1.2.840.113549.1.1.5' => :rsa,
    '1.2.840.113549.1.1.11' => :rsa,
    '1.2.840.113549.1.1.12' => :rsa,
    '1.2.840.113549.1.1.13' => :rsa,
    '1.2.840.113549.1.1.10' => :pss,
    '1.2.840.10040.4.3' => :dsa,
    '2.16.840.1.101.3.4.3.2' => :dsa,
    '1.2.840.10045.4.1' => :ecdsa,
    '1.2.840.10045.4.3.2' => :ecdsa,
    '1.2.840.10045.4.3.3' => :ecdsa,
    '1.2.840.10045.4.3.4' => :ecdsa
  }

  def self.check_pdu(pdu, content)
    messages = []
    content.force_encoding('BINARY')

    begin
      validator = CertLint::ASN1Validator.new(content, pdu)
    rescue => ex
      messages << "F: ASN.1 Error in #{pdu}: #{ex.message}"
      return messages
    end

    begin
      validator.check_constraints
    rescue => ex
      messages << "E: Constraint failure in #{pdu}: #{ex.message}"
    end

    begin
      der = validator.to_der
      unless der == content
        messages << "W: #{pdu} is not encoded using DER"
      end
    rescue NoMemoryError
      messages << "E: BadDER in #{pdu}"
    end

    # A few things pass asn1c but fail to decode in OpenSSL/Ruby
    begin
      OpenSSL::ASN1.decode(content)
    rescue ArgumentError => e
      messages << "F: Encoding error: #{e.message} in #{pdu}"
      return messages # ASN.1 error is fatal
    rescue TypeError => e
      if e.message == "bad GENERALIZEDTIME format"
        messages << "F: Bad GeneralizedTime in #{pdu}"
        return messages # ASN.1 error is fatal
      elsif e.message.start_with?("bad UTCTIME format")
        messages << "F: Bad UTCTime in #{pdu}"
        return messages # ASN.1 error is fatal
      end
      raise e
    rescue OpenSSL::ASN1::ASN1Error => e
      if e.message.include?("mismatch")
        messages << "F: Type mismatch during decode in #{pdu}"
      elsif e.message == "invalid object encoding"
        messages << "F: Bad encoding in #{pdu}"
      else
        messages << "F: Decode error in #{pdu}: #{e.message}"
      end
      return messages # ASN.1 error is fatal
    end

    # Check strings for things that asn1c does not cover in constraints
    # This includes:
    # - Null bytes
    # - Escape sequences in restricted character strings
    begin
      OpenSSL::ASN1.traverse(content) do |_depth, offset, header_len, length, _constructed, tag_class, tag|
        start_c = offset + header_len
        end_c = start_c + length
        value = content[start_c..end_c - 1]
        if (tag_class == :UNIVERSAL) && (tag == 12) # UTF8String
          unless value.force_encoding('UTF-8').valid_encoding?
            messages << "F: Incorrectly encoded UTF8String in #{pdu}"# at offset #{offset}"
          end
          if value.bytes.include? 0
            messages << "E: Null byte found in UTF8String in #{pdu}"# at offset #{offset}"
          end
        elsif (tag_class == :UNIVERSAL) && ([22, 26].include? tag)
          # IA5, Visible
          if value.bytes.any? { |b| b < 0x20 || b > 0x7E }
            messages << "E: Control character found in String in #{pdu}"# at offset #{offset}"
          end
        elsif (tag_class == :UNIVERSAL) && ([20, 21, 25, 27].include? tag)
          # Teletex, Videotex, Graphic, General String
          if value.bytes.include? 0
            messages << "E: Null byte found in String in #{pdu}"# at offset #{offset}"
          end
          escape = false
          if value.bytes.include? 27
            escape = true
            messages << "B: Unhandled escape found in String in #{pdu}"# at offset #{offset}"
          end
          if tag == 20
            unless escape || value.force_encoding('BINARY').bytes.all? { |b| (b >= 0x20 && b <= 0x5B) || b == 0x5D || b == 0x5F || (b >= 0x61 && b <= 0x7A) || b == 0x7C }
              messages << "E: Incorrectly encoded TeletexString in #{pdu}"# at offset #{offset}"
            end
          else
            messages << "B: No checks for String type #{tag} in #{pdu}"# at offset #{offset}"
          end
        end
      end
    rescue TypeError => e
      messages << "F: Type error during traverse in #{pdu}: #{e.message}"
      return messages # ASN.1 error is fatal
    end

    messages
  end

  # Takes a SubjectPublicKeyInfo in DER
  def self.check_spki(spki_der)
    messages = []
    spki = OpenSSL::ASN1.decode(spki_der)
    type = spki.value[0].value[0].oid
    params = spki.value[0].value[1] # May be nil, as is optional
    key_der = spki.value[1].value

    case type
    when '1.2.840.113549.1.1.1' # RSA
      # parameters field MUST have ASN.1 type NULL
      # public key MUST be encoded using the ASN.1 type RSAPublicKey
      if params.nil?
        messages << 'E: RSA keys must have a parameter specified'
      elsif !params.instance_of? OpenSSL::ASN1::Null
        messages << 'E: RSA keys must have a null parameter'
      end
      messages += check_pdu(:RSAPublicKey, key_der)
      if messages.any? { |m| m.start_with? 'F:' }
        return messages
      end
      # Section 3.1 of RFC 3447 requires n and e to both be positive
      # and e must be in the range 3 .. n-1
      rsa_asn = OpenSSL::ASN1.decode(key_der)
      positive = 0
      if rsa_asn.value[0].value > 0
        positive += 1
      else
        messages << 'E: RSA public key modulus must be positive'
      end
      if rsa_asn.value[1].value > 0
        positive += 1
      else
        messages << 'E: RSA public key exponent must be positive'
      end
      # Only run this check if both numbers were positive
      if positive == 2
        unless (rsa_asn.value[1].value >= 3) && (rsa_asn.value[1].value < rsa_asn.value[0].value)
          messages << 'E: RSA public key exponent must be between 3 and n - 1'
        end
      end
    when '1.2.840.10040.4.1' # DSA
      # When omitted, the parameters component MUST be omitted
      # entirely. If the DSA domain parameters are present, the
      # parameters are included using the Dss-Parms structure
      unless params.nil?
        messages += check_pdu(:'Dss-Parms', params.to_der)
      end
      messages += check_pdu(:DSAPublicKey, key_der)
    when '1.2.840.10046.2.1' # DH
      # parameters field have the ASN.1 type DomainParameters
      if params.nil?
        messages << 'E: DH keys must have parameters'
      else
        messages += check_pdu(:DomainParameters, params.to_der)
      end
      messages += check_pdu(:DHPublicKey, key_der)
    when '1.2.840.10045.2.1' # EC
      # parameters field is EcpkParameters
      if params.nil?
        messages << 'E: EC keys must have parameters'
      else
        messages += check_pdu(:EcpkParameters, params.to_der)
      end
      # EC keys are stored slightly oddly
      # They are raw mapped to the BIT STRING
      # rather than having their DER put into the
      # bit string; they natively are an OctetString
      # This check is fairly pointless, but here for
      # consistency
      k = OpenSSL::ASN1::OctetString.new(key_der)
      messages += check_pdu(:ECPoint, k.to_der)
      begin
        okey = OpenSSL::PKey::EC.new(spki_der)
      rescue ArgumentError => e
        messages << "E: EC public key #{e.message}"
      end
      if !okey.nil? && okey.public_key.infinity?
        messages << 'E: EC Public key is infinity'
      end
      if !okey.nil? && !okey.public_key.on_curve?
        messages << 'E: EC Public key is not on curve'
      end
    else
      messages << 'W: Unknown public key type'
    end
    messages
  end

  def self.lint(der)
    messages = []
    # First, check overall ASN.1 encoding and details that are not
    # visible once parsed into a certificate object
    messages += check_pdu(:Certificate, der)

    # Ensure that we bail on fatal errors
    if messages.any? { |m| m.start_with? 'F:' }
      return messages
    end

    # Check time fields
    OpenSSL::ASN1.traverse(der) do |_depth, offset, header_len, length, _constructed, tag_class, tag|
      start_c = offset + header_len
      end_c = start_c + length
      value = der[start_c..end_c - 1]
      if (tag_class == :UNIVERSAL) && (tag == 23) # UTCTimee
        # RFC 5280 4.1.2.5: times must be in Z (GMT)
        unless value =~ /Z\z/
          messages << 'E: Time not in Zulu/GMT'
        end
        if (value[0..1] >= '50') && (value[0..1] < '69')
          # Ruby uses (x < 69)?2000:1900, but
          # RFC 5280 says (x < 50)?2000:1900
          messages << 'N: Ruby may incorrectly interpret UTCTimes between 1950 and 1969'
        end
        # RFC 5280 4.1.2.5.1: UTCTime MUST include seconds, even when 00
        if value !~ /\A([0-9]{2})([01][0-9])([0-3][0-9])([012][0-9])([0-5][0-9]){2}Z\z/
          messages << 'E: UTCTime without seconds'
        end
      elsif (tag_class == :UNIVERSAL) && (tag == 24) # Generalized Time
        # RFC 5280 4.1.2.5: times must be in Z (GMT)
        unless value =~ /Z\z/
          messages << 'E: Time not in Zulu/GMT'
        end
        if value[0..3] < '2050'
          messages << 'E: Generalized Time before 2050'
        end
        if value !~ /\A([0-9]{4})([01][0-9])([0-3][0-9])([012][0-9])([0-5][0-9]){2}Z\z/
          messages << 'E: Generalized Time without seconds or with fractional seconds'
        end
      end
    end

    asn = OpenSSL::ASN1.decode(der)

    # tbsCertificate.version is optional, so we don't have a fixed
    # offset. Check if the first item is a pure ASN1Data, which
    # is a strong hint that it is an EXPLICIT wrapper for the first
    # element in the struct.  If so, this is the version, so everything
    # is offset by one.
    skip = 0
    if asn.value[0].value[0].instance_of? OpenSSL::ASN1::ASN1Data
      skip = 1
    end
    tbs_sign_alg = asn.value[0].value[1 + skip].to_der
    # The Certificate sequence always has three members, so no
    # need to use find or other heuristics
    cert_sign_alg = asn.value[1].to_der
    if tbs_sign_alg != cert_sign_alg
      messages << 'E: Certificate signature algorithm does not match TBS signature algorithm'
    end
    sig_oid = asn.value[1].value[0].oid
    sig_type = SIG_STRUCTS[sig_oid]
    sig_params = asn.value[1].value[1]
    case sig_type
    when nil
      messages << "W: Certificate signature algorithm type is unknown: #{sig_oid}"
    when :pss
      messages << 'I: No checks for PSS yet'
    when :rsa
      if sig_params.nil?
        messages << 'E: RSA signatures must have a parameter specified'
      elsif !sig_params.instance_of? OpenSSL::ASN1::Null
        messages << 'E: RSA signatures must have a null parameter'
      end
    when :dsa
      unless sig_params.nil?
        messages << 'E: DSA signatures must not have a parameter specified'
      end
      messages += check_pdu(:'Dss-Sig-Value', asn.value[2].value)
    when :ecdsa
      unless sig_params.nil?
        messages << 'E: ECDSA signatures must not have a parameter specified'
      end
      messages += check_pdu(:'ECDSA-Sig-Value', asn.value[2].value)
    else
      fail 'Unknown signature type'
    end

    # Check the SubjectPublicKeyInfo
    messages += check_spki(asn.value[0].value[5 + skip].to_der)

    begin
      cert = OpenSSL::X509::Certificate.new(der)
    rescue OpenSSL::X509::CertificateError
      messages << 'F: Unable to parse Certificate'
      return messages
    end

    if cert.version > 2
      messages << 'E: Invalid certificate version'
    elsif cert.version < 2
      messages << 'E: Old certificate version (not X.509v3)'
    end

    if cert.serial.to_s =~ /^-/
      messages << 'E: Negative serial number'
    elsif cert.serial.zero?
      messages << 'E: Serial number must be positive'
    end
    # DER of a 20 byte octet is 22 bytes (one byte type, one byte length, 20 bytes of data)
    if OpenSSL::ASN1::Integer.new(cert.serial).to_der.bytesize > 22
      messages << 'E: Serial numbers must be 20 octets or less'
    end

    ## Note: No checking of Issuer Name, as the most important
    # requirement is that it be exactly the same bytes the subject
    # of the previous cert in the chain to ensure chaining works.
    # Lint that cert if you want to check this Issuer Name.

    if cert.not_after < cert.not_before
      messages << 'E: Certificate has negative validity length'
    end

    m = NameLint.lint(cert.subject)
    unless m.nil?
      messages += m
    end

    # CAs conforming to this profile MUST NOT generate certificates with unique identifiers. (4.1.2.8)
    if asn.value[0].value.any? { |el| el.tag_class == :CONTEXT_SPECIFIC && el.tag == 1 }
      messages << 'E: issuerUniqueID is included'
    end
    if asn.value[0].value.any? { |el| el.tag_class == :CONTEXT_SPECIFIC && el.tag == 2 }
      messages << 'E: subjectUniqueID is included'
    end

    ext_list = []

    # Track basic constraints and keyUsage to check X.509 8.2.2.3
    bc = nil
    ku = nil

    first = true
    cert.extensions.each do |ext|
      # Do a little dance to get extension object string (der)
      e = OpenSSL::ASN1.decode(ext.to_der).value
      oid = e.first.oid

      if first
        if oid == '2.5.29.17' # SubjectAltName
          messages << 'N: Some python versions will not see SAN extension if it is the first extension'
        end
        first = false
      end

      if ext_list.include? oid
        messages << "E: Duplicate extension #{oid}"
      end
      ext_list << oid
      # if critical, e[1] is true and e[2] is octet string; otherwise e[1] is octet string
      # so use .last to make it universal
      extder = e.last

      # Default for critical is false
      critical = false
      critical = e[1].value if e.length == 3
      messages += CertExtLint.lint(oid, extder.value, cert, critical)

      if oid == '2.5.29.19' # basicConstraints
        bc = ext.value
      elsif oid == '2.5.29.15' # keyUsage
        ku = ext.value
      end
    end

    # X.509 8.2.2.3 says if keyCertSign is set, then CA:TRUE must be present
    if !ku.nil? && ku.split(',').any? { |s| s.strip == 'Certificate Sign' }
      if bc.nil? || !(bc.include? 'CA:TRUE')
        messages << 'E: keyCertSign without CA:TRUE'
      end
    end
    # RFC 5280 4.2.1.3
    # Conforming CAs MUST include this extension in certificates that
    # contain public keys that are used to validate digital signatures on
    # other public key certificates or CRLs.
    if !bc.nil? && (bc.include? 'CA:TRUE')
      if ku.nil? || !ku.split(',').any? { |s| s.strip == 'Certificate Sign' }
        messages << 'E: CA:TRUE without keyCertSign'
      end
    end
    messages
  end
end

if __FILE__ == $PROGRAM_NAME
  fn = File.basename(ARGV[0])
  raw = File.read(ARGV[0])
  if raw.include? '-BEGIN CERTIFICATE-'
    puts 'PEM!!!'
    exit 1
  end
  der = raw

  m = CertLint.lint(der)
  m.each do |msg|
    puts "#{msg}\t#{fn}"
  end
end
