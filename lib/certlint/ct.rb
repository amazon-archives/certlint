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
require 'net/http'
require 'uri'
require 'json'
require 'bindata'
require 'base64'
require 'openssl'

module CertLint
  class CT
    class PreCertificate < OpenSSL::X509::Certificate
      DER_SIG = OpenSSL::ASN1::BitString.new('0000').to_der

      attr_reader :raw

      def initialize(tbs_der)
        asn = OpenSSL::ASN1.decode(tbs_der)
        # tbsCertificate.version is optional, so we don't have a fixed
        # offset. Check if the first item is a pure ASN1Data, which
        # is a strong hint that it is an EXPLICIT wrapper for the first
        # element in the struct.  If so, this is the version, so everything
        # is offset by one.
        skip = asn.value[0].instance_of?(OpenSSL::ASN1::ASN1Data) ? 1 : 0
        sig_alg_der = asn.value[1 + skip].to_der
        @raw = OpenSSL::ASN1::Sequence.new([tbs_der, sig_alg_der, DER_SIG]).to_der
        super(@raw)
      end
    end

    class ASN1Cert < BinData::Primitive
      endian :big
      uint24	:len, :value => lambda { data.length }
      string	:data, :read_length => :len

      def get
        data
      end

      def set(v)
        data = v
      end

      def certificate
        OpenSSL::X509::Certificate.new(data)
      end

      def raw_certificate
        data
      end
    end

    class PreCert < BinData::Record
      endian :big
      string	:issuer_key_hash, :read_length => 32
      ASN1Cert :tbs_certificate

      def certificate
        PreCertificate.new(tbs_certificate.data)
      end

      def raw_certificate
        PreCertificate.new(tbs_certificate.data).raw
      end
    end

    class MerkleTreeLeaf < BinData::Record
      hide :zero, :extensions_len
      endian :big
      uint8 :version, :assert => 0 # v1
      uint8 :leaf_type, :assert => 0 # timestamped_entry
      uint64 :timestamp # Unix timestamp in ms
      uint16 :entry_type
      choice :signed_entry, :selection => :entry_type do
        ASN1Cert 0
        PreCert 1
      end
      uint16 :extensions_len, :assert => 0
      string :extensions, :read_length => :extensions_len
      count_bytes_remaining :zero
      virtual :assert => lambda { zero == 0 }

      def self.read_base64(b64)
        read(Base64.decode64(b64))
      end

      def raw_certificate
        signed_entry.raw_certificate
      end

      def certificate
        signed_entry.certificate
      end
    end

    class CertChain < BinData::Record
      hide :zero
      endian :big
      uint24	:chain_len
      array :chain, :type => ASN1Cert, :read_until => lambda { array.num_bytes == chain_len }
      count_bytes_remaining :zero
      virtual :assert => lambda { zero == 0 }

      def self.read_base64(b64)
        if b64 == 'AAAA'
          # Empty
          return CertChain.new
        end
        read(Base64.decode64(b64))
      end

      def chain_certificates
        chain.map(&:certificate)
      end
    end

    class PrecertChainEntry < BinData::Record
      endian :big
      ASN1Cert :pre_certificate
      CertChain :precertificate_chain

      def self.read_base64(b64)
        if b64 == 'AAAA'
          # Empty
          return PrecertChainEntry.new
        end
        read(Base64.decode64(b64))
      end

      def chain_certificates
        precertificate_chain.chain_certificates
      end
    end

    def initialize(log)
      @log = URI.parse(log + '/').normalize
    end

    def get_sth
      url = @log + 'ct/v1/get-sth'
      _call url
    end

    def get_entries(min = 0, max = 0)
      url = @log + 'ct/v1/get-entries'
      url.query = _qstr({ :start => min, :end => max })
      j = _call(url)
      if j['entries'].nil?
        return []
      end
      j['entries'].map do |x|
        e = {}
        e['leaf_input'] = MerkleTreeLeaf.read_base64(x['leaf_input'])
        if e['leaf_input'].entry_type == 0
          e['extra_data'] = CertChain.read_base64(x['extra_data'])
        else
          e['extra_data'] = PrecertChainEntry.read_base64(x['extra_data'])
        end
        e
      end
    end

    private

    def _qstr(h)
      h.map { |k, v| "#{k}=#{v}" }.join('&')
    end

    def _call(url)
      resp = Net::HTTP.get_response url
      JSON.parse(resp.body)
    end
  end
end
