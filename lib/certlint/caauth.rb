#!/usr/bin/ruby -Eutf-8:utf-8
# encoding: UTF-8
# Copyright 2018 Santhan Raj. All Rights Reserved.
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
require 'resolv'
require 'openssl'

module CAAuth

  #Performs a CAA request for the given domain. The second parameter "loc" is a placeholder to store whether this is the
  #primary domain in question or whether this domain is a result of either CNAME or Tree climbing look up of the primary
  #domain.

  # returns an array of hashs with CAA information for the particular domain (:flag, :tag, :value).

  def self.DnsRR(domain, loc)
    caa_rr = []
    Resolv::DNS.open do |dns|
      begin
        all_records = dns.getresources(domain, Resolv::DNS::Resource::IN::ANY)
      rescue Resolv::ResolvError
        caa_rr << {:error => true, :error_value => "Error retrieving"}
      rescue Resolv::ResolvTimeout
        caa_rr << {:error => true, :error_value => "Request timed-out trying"}
      else
        all_records.each do |rr|
          if (rr.is_a? Resolv::DNS::Resource::Generic) && (rr.class.name.split('::').last == 'Type257_Class1')
            data = rr.data.bytes
            flag = data[0].to_s
            if data[2..10].pack('c*').eql? "issuewild"
              tag = data[2..10].pack('c*')
              value = data[11..-1].pack('c*')
            elsif ["issue", "iodef"].include? data[2..6].pack('c*')
              tag = data[2..6].pack('c*')
              value = data[7..-1].pack('c*')
            else
              tag = "<<Unknown property-name-value ->> #{data[2..-1].pack('c*')}"
              value = ''
            end
            caa_rr << {:location => "#{domain}#{loc}", :flag => flag, :tag => tag, :value => value}
          end
        end
        return caa_rr
      ensure
        dns.close()
      end
    end
  end


  #Performs CAA check as per RFC 6844 Section 4 (Errata 5065, 5097). The
  #array from the DnsRR method is not manipulated/changed here. It is simply
  #passed on to the calling function. I kept getting an Ruby interpretor error
  #when I tried to return directly. Hence the need for an array to hold and return
  def self.CAA(domain)
    caa = []
    if DnsRR(domain, '').length > 0
      return DnsRR(domain, '(Primary Domain)')
    elsif CNAME(domain) && DnsRR(CNAME(domain), '').length > 0
      return DnsRR(CNAME(domain, '(CNAME)'))
    else
      while domain.to_s.split('.').length > 1
        domain.to_s.split('.').length
        domain = domain.to_s.split('.')[1..-1].join('.')
        if DnsRR(domain, '').length > 0
          caa = DnsRR(domain, '')
        elsif CNAME(domain) && DnsRR(CNAME(domain), '').length > 0
          caa = DnsRR(CNAME(domain), '(Hierarchy->CNAME)')
        end
        break if caa.length > 0
      end
      return caa
    end
  end

  def self.CNAME(domain)
    Resolv::DNS.open do |dns|
      begin
        return dns.getresources(domain, Resolv::DNS::Resource::IN::CNAME)[0].name.to_s rescue nil
      rescue Resolv::ResolvError
        nil
      ensure
        dns.close()
      end
    end
  end

  #Takes a der/pem cert as input and runs each domain in SAN through the CAA check.
  #It doesn't check the CN since the CN should be a part of SAN
  def self.CheckCAA(raw)
    caa_result = []
    begin
      cert = OpenSSL::X509::Certificate.new raw
    rescue OpenSSL::X509::CertificateError
      caa_result << "CAA: Error parsing Certificate"
    else
      san = cert.extensions.find {|e| e.oid == "subjectAltName"}
      san_list = san.to_a[1].split(',')
      san_list.each do |s|
        s.slice! "DNS:"
        result = CAA(s.strip)
        if result.length > 0
          result.each do |r|
            if r[:error]
              caa_result << "CAA: #{r[:error_value]} CAA information for #{s.strip}"
            else
              caa_result << "CAA: #{s.strip} has CAA record at #{r[:location]}. CAA #{r[:flag]} #{r[:tag]} #{r[:value]}"
            end
          end
        else
          caa_result << "CAA: CAA not found for #{s.strip}"
        end
      end
    end
    return caa_result
  end
end
