#!/usr/bin/ruby

# Prefill with the CA/B Forum attributes
attrs = {
'1.3.6.1.4.1.311.60.2.1.1' => 'jurisdictionLocalityName',
'1.3.6.1.4.1.311.60.2.1.2' => 'jurisdictionStateOrProvinceName',
'1.3.6.1.4.1.311.60.2.1.3' => 'jurisdictionCountryName'
}

IO.foreach(ARGV[0]) do |line|
  p = line.strip.split(',')
  next unless p[1] == 'A' && p[2] =~ /^[0-2]/
  oid = p[2].strip.split('.').map(&:strip).join('.')
  name = p[0]
  if !attrs.key? oid
    attrs[oid] = name
  elsif attrs[oid].length < name.length
    attrs[oid] = name
  end
end

def sort_oid(ao, bo)
  a = ao.split('.').map(&:to_i)
  b = bo.split('.').map(&:to_i)
  p = 0
  a.each do |seg|
    return 1 if b[p].nil?
    return 1 if seg > b[p]
    return -1 if seg < b[p]
    p += 1
  end
  if !b[p].nil?
    return -1
  end
  0
end
  

attrs.keys.sort{|a,b|sort_oid(a,b)}.each do |oid|
  puts "'#{oid}' => '#{attrs[oid]}',"
end
