# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "ipaddr"

class LogStash::Filters::Mtools < LogStash::Filters::Base

  config_name "mtools"

  # The source array of origin *pn strings
  config :pnumbers, :validate => :array

  # The source array of origin *pn strings
  config :ipaddress, :validate => :array

  # The subfields terminator
  config :terminator, :validate => :string, :default => ":"
  
  # The message field to detect nonascii chars
  config :inspect_ascii, :validate => :string
  
  public
  def register
  end # def register

  public
  def filter(event)
    pn_to_array(event) if @pnumbers
    str_to_ipstr(event) if @ipaddress
    drop_if_nonascii(event) if@inspect_ascii
    filter_matched(event)
  end # def filter


  private
  def pn_to_array(event)
    if @pnumbers
      pnumbers.each do |pn|
	attr = event.get(pn)
	if !attr.nil?
	  pn_arr = attr.split(@terminator)
	  if pn_arr.size > 2
	    new_field = {"type"=>"#{pn_arr[0]}", "class"=>"#{pn_arr[1]}", "number"=>"#{pn_arr[2]}"}
	    event.set(pn, new_field)
	  elsif pn_arr.size == 1
	    new_field = {"number"=>"#{pn_arr[0]}"}
	    event.set(pn, new_field)
	  end
        end
      end
    else
      logger.fatal("No pnumbers array provided")
    end
  end # def pn_to_array

  private
  def drop_if_nonascii(event)
    if @inspect_ascii
      msg = event.get(@inspect_ascii)
      unless msg.ascii_only?
	event.tag("_nonasciifailure")
      end
    end
  end # def drop_if_nonascii

  private
  def str_to_ipstr(event)
    if @ipaddress
      @ipaddress.each do |ip|
	if !ip.nil?
	  #if ipstr = event.get(ip)
	  strip = IPAddr.new(event.get(ip).to_i(16),Socket::AF_INET)
	  #logger.warn("ERR",:ip => ip, :eventval=> event.get(ip), :str=>"#{strip}")
	  event.set(ip, IPAddr.new(event.get(ip).to_i(16),Socket::AF_INET).to_s)
	end
      end
    else
      logger.fatal("No ipaddress array provided")
    end
  end

end # class LogStash::Filters::Mtools
