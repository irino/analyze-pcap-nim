## packetdistribution.nim reads pcap file and make their packet size list

import pcap
import std/hashes, std/nativesockets, std/net, std/parseopt, std/streams, std/strformat,
       std/strutils, std/tables

const ETHER_HEADER_SIZE = 14
const IPV4_HEADER_SIZE = 20
const IPV6_HEADER_SIZE = 40

type CommandOptions = object
  ## Commandoptions type contains variables for getopt
  count: uint
  excludeIPv4: bool
  excludeIPv6: bool
  excludeOverMTU: bool
  excludePortZero: bool
  ignorePort: bool
  ignoreProto: bool
  mtu: uint16
  overhead: uint16
  pcapFile: string

type FlowKey = object
  ## FlowKey type contains key (variables in IPv4 or IPv6 header)of flows
  ipVersion: uint8
  proto: uint8
  port: uint16 # TypeCode when ICMP/ICMPv6
  length: uint32

type StatisticsResult = object
  ## Statisticsresult type contains variables for result of calcuration fragment and overhead
  fragmentPerPacket: int
  length: int
  octet: int
  ratio: float
  
proc toUint64(f:FlowKey):uint64 = 
  f.ipVersion.uint64 shl 56 or f.proto.uint64 shl 48 or f.port.uint64 shl 32 or f.length.uint64

proc toCSVString(f:FlowKey):string= 
  "{f.ipVersion.int},{f.proto.int},{f.port.int},{f.length.int}".fmt

proc toFlowKey(u:uint64):FlowKey = 
  FlowKey(ipVersion: (u shr 56).uint8,
          proto: ((u shr 48) and 0x00000000000000ff'u64).uint8,
          port: ((u shr 32) and 0x000000000000ffff'u64).uint16,
          length: (u and 0x00000000ffffffff'u64).uint32)
  
proc fragmentPacket(f:FlowKey, mtu:int, overhead:int):int = 
  var fragmentpacket: int = 1
  if mtu - overhead < f.length.int:
    var fragmentPayloadLength = mtu - overhead - (ETHER_HEADER_SIZE + IPV4_HEADER_SIZE)
    if f.ipVersion == 6'u8:
      fragmentPayloadLength = mtu - overhead - (ETHER_HEADER_SIZE + IPV6_HEADER_SIZE)
    fragmentpacket += (f.length.int - mtu) div fragmentPayloadLength
    if f.length.int mod fragmentpayloadlength > 0:
      fragmentpacket += 1
  fragmentpacket

proc lenIncOverhead(f:FlowKey, fragmentpacket:int, overhead: int):int =  
  var headersize = ETHER_HEADER_SIZE + IPV4_HEADER_SIZE
  if f.ipVersion == 6'u8:
    headersize = ETHER_HEADER_SIZE + IPV6_HEADER_SIZE
  f.length.int + fragmentpacket * overhead + (fragmentpacket - 1) * headersize

proc bytesToUint16(data: openArray[uint8]): uint16 =
  data[0].uint16 shl 8 or data[1]

proc constructStatisticsResult (flowKey:FlowKey, c:int, mtu:int, overhead:int): StatisticsResult =
  var fragmentPerPacket: int = fragmentPacket(flowKey, mtu, overhead)
  var length: int = lenIncOverhead(flowKey, fragmentPerPacket, overhead)
  StatisticsResult(fragmentPerPacket: fragmentPerPacket, length: length, octet: length * c,
                   ratio:length / flowKey.length.int)

proc toString(s:StatisticsResult): string =
  "{s.fragmentPerPacket},{s.length},{s.octet},{s.ratio}".fmt

proc writeResultCSV(flowTable: CountTable[uint64], filename:string, options:CommandOptions) = 
  var csvcontent = "ip,proto,port,length,packet,octet(lenXpkt)"
  if options.mtu.int > 0:
    csvcontent &= ",fragment(len/mtu),length(incFrag),octet(incFrag),ration(incFlag),"
    if options.overhead.int > 0:
      csvcontent &= ",fragment(incOH),length(incOH),octet(incOH),ration(incOH),"
  csvcontent &= "\n"
  # csv content
  var totalOctet: int = 0
  var totalOctetIncFrag: int = 0
  var totalOctetIncOverhead: int = 0
  for u, c in pairs(flowTable):
    var flowKey: FlowKey = u.toFlowKey
    var octet = flowKey.length.int * c
    totalOctet += octet
    csvcontent &= "{flowKey.toCSVString},{c},{octet}".fmt
    if options.mtu.int > 0:
      var result: StatisticsResult = constructStatisticsResult(flowKey, c, options.mtu.int, 0)
      csvcontent &= ",{result.toString}".fmt
      totalOctetIncFrag += result.octet
      if options.overhead.int > 0:
        result = constructStatisticsResult(flowKey, c, options.mtu.int, options.overhead.int)
        csvcontent &= ",{result.toString}".fmt
        totalOctetIncOverhead += result.octet
    csvcontent &= "\n"
  csvcontent &= "-,-,-,-,-,{totalOctet}".fmt
  if options.mtu.int > 0:
    csvcontent &= ",-,-,{totalOctetIncFrag},{totalOctetIncFrag/totalOctet}".fmt
    if options.overhead.int > 0:
      csvcontent &= ",-,-,{totalOctetIncOverhead},{totalOctetIncOverhead/totalOctet}\n".fmt
  writeFile(filename, csvcontent)
  
proc echoHelp() = 
  echo "-c:count (default:0 which means all of packets in pcapfile)"
  echo "--excludeIPv4:true/false (default:false)"
  echo "--excludeIPv6:true/false (default:false)"
  echo "--excludeOverMTU:true/false (default:false)"
  echo "--excludePortZero:true/false (default:false)"
  echo "-h (print this help)"
  echo "--ignorePort:true/false (default:false)"
  echo "--ignoreProto:true/false (default:false)"
  echo "-m:mtu (default:1514 which includes ethernet header size)"
  echo "-o:overhead (default:0)"
  echo "-r:filename"

# main
var parser = initOptParser("", shortNoVal = {'r'}, longNoVal = @["read"])
var options: CommandOptions =
  CommandOptions(count: 0, excludeIPv4: false, excludeIPv6: false,  excludeOverMTU: false,
                 excludePortZero: false, ignorePort: false, ignoreProto: false, mtu:1514,
                 pcapFile:"")
for kind, key, val in parser.getopt():
  case kind
  of cmdEnd: doAssert(false)  # Doesn't happen with getopt()
  of cmdShortOption, cmdLongOption, cmdArgument:
    case key
    of "c":
      options.count = uint(parseUInt(val))
    of "h":
      echoHelp()
      quit(1)
    of "excludeIPv4":
      options.excludeIPv4 = true 
    of "excludeIPv6":
      options.excludeIPv6 = true 
    of "excludeOverMTU":
      options.excludeOverMTU = true 
    of "excludePortZero":
      options.excludePortZero = true 
    of "ignorePort":
      options.ignorePort = true 
    of "ignoreProto":
      options.ignoreProto = true 
    of "m":
      options.mtu = uint16(parseUInt(val))
    of "o":
      options.overhead = uint16(parseUInt(val))
    of "r":
      options.pcapFile = val
echo options

## pcap read
let pcapstream = newFileStream(options.pcapFile, fmRead)
if isNil(pcapstream):
  doAssert(false, "pcapFile is not specified")

let globalHeader = pcapstream.readGlobalHeader()

var upFlowTable = initCountTable[uint64]()
var downFlowTable = initCountTable[uint64]()
var count:uint = 0
var excludedPackets: uint = 0
while (options.count == 0 and not pcapstream.atEnd) or count < options.count:
  let record = pcapstream.readRecord(globalHeader)
  let etype: uint16 = bytesToUint16(record.data[12..13])
  var l4offset: uint32 = ETHER_HEADER_SIZE + IPV4_HEADER_SIZE # default: IPv4
  var ipVersion: uint8 = 4
  var proto: uint8 = 0
  var sport: uint16 = 0
  var dport: uint16 = 0
  if options.excludeOverMTU and options.mtu < record.header.origLen.uint16:
    excludedPackets += 1
    continue
  if not options.excludeIPv4 and etype == 0x0800 and record.header.inclLen >= l4offset.uint32:
    proto = record.data[23]
  if not options.excludeIPv6 and etype == 0x86DD and record.header.inclLen >= (ETHER_HEADER_SIZE + IPV6_HEADER_SIZE).uint32:
    l4offset = ETHER_HEADER_SIZE + IPV6_HEADER_SIZE
    ipVersion = 6
    proto = record.data[20]
  if (proto == IPPROTO_TCP.uint8 or proto == IPPROTO_UDP.uint8) and record.header.inclLen >= l4offset+4:
      sport = bytesToUint16(record.data[l4offset..l4offset+1])
      dport = bytesToUint16(record.data[l4offset+2..l4offset+3])
  if options.excludePortZero and sport == 0'u8 and dport == 0'u8:
    excludedPackets += 1
    continue
  if options.ignoreProto:
    proto = 0
  var flowKeyUint64: uint64
  if sport < dport:
    if options.ignorePort:
      sport = 0
    flowKeyUint64 = FlowKey(ipVersion: ipVersion, proto: proto, port: sport, length:record.header.origLen).toUint64
    downflowTable.inc(flowKeyUint64)
  else:
    if options.ignorePort:
      dport = 0
    flowKeyUint64 = FlowKey(ipVersion: ipVersion, proto: proto, port: dport, length:record.header.origLen).toUint64
    upflowTable.inc(flowKeyUint64)
  count += 1

upFlowTable.sort()
downFlowTable.sort()

echo "excludedPackets: " & intToStr(excludedPackets.int)

writeResultCSV(upFlowTable, options.pcapFile & ".up.csv", options)
writeResultCSV(downFlowTable, options.pcapFile & ".down.csv", options)
