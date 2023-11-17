//// Blake

// set power, power gain, noise db for nbiot nodes
// set energy, memory and time calculation
// send data, print message in server
// split hash into 4 partst and send data
// check data at server and authenticate

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-helper.h"
#include "ns3/lte-module.h"
#include "ns3/spectrum-module.h"
//#include "ns3/yans-wifi-channel.h"
#include "ns3/hash.h"
#include "ns3/energy-module.h"
#include "ns3/wifi-radio-energy-model-helper.h"

#include <iostream>
#include <stack>


#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <iostream>
#include <sstream>



 #include <fstream>
 #include <vector>
 #include <string>
 #include "ns3/core-module.h"
 #include "ns3/network-module.h"
 #include "ns3/mobility-module.h"
 #include "ns3/config-store-module.h"
 #include "ns3/energy-module.h"
 #include "ns3/internet-module.h"
 #include "ns3/yans-wifi-helper.h"
 #include "ns3/wifi-radio-energy-model-helper.h"

 #include "ns3/point-to-point-module.h"
 #include "ns3/tag.h"
 #include "ns3/packet.h"
 #include "ns3/string.h"
 #include <sys/time.h>
 //#include "ns3/packet.h"
 //#include "ns3/header.h"
 #include <unistd.h>
 #include <chrono>

using namespace ns3;
using namespace std;
using namespace std::chrono;

NS_LOG_COMPONENT_DEFINE ("FirstScriptExample");


///// Calculate memory usage (in kB)
void process_mem_usage(double& vm_usage, double& resident_set)
{
    vm_usage     = 0.0;
    resident_set = 0.0;

    // the two fields we want
    unsigned long vsize;
    long rss;
    {
        std::string ignore;
        std::ifstream ifs("/proc/self/stat", std::ios_base::in);
        ifs >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
                >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore >> ignore
                >> ignore >> ignore >> vsize >> rss;
    }

    long page_size_kb = sysconf(_SC_PAGE_SIZE) / 1024; // in case x86-64 is configured to use 2MB pages
    vm_usage = vsize / 1024.0;
    resident_set = rss * page_size_kb;
}
/////


 static inline std::string
 PrintReceivedPacket (Address& from)
 {
   InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (from);
  
   std::ostringstream oss;
   oss << "--\nReceived one packet! Socket: " << iaddr.GetIpv4 ()
       << " port: " << iaddr.GetPort ()
       << " at time = " << Simulator::Now ().GetSeconds ()
       << "\n--";
  
   return oss.str ();
 }
  
 void
 ReceivePacket (Ptr<Socket> socket)
 {
   Ptr<Packet> packet;
   Address from;
   while ((packet = socket->RecvFrom (from)))
     {
       if (packet->GetSize () > 0)
         {
             NS_LOG_UNCOND (PrintReceivedPacket (from));
         }
     }
 }



 //#include <string.h>
 //char* a = strdup("hello");
 //uint8_t a[1] = {1};
 //uint8_t header[2] = {1,2};
 //uint8_t sender_message;
 //uint8_t sender_hash;


 static void
 GenerateTraffic (Ptr<Socket> socket, uint32_t pktSize, Ptr<Node> n,
                  uint32_t pktCount, Time pktInterval)
 {
   while (pktCount > 0)
     {
       Ptr<Packet> packet = Create<Packet> (pktSize); //message packet
       //uint8_t *buffer = new uint8_t (packet->GetSize ()); //copy message from message packet
       //sender_message = packet->CopyData (buffer, packet->GetSize ());

       //Ptr<Packet> packet1 = Create<Packet> (3); //hash packet
       //uint8_t *buffer1 = new uint8_t (packet1->GetSize ()); //copy hash form hash packet
       //sender_hash = packet1->CopyData (buffer1, packet1->GetSize ());

       //packet->AddAtEnd (packet1);

       // add tag (to number the packets) - Size of tag = 20bytes
       //MyTag tag;
       //tag.SetSimpleValue (0x56);
       //packet->AddPacketTag (tag);

       // add header (hash of message) - Size of header = 8bytes
       //YHeader yHeader;
       //yHeader.SetData (0xffffff);
       //packet->AddHeader (yHeader);

/*
       // add trailer - Size of trailer = 8bytes
       ZTrailer zTrailer;
       zTrailer.SetData (0xdeadbeaf);
       packet->AddTrailer (zTrailer);
*/

       socket->Send (packet);
       //socket->Send (Create<Packet> (pktSize)); // send packete with anonymous data
       //socket->Send (Create<Packet> (reinterpret_cast<const uint8_t*> (a), 5)); // send string
       //socket->Send (Create<Packet> (a, 3)); // send array
       Simulator::Schedule (pktInterval, &GenerateTraffic, socket, pktSize, n,
                            pktCount - 1, pktInterval);
       pktCount = pktCount - 1; 
     }
   //else
   //  {
   //    socket->Close ();
   //  }
 }


 void
 RemainingEnergy (double oldValue, double remainingEnergy)
 {
   NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                  << "s Current remaining energy = " << remainingEnergy << "J");
 }
  
 void
 TotalEnergy (double oldValue, double totalEnergy)
 {
   NS_LOG_UNCOND (Simulator::Now ().GetSeconds ()
                  << "s Total energy consumed by radio = " << totalEnergy << "J");
 }
  
  

    unsigned long long rdtscl(void)
  {
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));                        
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );  
  }



static void RxDrop (Ptr<const Packet> p)
{
  NS_LOG_UNCOND ("RxDrop at " << Simulator::Now ().GetSeconds ());
}

void BandwidthTrace()
{
  Config::Set("/NodeList/0/DeviceList/0/$ns3::PointToPointNetDevice/DataRate", StringValue("180kbps") );
}



   ///// Start clock
   auto start = std::chrono::high_resolution_clock::now();
   /////


//// functions for Blake
#define U8TO32_BIG(p)					      \
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |  \
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))

#define U32TO8_BIG(p, v)				        \
  (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
  (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      );

#define U8TO64_BIG(p) \
  (((uint64_t)U8TO32_BIG(p) << 32) | (uint64_t)U8TO32_BIG((p) + 4))

#define U64TO8_BIG(p, v)		      \
  U32TO8_BIG((p),     (uint32_t)((v) >> 32)); \
  U32TO8_BIG((p) + 4, (uint32_t)((v)      ));

typedef struct
{
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t  buf[64];
} state256;

typedef state256 state224;

typedef struct
{
  uint64_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[128];
} state512;

typedef state512 state384;

const uint8_t sigma[][16] =
{
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
  {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
  {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
  { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
  {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13 , 0 },
  { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
  {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
  {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
  { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
  { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
  { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 }
};

const uint32_t u256[16] =
{
  0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
  0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
  0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
  0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917
};

const uint64_t u512[16] =
{
  0x243f6a8885a308d3ULL, 0x13198a2e03707344ULL, 
  0xa4093822299f31d0ULL, 0x082efa98ec4e6c89ULL,
  0x452821e638d01377ULL, 0xbe5466cf34e90c6cULL, 
  0xc0ac29b7c97c50ddULL, 0x3f84d5b5b5470917ULL,
  0x9216d5d98979fb1bULL, 0xd1310ba698dfb5acULL, 
  0x2ffd72dbd01adfb7ULL, 0xb8e1afed6a267e96ULL,
  0xba7c9045f12c7f99ULL, 0x24a19947b3916cf7ULL, 
  0x0801f2e2858efc16ULL, 0x636920d871574e69ULL
};


static const uint8_t padding[129] =
{
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};



void blake256_compress( state256 *S, const uint8_t *block )
{
  uint32_t v[16], m[16], i;
#define ROT(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G(a,b,c,d,e)          \
  v[a] += (m[sigma[i][e]] ^ u256[sigma[i][e+1]]) + v[b]; \
  v[d] = ROT( v[d] ^ v[a],16);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c],12);        \
  v[a] += (m[sigma[i][e+1]] ^ u256[sigma[i][e]])+v[b]; \
  v[d] = ROT( v[d] ^ v[a], 8);        \
  v[c] += v[d];           \
  v[b] = ROT( v[b] ^ v[c], 7);

  for( i = 0; i < 16; ++i )  m[i] = U8TO32_BIG( block + i * 4 );

  for( i = 0; i < 8; ++i )  v[i] = S->h[i];

  v[ 8] = S->s[0] ^ u256[0];
  v[ 9] = S->s[1] ^ u256[1];
  v[10] = S->s[2] ^ u256[2];
  v[11] = S->s[3] ^ u256[3];
  v[12] = u256[4];
  v[13] = u256[5];
  v[14] = u256[6];
  v[15] = u256[7];

  /* don't xor t when the block is only padding */
  if ( !S->nullt )
  {
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for( i = 0; i < 14; ++i )
  {
    /* column step */
    G( 0,  4,  8, 12,  0 );
    G( 1,  5,  9, 13,  2 );
    G( 2,  6, 10, 14,  4 );
    G( 3,  7, 11, 15,  6 );
    /* diagonal step */
    G( 0,  5, 10, 15,  8 );
    G( 1,  6, 11, 12, 10 );
    G( 2,  7,  8, 13, 12 );
    G( 3,  4,  9, 14, 14 );
  }

  for( i = 0; i < 16; ++i )  S->h[i % 8] ^= v[i];

  for( i = 0; i < 8 ; ++i )  S->h[i] ^= S->s[i % 4];
}


void blake256_init( state256 *S )
{
  S->h[0] = 0x6a09e667;
  S->h[1] = 0xbb67ae85;
  S->h[2] = 0x3c6ef372;
  S->h[3] = 0xa54ff53a;
  S->h[4] = 0x510e527f;
  S->h[5] = 0x9b05688c;
  S->h[6] = 0x1f83d9ab;
  S->h[7] = 0x5be0cd19;
  S->t[0] = S->t[1] = S->buflen = S->nullt = 0;
  S->s[0] = S->s[1] = S->s[2] = S->s[3] = 0;
}


void blake256_update( state256 *S, const uint8_t *in, int inlen )
{
  int left = S->buflen;
  int fill = 64 - left;

  /* data left and data received fill a block  */
  if( left && ( inlen >= fill ) )
  {
    memcpy( ( void * ) ( S->buf + left ), ( void * ) in, fill );
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, S->buf );
    in += fill;
    inlen  -= fill;
    left = 0;
  }

  /* compress blocks of data received */
  while( inlen >= 64 )
  {
    S->t[0] += 512;

    if ( S->t[0] == 0 ) S->t[1]++;

    blake256_compress( S, in );
    in += 64;
    inlen -= 64;
  }

  /* store any data left */
  if( inlen > 0 )
  {
    memcpy( ( void * ) ( S->buf + left ),   \
            ( void * ) in, ( size_t ) inlen );
    S->buflen = left + ( int )inlen;
  }
  else S->buflen = 0;
}


void blake256_final( state256 *S, uint8_t *out )
{
  uint8_t msglen[8], zo = 0x01, oo = 0x81;
  int lo = S->t[0] + ( S->buflen << 3 ), hi = S->t[1];

  /* support for hashing more than 2^32 bits */
  if ( lo < ( S->buflen << 3 ) ) hi++;

  U32TO8_BIG(  msglen + 0, hi );
  U32TO8_BIG(  msglen + 4, lo );

  if ( S->buflen == 55 )   /* one padding byte */
  {
    S->t[0] -= 8;
    blake256_update( S, &oo, 1 );
  }
  else
  {
    if ( S->buflen < 55 )   /* enough space to fill the block  */
    {
      if ( !S->buflen ) S->nullt = 1;

      S->t[0] -= 440 - ( S->buflen << 3 );
      blake256_update( S, padding, 55 - S->buflen );
    }
    else   /* need 2 compressions */
    {
      S->t[0] -= 512 - ( S->buflen << 3 );
      blake256_update( S, padding, 64 - S->buflen );
      S->t[0] -= 440;
      blake256_update( S, padding + 1, 55 );
      S->nullt = 1;
    }

    blake256_update( S, &zo, 1 );
    S->t[0] -= 8;
  }

  S->t[0] -= 64;
  blake256_update( S, msglen, 8 );
  U32TO8_BIG( out + 0, S->h[0] );
  U32TO8_BIG( out + 4, S->h[1] );
  U32TO8_BIG( out + 8, S->h[2] );
  U32TO8_BIG( out + 12, S->h[3] );
  U32TO8_BIG( out + 16, S->h[4] );
  U32TO8_BIG( out + 20, S->h[5] );
  U32TO8_BIG( out + 24, S->h[6] );
  U32TO8_BIG( out + 28, S->h[7] );
}


void blake256_hash( uint8_t *out, const uint8_t *in, uint64_t inlen )
{
  state256 S;
  blake256_init( &S );
  blake256_update( &S, in, inlen );
  blake256_final( &S, out );
  
  std::cout<<out<<std::endl;
  //std::cout<<sizeof(out)<<std::endl;
}


void blake256_test()
{
  int i, v;
  uint8_t in[72], out[32];
  uint8_t test1[] =
  {
    0x0c, 0xe8, 0xd4, 0xef, 0x4d, 0xd7, 0xcd, 0x8d,
    0x62, 0xdf, 0xde, 0xd9, 0xd4, 0xed, 0xb0, 0xa7,
    0x74, 0xae, 0x6a, 0x41, 0x92, 0x9a, 0x74, 0xda,
    0x23, 0x10, 0x9e, 0x8f, 0x11, 0x13, 0x9c, 0x87
  };
  uint8_t test2[] =
  {
    0xd4, 0x19, 0xba, 0xd3, 0x2d, 0x50, 0x4f, 0xb7,
    0xd4, 0x4d, 0x46, 0x0c, 0x42, 0xc5, 0x59, 0x3f,
    0xe5, 0x44, 0xfa, 0x4c, 0x13, 0x5d, 0xec, 0x31,
    0xe2, 0x1b, 0xd9, 0xab, 0xdc, 0xc2, 0x2d, 0x41
  };
  memset( in, 0, 72 );
  blake256_hash( out, in, 1 );
  v = 0;

  for( i = 0; i < 32; ++i )
  {
    if ( out[i] != test1[i] ) v = 1;
  }

  if ( v ) printf( "test 1 error\n" );

  blake256_hash( out, in, 72 );
  v = 0;

  for( i = 0; i < 32; ++i )
  {
    if ( out[i] != test2[i] ) v = 1;
  }

  if ( v ) printf( "test 2 error\n" );
}


////


int main (int argc, char *argv[])
{

  double txPowerStart = 0.0; // dbm
  double txPowerEnd = 15.0; // dbm
  uint32_t nTxPowerLevels = 16;
  uint32_t txPowerLevel = 0;
  
  bool verbose = false;
  
  CommandLine cmd (__FILE__);
  cmd.AddValue ("txPowerStart", "Minimum available transmission level (dbm)", txPowerStart);
  cmd.AddValue ("txPowerEnd", "Maximum available transmission level (dbm)", txPowerEnd);
  cmd.AddValue ("nTxPowerLevels", "Number of transmission power levels available between txPowerStart and txPowerEnd included", nTxPowerLevels);
  cmd.AddValue ("txPowerLevel", "Transmission power level", txPowerLevel);
  

 
  std::string phyMode ("DsssRate1Mbps");
  // But since this is a realtime script, don't allow the user to mess with
  // that.
  //
  //GlobalValue::Bind ("SimulatorImplementationType", 
  //                   StringValue ("ns3::RealtimeSimulatorImpl"));

  LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);


  // disable fragmentation for frames below 72 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold",
                       StringValue ("72"));
  // turn off RTS/CTS for frames below 72 bytes
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold",
                       StringValue ("72"));
  // Fix non-unicast data rate to be the same as that of unicast
  Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                       StringValue (phyMode));
  


   ///// memory usage
   using std::cout;
   using std::endl;

   double vm, rss;
   process_mem_usage(vm, rss);
   std::cout << "VM: " << vm << "; RSS: " << rss << std::endl;
   /////


  NodeContainer nodes;
  nodes.Create (2);
  NodeContainer networkNodes;
  networkNodes.Add (nodes.Get (0));
  networkNodes.Add (nodes.Get (1));

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("26kbps"));
  pointToPoint.SetDeviceAttribute ("Mtu", UintegerValue (85));
  pointToPoint.SetChannelAttribute ("Delay", TimeValue (Seconds (0.3))); //StringValue ("100ns")

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes);
  
 
 
    // The below set of helpers will help us to put together the wifi NICs we want
   WifiHelper wifi;
   if (verbose)
     {
       wifi.EnableLogComponents ();
     }
   wifi.SetStandard (WIFI_STANDARD_80211b);
  
   /***************************************************************************/
   //YansWifiPhyHelper wifiPhy;
   YansWifiPhyHelper wifiPhy = YansWifiPhyHelper ();
   wifiPhy.Set ("RxGain", DoubleValue (40));
   wifiPhy.Set ("TxGain", DoubleValue (70));
   //wifiPhy.Set ("TxGain", DoubleValue (offset + Prss));
   //wifiPhy.Set ("CcaMode1Threshold", DoubleValue (0.0));
  
   YansWifiChannelHelper wifiChannel;
   wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
   wifiChannel.AddPropagationLoss ("ns3::FriisPropagationLossModel");
   
   // create wifi channel
   Ptr<YansWifiChannel> wifiChannelPtr = wifiChannel.Create ();
   wifiPhy.SetChannel (wifiChannelPtr);
  
   // Add a MAC and disable rate control
   WifiMacHelper wifiMac;
   wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager", "DataMode",
                                 StringValue (phyMode), "ControlMode",
                                 StringValue (phyMode));
   // Set it to ad-hoc mode
   wifiMac.SetType ("ns3::AdhocWifiMac");
  
   //NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, networkNodes);
  
   uint64_t distanceToRx = 100;
   MobilityHelper mobility;
   Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
   positionAlloc->Add (Vector (0.0, 0.0, 0.0));
   positionAlloc->Add (Vector (2 * distanceToRx, 0.0, 0.0));
   mobility.SetPositionAllocator (positionAlloc);
   mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
   mobility.Install (nodes);
 
  
/*
    /////////////////////////////////////////////////////////////////////////////////
   // energy source
   BasicEnergySourceHelper basicSourceHelper;
   // configure energy source
   basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (3.6)); //https://tech-journal.semtech.com/analyzing-nb-iot-and-lorawan-sensor-battery-life - battery is 1000-2000mAh, volt is 3.6V

   // install source
   EnergySourceContainer sources = basicSourceHelper.Install (nodes);
   // device energy model //
   WifiRadioEnergyModelHelper radioEnergyHelper;
   // configure radio energy model
   radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0000217)); //https://waviot.com/catalog/electric-meters/waviot-single-phase-electricity-meter/ - 5mW, 230V
   //radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.0000217));
   // install device model
   DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (devices, sources);
   /////////////////////////////////////////////////////////////////////////////////
*/


  /*
  //// WiFi channel attributes
  WifiHelper wifi;
  YansWifiPhyHelper wifiPhy;
  
  wifiPhy.Set ("TxPowerStart", DoubleValue (txPowerStart));
  wifiPhy.Set ("TxPowerEnd", DoubleValue (txPowerEnd));
  wifiPhy.Set ("TxPowerLevels", UintegerValue (nTxPowerLevels));
 
  YansWifiChannelHelper wifiChannel = YansWifiChannelHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ()); 
 
  // Add a mac and set the selected tx power level
  WifiMacHelper wifiMac;
  wifi.SetRemoteStationManager ("ns3::ArfWifiManager", "DefaultTxPowerLevel", UintegerValue (txPowerLevel));
  // Set it to adhoc mode
  wifiMac.SetType ("ns3::AdhocWifiMac");
  NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, c);
  ////
  */


  //// Set pathloss model and bandwidth
  Ptr<LteHelper> lteHelper = CreateObject<LteHelper> ();
  lteHelper->SetHandoverAlgorithmType ("ns3::NoOpHandoverAlgorithm"); // disable automatic handover
  lteHelper->SetAttribute ("PathlossModel", StringValue ("ns3::Cost231PropagationLossModel"));
  lteHelper->SetEnbDeviceAttribute ("DlBandwidth", UintegerValue (25));
  lteHelper->SetEnbDeviceAttribute ("UlBandwidth", UintegerValue (25));
  ////

  
  //// introduce error rate for packet loss
  Ptr<RateErrorModel> em = CreateObject<RateErrorModel> ();
  em->SetAttribute ("ErrorRate", DoubleValue (0.0001));
  devices.Get (1)->SetAttribute ("ReceiveErrorModel", PointerValue (em));
  
  devices.Get (1)->TraceConnectWithoutContext("PhyRxDrop", MakeCallback (&RxDrop));
  ////
  

  /*
  //// set node positions
  MobilityHelper mobility;
  mobility.SetMobilityModel ("ns3::SteadyStateRandomWaypointMobilityModel",
                             //"MinSpeed",DoubleValue (5.0),"MaxSpeed",DoubleValue (10.0),
                             //"MinPause",DoubleValue (0.04),"MaxPause",DoubleValue (0.04),
                             "MinX", DoubleValue (0.0),"MaxX", DoubleValue (10.0),
                             "MinY", DoubleValue (0.0),"MaxY", DoubleValue (110.0));

  mobility.Install (nodes);
  ////
  */

  InternetStackHelper stacks;
  stacks.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");

  Ipv4InterfaceContainer interfaces = address.Assign (devices);


/*
 Users may find it convenient to initialize echo packets with actual data;
 the below lines suggest how to do this

  echoClient.SetFill (apps.Get (0), "Hello World");

  echoClient.SetFill (apps.Get (0), 0xa5, 1024);

  uint8_t fill[] = { 0, 1, 2, 3, 4, 5, 6};
  echoClient.SetFill (apps.Get (0), fill, sizeof(fill), 1024);
*/


  //// Blake hash generation

#define BLOCK256 64
  FILE *fp;
  int i, j, bytesread;
  uint8_t in[BLOCK256], out[32];
  state256 S;
  blake256_test();

  for( i = 1; i < argc; ++i )
  {
    fp = fopen( *( argv + i ), "r" );

    if ( fp == NULL )
    {
      printf( "Error: unable to open %s\n", *( argv + i ) );
      return 1;
    }

    blake256_init( &S );

    while( 1 )
    {
      bytesread = fread( in, 1, BLOCK256, fp );

      if ( bytesread )
        blake256_update( &S, in, bytesread );
      else
        break;
    }

    blake256_final( &S, out );

    for( j = 0; j < 32; ++j )
      printf( "%02x", out[j] );

    printf( " %s\n", *( argv + i ) );
    fclose( fp );
  }
  
  ////  




  //// formation of message+tag
  
  // message + tag
  std::string m1 = "abcdefghabcdefg";
  
  stringstream ss;
  ss<<out;
  string s;
  ss>>s;
  
  std::string M1 = m1+s;          //24B
  ////


  // store variables received at server in stack
  stack<std::string> servermessages; 


/*
   /////////////////////////////////////////////////////////////////////////////
   // all sources are connected to node 1
   // energy source
   Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource> (sources.Get (1));
   basicSourcePtr->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergy));
   // device energy model
   Ptr<DeviceEnergyModel> basicRadioModelPtr =
     basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
   NS_ASSERT (basicRadioModelPtr != NULL);
   basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption", MakeCallback (&TotalEnergy));
   ////////////////////////////////////////////////////////////////////////////
*/
    


  //// client1
  UdpEchoClientHelper echoClient1 (interfaces.GetAddress (1), 9);
  echoClient1.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient1.SetAttribute ("Interval", TimeValue (Seconds (1.0))); //interPacketInterval
  echoClient1.SetAttribute ("PacketSize", UintegerValue (10));
  //echoClient.SetAttribute ("txPower", UintegerValue (35));
  
  ApplicationContainer clientApps1 = echoClient1.Install (nodes.Get (0));
  echoClient1.SetFill (clientApps1.Get (0), M1);
  clientApps1.Start (Seconds (2.0));
  clientApps1.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(0)<<std::endl;


  // server1
  UdpEchoServerHelper echoServer1 (9);

  ApplicationContainer serverApps1 = echoServer1.Install (nodes.Get (1));
  //serverApps.SetAttribute ("txPower", UintegerValue (23));
  serverApps1.Start (Seconds (1.0));
  serverApps1.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(1)<<std::endl;
  
  std::stringstream aa;
  aa << nodes.Get(1);
  //std::cout << aa.str() <<std::endl;

  std::stringstream bb;
  bb << nodes.Get(0);
  //std::cout << bb.str() <<std::endl;
  
  servermessages.push(aa.str());
  ////




  // pop server variables from stack  
  std::string AA = servermessages.top();

  AA = AA.substr(0, AA.size()-6);
  
  std::string BB = bb.str();

  BB = BB.substr(0, BB.size()-6);
  

  if (BB == AA)
  {
  std::cout << "M1 verified" <<std::endl;
  }
  else
  {
  std::cout << "M1 not verified" <<std::endl;
  }




  
  // generate trace file
  AsciiTraceHelper ascii;
  pointToPoint.EnableAsciiAll (ascii.CreateFileStream ("2.tr"));
  pointToPoint.EnablePcapAll ("2", true);

  // set channel bandwidth to 180kHz
  Simulator::Schedule (Seconds(1) , &BandwidthTrace); 

  Simulator::Run ();

/*
   for (DeviceEnergyModelContainer::Iterator iter = deviceModels.Begin (); iter != deviceModels.End (); iter ++)
     {
       double energyConsumed = (*iter)->GetTotalEnergyConsumption ();
       NS_LOG_UNCOND ("End of simulation (" << Simulator::Now ().GetSeconds ()
                      << "s) Total energy consumed by radio = " << energyConsumed << "J");
       //NS_ASSERT (energyConsumed <= 0.1);
     }
*/

   ///// Stop clock
   auto stop = high_resolution_clock::now();
   auto duration = duration_cast<microseconds>(stop - start);
   cout << "Time=" << duration.count()/1000 << "milliseconds" << endl;
   /////

 //cout<<rdtscl()<<endl;

  Simulator::Destroy ();
  return 0;
}
