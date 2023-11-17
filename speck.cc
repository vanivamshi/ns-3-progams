//// Speck

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

#include <iostream>
#include <stack>


#include <stdio.h>
#include <string.h>
#include <stdlib.h>



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


//// functions for Speck
#ifndef __SPECK_H
#define __SPECK_H

#ifndef USUAL_TYPES
#define USUAL_TYPES
typedef unsigned char byte;
typedef unsigned int  uint;
//typedef unsigned long long uint64_t;
#endif /* USUAL_TYPES */

#ifndef BOOL
#define BOOL    int
#define FALSE   0
#define TRUE    1
#endif

// Define size of block and key
#define SPECK_BITS 128

#if (SPECK_BITS==128)
#define SPECK_WBYTES 8
#define SPECK_BBYTES (2*SPECK_WBYTES)
#define SPECK_ROUNDS 32
#elif (SPECK_BITS==112)
#define SPECK_WBYTES 7
#define SPECK_BBYTES (2*SPECK_WBYTES)
#define SPECK_ROUNDS 30
#elif (SPECK_BITS==96)
#define SPECK_WBYTES 6
#define SPECK_BBYTES (2*SPECK_WBYTES)
#define SPECK_ROUNDS 28
#elif (SPECK_BITS==80)
#define SPECK_WBYTES 5
#define SPECK_BBYTES (2*SPECK_WBYTES)
#define SPECK_ROUNDS 26
#elif (SPECK_BITS==64)
#define SPECK_WBYTES 4
#define SPECK_BBYTES (2*SPECK_WBYTES)
#define SPECK_ROUNDS 24
#else
#error "SPECK_BITS undefined"
#endif // SPECK_BITS

void speckEncrypt(byte *key, byte *pt, byte *ct);
void speckDecrypt(byte *key, byte *ct, byte *pt);

#endif /* __SPECK_H */




void speckDecrypt(byte *key, byte *ct, byte *pt) {
    byte p0, k0;
    byte kt[SPECK_BBYTES];
    int i, j;
    int ak;
    int ap;
    byte *p = &pt[SPECK_WBYTES];
    byte *k = &kt[SPECK_WBYTES];

    for (i = 0; i < SPECK_BBYTES; i++) {
        kt[i] = key[i];
        pt[i] = ct[i];
    }

    //calculates modified key of encrypt to start calculation
    for (i = 0; i < SPECK_ROUNDS; i++) {
        k0 = k[0];
        ak = 0;
        for (j = 0; j < SPECK_WBYTES-1; j++) {
            ak += (uint)kt[j] + (uint)k[j + 1]; k[j] = (byte)ak; ak >>= 8;
        }
        ak += (uint)kt[SPECK_WBYTES-1] + (uint)k0; k[SPECK_WBYTES-1] = (byte)ak;
        kt[SPECK_WBYTES] ^= (byte)i;
        k0 = kt[SPECK_WBYTES-1];
        for (j = SPECK_WBYTES-1; j > 0; j--) {
            kt[j] = ((kt[j] << 3) | (kt[j - 1] >> 5)) ^ k[j];
        }
        kt[0] = ((kt[0] << 3) | (k0 >> 5)) ^ k[0];
    }

    //starts decryption
    for(i = SPECK_ROUNDS-1; i >= 0; i--) {
        //decrypts first part of message
        for(j = 0; j < SPECK_WBYTES; j++) {
            kt[j] ^= k[j];
            pt[j] ^= p[j];
        }
        k0 = kt[0];
        p0 = pt[0];
        for(j = 0; j < SPECK_WBYTES-1; j++) {
            kt[j] = ((kt[j] >> 3) | (kt[j+1] << 5));
            pt[j] = ((pt[j] >> 3) | (pt[j+1] << 5));
        }
        kt[SPECK_WBYTES-1] = ((kt[SPECK_WBYTES-1] >> 3) | (k0 << 5));
        pt[SPECK_WBYTES-1] = ((pt[SPECK_WBYTES-1] >> 3) | (p0 << 5));

        //decrypts second part of message
        k[0] ^= (byte)i;
        for(j = 0; j < SPECK_WBYTES; j++) {
            p[j] ^= kt[j];
        }
        ak = 0;
        ap = 0;
        for(j = 0; j < SPECK_WBYTES; j++) {
            ak += (uint)k[j] - (uint)kt[j];
            k[j] = (byte)ak;
            ak >>= 8;
            ap += (uint)p[j] - (uint)pt[j];
            p[j] = (byte)ap;
            ap >>= 8;
        }

        k0 = k[SPECK_WBYTES-1];
        p0 = p[SPECK_WBYTES-1];
        for(j = SPECK_WBYTES-1; j > 0; j--) {
            k[j] = k[j-1];
            p[j] = p[j-1];
        }
        k[0] = k0;
        p[0] = p0;
    }
}

void speckEncrypt(byte *key, byte *pt, byte *ct) {
    byte c0, k0;
    byte kt[SPECK_BBYTES];
    int i, j;
    uint ac, ak;
    byte *c = &ct[SPECK_WBYTES];
    byte *k = &kt[SPECK_WBYTES];
    for (i = 0; i < SPECK_BBYTES; i++) {
        kt[i] = key[i];
        ct[i] = pt[i];
    }
    for (i = 0; i < SPECK_ROUNDS; i++) {
        c0 = c[0];
        k0 = k[0];
        ac = 0;
        ak = 0;
        for (j = 0; j < SPECK_WBYTES-1; j++) {
            ac += (uint)ct[j] + (uint)c[j + 1]; c[j] = (byte)ac ^ kt[j]; ac >>= 8;
            ak += (uint)kt[j] + (uint)k[j + 1]; k[j] = (byte)ak;         ak >>= 8;
        }
        ac += (uint)ct[SPECK_WBYTES-1] + (uint)c0; c[SPECK_WBYTES-1] = (byte)ac ^ kt[SPECK_WBYTES-1];
        ak += (uint)kt[SPECK_WBYTES-1] + (uint)k0; k[SPECK_WBYTES-1] = (byte)ak;
        kt[SPECK_WBYTES] ^= (byte)i;

        c0 = ct[SPECK_WBYTES-1];
        k0 = kt[SPECK_WBYTES-1];
        for (j = SPECK_WBYTES-1; j > 0; j--) {
            ct[j] = ((ct[j] << 3) | (ct[j - 1] >> 5)) ^ c[j];
            kt[j] = ((kt[j] << 3) | (kt[j - 1] >> 5)) ^ k[j];
        }
        ct[0] = ((ct[0] << 3) | (c0 >> 5)) ^ c[0];
        kt[0] = ((kt[0] << 3) | (k0 >> 5)) ^ k[0];
    }
}




#define ENCRYPT
// #define DECRYPT

static void Display(const char *tag, unsigned char block[], int block_size) {
    int i;
    printf("%s\t=\t", tag);
    for (i = 0; i < block_size; i++) {
        printf("%02X", block[i]);
    }
    printf("\n");
}

static BOOL equalBlocks(byte first_block[], byte second_block[], const int block_sizes) {
  int i;
  BOOL result = TRUE;

  for (i = 0; i < block_sizes; i++) {
    if(first_block[i] != second_block[i]) {
      result = FALSE;
      break;
    }
  }

  return result;
}

BOOL speckTest(int ntests) {
  byte key[SPECK_BBYTES], pt[SPECK_BBYTES], ct[SPECK_BBYTES], ct_aux[SPECK_BBYTES];

  //test values for 128-bit block and key sizes
  memcpy(key, "\x2b\x7e\x15\x16\x78\xcf\xa7\xca\xc4\xd7\x57\xe9\x7b\xbd\x2a\x48", SPECK_BBYTES);
  memcpy(pt, "\x02\x05\x05\x09\x54\x6f\x6d\xe1\x73\x20\x41\x2e\x20\x41\x7a\x65", SPECK_BBYTES);
  memcpy(ct_aux, "\x2D\x14\xF7\xE2\x96\x62\xFA\xC8\xD3\x8F\x1B\xBE\x8A\xBF\x5A\x19", SPECK_BBYTES);

  for(int j = 0; j < ntests; j++) {
    #ifdef ENCRYPT
      speckEncrypt(key, pt, ct);
    #elif defined(DECRYPT)
      speckDecrypt(key, ct_aux, ct);
    #endif

    Display("key", key, SPECK_BBYTES);
    Display("pt", pt, SPECK_BBYTES);
    Display("ct", ct, SPECK_BBYTES);
    Display("ct_aux", ct_aux, SPECK_BBYTES);
    #ifdef ENCRYPT
      if(equalBlocks(ct, ct_aux, SPECK_BBYTES))
        printf("ENCRYPT SUCESS!!\n");
      else
        printf("ENCRYPT FAILURE!!\n");
    #elif defined(DECRYPT)
      if(equalBlocks(ct, pt, SPECK_BBYTES))
        printf("DECRYPT SUCESS!!\n");
      else
        printf("DECRYPT FAILURE!!\n");
    #endif
  }

  return TRUE;

}



////


int main (int argc, char *argv[])
{

  double txPowerStart = 0.0; // dbm
  double txPowerEnd = 15.0; // dbm
  uint32_t nTxPowerLevels = 16;
  uint32_t txPowerLevel = 0;
  
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

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("26kbps"));
  pointToPoint.SetDeviceAttribute ("Mtu", UintegerValue (85));
  pointToPoint.SetChannelAttribute ("Delay", TimeValue (Seconds (0.3))); //StringValue ("100ns")

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes);
  
  
/*
   /////////////////////////////////////////////////////////////////////////////
   // energy source //
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
   /////////////////////////////////////////////////////////////////////////////
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


  //// Speck hash generation

  int ntests;
  BOOL test_results;

  ntests = 1;

  test_results = speckTest(ntests);

  if(test_results)
      printf("SUCESS!!\n");
  else
      printf("FAILURE!!\n");

  ////  




  //// formation of message+tag
  
  // message + tag
  std::string m1 = "abcdefghabcdefg";
  std::string h1 = "2D14F7E29662FAC8D38F1BBE8ABF5A19";
  
  std::string M1 = m1+h1;          //24B
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
   /////////////////////////////////////////////////////////////////////////////
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


   ///// Stop clock
   auto stop = high_resolution_clock::now();
   auto duration = duration_cast<microseconds>(stop - start);
   cout << "Time=" << duration.count()/1000 << "milliseconds" << endl;
   /////

 cout<<rdtscl()<<endl;


  Simulator::Destroy ();
  return 0;
}
