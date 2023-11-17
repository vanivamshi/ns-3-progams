//// Truncated MAC


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


   ///// Start clock
   auto start = std::chrono::high_resolution_clock::now();
   /////


/////////////////////////////////// Truncated MAC

  //// hash calculation, split, message+tag
  std::string q1 = "abcdefghabcdefg"; //message1
  std::string q2 = "abcdefghabcdefg"; //message2
  std::string q3 = "abcdefghabcdefg"; //message3
  std::string q4 = "abcdefghabcdefg"; //message4
  uint32_t  string_hash1 = Hash32 (q1); //hash1
  uint32_t  string_hash2 = Hash32 (q2); //hash2
  uint32_t  string_hash3 = Hash32 (q3); //hash3
  uint32_t  string_hash4 = Hash32 (q4); //hash4
  //std::cout<<string_hash<<std::endl;

  // split hash
  uint32_t q1H4 = string_hash1%100;
  uint32_t q1H3 = (string_hash1/100)%100;
  uint32_t q1H2 = (string_hash1/10000)%1000;
  uint32_t q1H1 = (string_hash1/10000000)%1000;

  uint32_t q2H4 = string_hash2%100;
  uint32_t q2H3 = (string_hash2/100)%100;
  uint32_t q2H2 = (string_hash2/10000)%1000;
  uint32_t q2H1 = (string_hash2/10000000)%1000;

  uint32_t q3H4 = string_hash3%100;
  uint32_t q3H3 = (string_hash3/100)%100;
  uint32_t q3H2 = (string_hash3/10000)%1000;
  uint32_t q3H1 = (string_hash3/10000000)%1000;

  uint32_t q4H4 = string_hash4%100;
  uint32_t q4H3 = (string_hash4/100)%100;
  uint32_t q4H2 = (string_hash4/10000)%1000;
  uint32_t q4H1 = (string_hash4/10000000)%1000;


  //std::cout<<H4<<std::endl;
  //std::cout<<H3<<std::endl;
  //std::cout<<H2<<std::endl;
  //std::cout<<H1<<std::endl;

  // convert hash from int to string  

  // message 1
  std::stringstream sa;  
  sa<<q1H1;  
  std::string q1h1;  
  sa>>q1h1;  
  
  std::stringstream sb;  
  sb<<q1H2;  
  std::string q1h2;  
  sb>>q1h2;  
  
  std::stringstream sc;  
  sc<<q1H3;  
  std::string q1h3;  
  sc>>q1h3;  

  std::stringstream sd;  
  sd<<q1H4;  
  std::string q1h4;  
  sd>>q1h4;  

  // message 2
  std::stringstream ta;  
  ta<<q2H1;  
  std::string q2h1;  
  ta>>q2h1;  
  
  std::stringstream tb;  
  tb<<q2H2;  
  std::string q2h2;  
  tb>>q2h2;  
  
  std::stringstream tc;  
  tc<<q2H3;  
  std::string q2h3;  
  tc>>q2h3;  

  std::stringstream td;  
  td<<q2H4;  
  std::string q2h4;  
  td>>q2h4;  

  // message 3
  std::stringstream ua;  
  ua<<q3H1;  
  std::string q3h1;  
  ua>>q3h1;  
  
  std::stringstream ub;  
  ub<<q3H2;  
  std::string q3h2;  
  ub>>q3h2;  
  
  std::stringstream uc;  
  uc<<q3H3;  
  std::string q3h3;  
  uc>>q3h3;  

  std::stringstream ud;  
  ud<<q3H4;  
  std::string q3h4;  
  ud>>q3h4;  

  // message 4
  std::stringstream va;  
  va<<q4H1;  
  std::string q4h1;  
  va>>q4h1;  
  
  std::stringstream vb;  
  vb<<q4H2;  
  std::string q4h2;  
  vb>>q4h2;  
  
  std::stringstream vc;  
  vc<<q4H3;  
  std::string q4h3;  
  vc>>q4h3;  

  std::stringstream vd;  
  vd<<q4H4;  
  std::string q4h4;  
  vd>>q4h4;  
  

  // message + tag
  std::string m1 = "abcdefghabcdefg";
  std::string m2 = "abcdefghabcdefg";
  std::string m3 = "abcdefghabcdefg";
  std::string m4 = "abcdefghabcdefg";
  
  std::string M1 = m1+q1h1+q1h2+q1h3+q1h4;
  std::string M2 = m2+q2h1+q2h2+q2h3+q2h4;
  std::string M3 = m3+q3h1+q3h2+q3h3+q3h4;
  std::string M4 = m4+q4h1+q4h2+q4h3+q4h4;
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


  //// client2
  UdpEchoClientHelper echoClient2 (interfaces.GetAddress (1), 10);
  echoClient2.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient2.SetAttribute ("Interval", TimeValue (Seconds (1.0))); //interPacketInterval
  echoClient2.SetAttribute ("PacketSize", UintegerValue (10));
  //echoClient.SetAttribute ("txPower", UintegerValue (35));
  
  ApplicationContainer clientApps2 = echoClient1.Install (nodes.Get (0));
  echoClient2.SetFill (clientApps2.Get (0), M2);
  clientApps2.Start (Seconds (2.0));
  clientApps2.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(0)<<std::endl;


  // server2
  UdpEchoServerHelper echoServer2 (10);

  ApplicationContainer serverApps2 = echoServer2.Install (nodes.Get (1));
  //serverApps.SetAttribute ("txPower", UintegerValue (23));
  serverApps2.Start (Seconds (1.0));
  serverApps2.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(1)<<std::endl;
  
  std::stringstream cc;
  cc << nodes.Get(1);
  //std::cout << cc.str()<<std::endl;

  std::stringstream dd;
  dd << nodes.Get(0);
  //std::cout << dd.str() <<std::endl;
  
  servermessages.push(cc.str());
  ////


  //// client3
  UdpEchoClientHelper echoClient3 (interfaces.GetAddress (1), 11);
  echoClient3.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient3.SetAttribute ("Interval", TimeValue (Seconds (1.0))); //interPacketInterval
  echoClient3.SetAttribute ("PacketSize", UintegerValue (10));
  //echoClient.SetAttribute ("txPower", UintegerValue (35));
  
  ApplicationContainer clientApps3 = echoClient3.Install (nodes.Get (0));
  echoClient3.SetFill (clientApps3.Get (0), M3);
  clientApps3.Start (Seconds (2.0));
  clientApps3.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(0)<<std::endl;

  // server3
  UdpEchoServerHelper echoServer3 (11);

  ApplicationContainer serverApps3 = echoServer3.Install (nodes.Get (1));
  //serverApps.SetAttribute ("txPower", UintegerValue (23));
  serverApps3.Start (Seconds (1.0));
  serverApps3.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(1)<<std::endl;
  
  std::stringstream ee;
  ee << nodes.Get(1);
  //std::cout << ee.str()<<std::endl;

  std::stringstream ff;
  ff << nodes.Get(0);
  //std::cout << ff.str() <<std::endl;
  
  servermessages.push(ee.str());
  ////


  //// client4
  UdpEchoClientHelper echoClient4 (interfaces.GetAddress (1), 12);
  echoClient4.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient4.SetAttribute ("Interval", TimeValue (Seconds (1.0))); //interPacketInterval
  echoClient4.SetAttribute ("PacketSize", UintegerValue (10));
  //echoClient.SetAttribute ("txPower", UintegerValue (35));
  
  ApplicationContainer clientApps4 = echoClient4.Install (nodes.Get (1));
  echoClient4.SetFill (clientApps4.Get (0), M4);
  clientApps4.Start (Seconds (2.0));
  clientApps4.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(0)<<std::endl;

  // server4
  UdpEchoServerHelper echoServer4 (12);

  ApplicationContainer serverApps4 = echoServer4.Install (nodes.Get (0));
  //serverApps.SetAttribute ("txPower", UintegerValue (23));
  serverApps4.Start (Seconds (1.0));
  //serverApps4.Stop (Seconds (5.0));
  //std::cout<<nodes.Get(1)<<std::endl;
  
  std::stringstream gg;
  gg << nodes.Get(1);
  //std::cout << gg.str()<<std::endl;

  std::stringstream hh;
  hh << nodes.Get(0);
  //std::cout << hh.str() <<std::endl;

  servermessages.push(gg.str());
  ////


  // pop server variables from stack  
  std::string GG = servermessages.top();
  std::string EE = servermessages.top();
  std::string CC = servermessages.top();
  std::string AA = servermessages.top();

  AA = AA.substr(0, AA.size()-6);
  CC = CC.substr(0, CC.size()-6);
  EE = EE.substr(0, EE.size()-6);
  GG = GG.substr(0, GG.size()-6);
  
  std::string BB = bb.str();
  std::string DD = dd.str();
  std::string FF = ff.str();
  std::string HH = hh.str();

  BB = BB.substr(0, BB.size()-6);
  DD = DD.substr(0, DD.size()-6);
  FF = FF.substr(0, FF.size()-6);
  HH = HH.substr(0, HH.size()-6);
  

  if (BB == AA)
  {
  std::cout << "M1 verified" <<std::endl;
  }
  else
  {
  std::cout << "M1 not verified" <<std::endl;
  }


  if (DD == CC)
  {
  std::cout << "M2 verified" <<std::endl;
  }
  else
  {
  std::cout << "M2 not verified" <<std::endl;
  }


  if (FF == EE)
  {
  std::cout << "M3 verified" <<std::endl;
  }
  else
  {
  std::cout << "M3 not verified" <<std::endl;
  }

  
  if (HH == GG)
  {
  std::cout << "M4 verified" <<std::endl;
  }
  else
  {
  std::cout << "M4 not verified" <<std::endl;
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

  //cout<<rdtscl()<<endl;


  Simulator::Destroy ();
  return 0;
}
