//// Retransmit - cumac real time authentication

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

#include <iostream>
#include <stack>
#include <sys/time.h>
#include <chrono>
#include <unistd.h>

using namespace ns3;
using namespace std;

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
  

  NodeContainer nodes;
  nodes.Create (2);

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("26kbps"));
  pointToPoint.SetDeviceAttribute ("Mtu", UintegerValue (85));
  pointToPoint.SetChannelAttribute ("Delay", TimeValue (Seconds (0.3))); //StringValue ("100ns")

  NetDeviceContainer devices;
  devices = pointToPoint.Install (nodes);
  
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

  //// hash calculation, split, message+tag
  std::string q = "abcdefghabcdefg"; //message
  uint32_t  string_hash = Hash32 (q); //hash
  //std::cout<<string_hash<<std::endl;

  // split hash
  uint32_t H4 = string_hash%100;
  uint32_t H3 = (string_hash/100)%100;
  uint32_t H2 = (string_hash/10000)%1000;
  uint32_t H1 = (string_hash/10000000)%1000;
  uint32_t H8 = string_hash%100;
  uint32_t H7 = (string_hash/100)%100;
  uint32_t H6 = (string_hash/10000)%1000;
  uint32_t H5 = (string_hash/10000000)%1000;

  // convert hash from int to string  
  std::stringstream ss;  
  ss<<H1;  
  std::string h1;  
  ss>>h1;  
  
  std::stringstream st;  
  st<<H2;  
  std::string h2;  
  st>>h2;  
  
  std::stringstream su;  
  su<<H3;  
  std::string h3;  
  su>>h3;  

  std::stringstream sv;  
  sv<<H4;  
  std::string h4;  
  sv>>h4;  
  

  std::stringstream ts;  
  ss<<H5;  
  std::string h5;  
  ss>>h5;  
  
  std::stringstream tt;  
  st<<H6;  
  std::string h6;  
  st>>h6;  
  
  std::stringstream tu;  
  su<<H7;  
  std::string h7;  
  su>>h7;  

  std::stringstream tv;  
  sv<<H8;  
  std::string h8;  
  sv>>h8;  


  // message + tag
  std::string m1 = "abcdefghabcdefg";
  std::string m2 = "abcdefghabcdefg";
  std::string m3 = "abcdefghabcdefg";
  std::string m4 = "abcdefghabcdefg";
  std::string m5 = "abcdefghabcdefg";
  std::string m6 = "abcdefghabcdefg";
  std::string m7 = "abcdefghabcdefg";
  std::string m8 = "abcdefghabcdefg";
  
  //std::string M1 = m1+h1;          //24B
  //std::string M2 = m2+h1+h2;       //32B
  //std::string M3 = m3+h1+h2+h3;    //40B
  //std::string M4 = m4+h1+h2+h3+h4; //48B
  
  std::string M5 = m5+h2+h3+h4+h5+m1+h1;          //72B
  std::string M6 = m6+h3+h4+h5+h6+m2+h1+h2;       //80B
  std::string M7 = m7+h4+h5+h6+h7+m3+h1+h2+h3;    //88B
  std::string M8 = m8+h5+h6+h7+h8+m4+h1+h2+h3+h4; //96B
  ////
  
  

  // store variables received at server in stack
  stack<std::string> servermessages; 


  //// client1
  UdpEchoClientHelper echoClient1 (interfaces.GetAddress (1), 9);
  echoClient1.SetAttribute ("MaxPackets", UintegerValue (1));
  echoClient1.SetAttribute ("Interval", TimeValue (Seconds (1.0))); //interPacketInterval
  echoClient1.SetAttribute ("PacketSize", UintegerValue (10));
  //echoClient.SetAttribute ("txPower", UintegerValue (35));
  
  ApplicationContainer clientApps1 = echoClient1.Install (nodes.Get (0));
  echoClient1.SetFill (clientApps1.Get (0), M5);
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
  echoClient2.SetFill (clientApps2.Get (0), M6);
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
  echoClient3.SetFill (clientApps3.Get (0), M7);
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
  echoClient4.SetFill (clientApps4.Get (0), M8);
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
  
  std::string GG1 = GG;
  std::string EE1 = EE;
  std::string CC1 = CC;
  std::string AA1 = AA;

  AA = AA.substr(0, AA.size()-12);
  CC = CC.substr(0, CC.size()-18);
  EE = EE.substr(0, EE.size()-24);
  GG = GG.substr(0, GG.size()-30);
  
  AA1 = AA1.substr(6, AA1.size()-6);
  CC1 = CC1.substr(6, CC1.size()-6);
  EE1 = EE1.substr(6, EE1.size()-6);
  GG1 = GG1.substr(6, GG1.size()-6);

  
  std::string BB = bb.str();
  std::string DD = dd.str();
  std::string FF = ff.str();
  std::string HH = hh.str();

  std::string BB1 = BB;
  std::string DD1 = DD;
  std::string FF1 = FF;
  std::string HH1 = HH;

  BB = BB.substr(0, BB.size()-12);
  DD = DD.substr(0, DD.size()-18);
  FF = FF.substr(0, FF.size()-24);
  HH = HH.substr(0, HH.size()-30);

  BB1 = BB1.substr(6, BB1.size()-6);
  DD1 = DD1.substr(6, DD1.size()-6);
  FF1 = FF1.substr(6, FF1.size()-6);
  HH1 = HH1.substr(6, HH1.size()-6);
  

  if (BB1 == AA1)
  {
  std::cout << "M1 verified" <<std::endl;
  }
  else
  {
  std::cout << "M1 not verified" <<std::endl;
  }


  if (DD1 == CC1)
  {
  std::cout << "M2 verified" <<std::endl;
  }
  else
  {
  std::cout << "M2 not verified" <<std::endl;
  }


  if (FF1 == EE1)
  {
  std::cout << "M3 verified" <<std::endl;
  }
  else
  {
  std::cout << "M3 not verified" <<std::endl;
  }

  
  if (HH1 == GG1)
  {
  std::cout << "M4 verified" <<std::endl;
  }
  else
  {
  std::cout << "M4 not verified" <<std::endl;
  }


  if (BB == AA)
  {
  std::cout << "M5 verified" <<std::endl;
  }
  else
  {
  std::cout << "M5 not verified" <<std::endl;
  }


  if (DD == CC)
  {
  std::cout << "M6 verified" <<std::endl;
  }
  else
  {
  std::cout << "M6 not verified" <<std::endl;
  }


  if (FF == EE)
  {
  std::cout << "M7 verified" <<std::endl;
  }
  else
  {
  std::cout << "M7 not verified" <<std::endl;
  }

  
  if (HH == GG)
  {
  std::cout << "M8 verified" <<std::endl;
  }
  else
  {
  std::cout << "M8 not verified" <<std::endl;
  }


   ///// Stop clock
   auto stop = std::chrono::high_resolution_clock::now();
   auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
   std::cout << "Time=" << duration.count()/1000 << "milliseconds" << std::endl;
   /////
   

   ///// memory usage
   using std::cout;
   using std::endl;

   double vm, rss;
   process_mem_usage(vm, rss);
   std::cout << "VM: " << vm << "; RSS: " << rss << std::endl;
   /////


  // generate trace file
  AsciiTraceHelper ascii;
  pointToPoint.EnableAsciiAll (ascii.CreateFileStream ("2.tr"));
  pointToPoint.EnablePcapAll ("2", true);

  // set channel bandwidth to 180kHz
  Simulator::Schedule (Seconds(1) , &BandwidthTrace); 

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
