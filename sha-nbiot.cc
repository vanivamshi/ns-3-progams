/* Message with HMAC algorithm*/

/* -*-  Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
 /*
  * Copyright (c) 2010 Network Security Lab, University of Washington, Seattle.
  *
  * This program is free software; you can redistribute it and/or modify
  * it under the terms of the GNU General Public License version 2 as
  * published by the Free Software Foundation;
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program; if not, write to the Free Software
  * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  *
  * Author: Sidharth Nabar <snabar@uw.edu>, He Wu <mdzz@u.washington.edu>
  */
  
 #include <iostream>
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
 using namespace std::chrono;
  
 NS_LOG_COMPONENT_DEFINE ("EnergyExample");


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

/*
///// Begin add header
 class YHeader : public Header
 {
 public:
   YHeader ();
   virtual ~YHeader();

   // must be implemented to become a valid new header.
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (Buffer::Iterator start) const;
   virtual uint32_t Deserialize (Buffer::Iterator start);
   virtual void Print (std::ostream &os) const;
   //void SetSize (uint64_t size);

   // allow protocol-specific access to the header data.
   void SetData (uint32_t data);
   uint32_t GetData (void) const;
 private:
   uint32_t m_data;
   //uint64_t m_size {8};
 };

 YHeader::YHeader () {}
 YHeader::~YHeader() {}

 TypeId
 YHeader::GetTypeId (void)
 {
   static TypeId tid = TypeId ("YHeader")
     .SetParent<Header> ()
     .AddConstructor<YHeader> ()
   ;
   return tid;
 }

 TypeId
 YHeader::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 YHeader::GetSerializedSize (void) const
 {
   return 6;
 }

 void 
 YHeader::Serialize (Buffer::Iterator start) const
 {
   // The 2 byte-constant
   start.WriteU8 (0xfe);
   start.WriteU8 (0xef);
   // The data.
   start.WriteHtonU32 (m_data);
 }

 uint32_t 
 YHeader::Deserialize (Buffer::Iterator start)
 {
   uint8_t tmp;
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xfe);
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xef);
   m_data = start.ReadNtohU32 ();
   return 6; // the number of bytes consumed.
 }

 void 
 YHeader::Print (std::ostream &os) const
 {
   os << "data=" << m_data;
 }

 void 
 YHeader::SetData (uint32_t data)
 {
   m_data = data;
 }

 uint32_t
 YHeader::GetData (void) const
 {
   return m_data;
 }
///// End add header
*/

/*
///// Begin add trailer
 class ZTrailer : public Trailer
 {
 public:
   ZTrailer ();
   virtual ~ZTrailer();

   // must be implemented to become a valid new trailer.
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (Buffer::Iterator start) const;
   virtual uint32_t Deserialize (Buffer::Iterator start);
   virtual void Print (std::ostream &os) const;

   // allow protocol-specific access to the trailer data.
   void SetData (uint32_t data);
   uint32_t GetData (void) const;
 private:
   uint32_t m_data;
 };

 //virtual ZTrailer();
 ZTrailer::ZTrailer () {}
 //virtual ~ZTrailer();
 ZTrailer::~ZTrailer() {}

 TypeId
 ZTrailer::GetTypeId (void)
 {
   static TypeId tid = TypeId ("ZTrailer")
     .SetParent<Trailer> ()
     .AddConstructor<ZTrailer> ()
   ;
   return tid;
 }

 TypeId
 ZTrailer::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 ZTrailer::GetSerializedSize (void) const
 {
   return 6;
 }

 void 
 ZTrailer::Serialize (Buffer::Iterator start) const
 {
   // The 2 byte-constant
   start.WriteU8 (0xfe);
   start.WriteU8 (0xef);
   // The data.
   start.WriteHtonU32 (m_data);
 }

 uint32_t 
 ZTrailer::Deserialize (Buffer::Iterator start)
 {
   uint8_t tmp;
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xfe);
   tmp = start.ReadU8 ();
   NS_ASSERT (tmp == 0xef);
   m_data = start.ReadNtohU32 ();
   return 6; // the number of bytes consumed.
 }

 void 
 ZTrailer::Print (std::ostream &os) const
 {
   os << "data=" << m_data;
 }

 void 
 ZTrailer::SetData (uint32_t data)
 {
   m_data = data;
 }

 uint32_t
 ZTrailer::GetData (void) const
 {
   return m_data;
 }
///// End add trailer
*/


///// Begin add tag
 class MyTag : public Tag
 {
 public:
   static TypeId GetTypeId (void);
   virtual TypeId GetInstanceTypeId (void) const;
   virtual uint32_t GetSerializedSize (void) const;
   virtual void Serialize (TagBuffer i) const;
   virtual void Deserialize (TagBuffer i);
   virtual void Print (std::ostream &os) const;
  
   // these are our accessors to our tag structure
   void SetSimpleValue (uint8_t value);
   uint8_t GetSimpleValue (void) const;
 private:
   uint8_t m_simpleValue;  
 };

 //MyTag::MyTag () {}
 //MyTag::~MyTag() {}

 TypeId 
 MyTag::GetTypeId (void)
 {
   static TypeId tid = TypeId ("ns3::MyTag")
     .SetParent<Tag> ()
     .AddConstructor<MyTag> ()
     .AddAttribute ("SimpleValue",
                    "A simple value",
                    EmptyAttributeValue (),
                    MakeUintegerAccessor (&MyTag::GetSimpleValue),
                    MakeUintegerChecker<uint8_t> ())
   ;
   return tid;
 }

 TypeId 
 MyTag::GetInstanceTypeId (void) const
 {
   return GetTypeId ();
 }

 uint32_t 
 MyTag::GetSerializedSize (void) const
 {
   return 1;
 }

 void 
 MyTag::Serialize (TagBuffer i) const
 {
   i.WriteU8 (m_simpleValue);
 }

 void 
 MyTag::Deserialize (TagBuffer i)
 {
   m_simpleValue = i.ReadU8 ();
 }

 void 
 MyTag::Print (std::ostream &os) const
 {
   os << "v=" << (uint32_t)m_simpleValue;
 }

 void 
 MyTag::SetSimpleValue (uint8_t value)
 {
   m_simpleValue = value;
 }

 uint8_t 
 MyTag::GetSimpleValue (void) const
 {
   return m_simpleValue;
 }
///// End add tag


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
           // copy tag, message, hash to with received data - real time
           Ptr<Packet> aCopy = packet->Copy ();
           // read the tag from the packet copy
           MyTag tag;
           MyTag tagCopy;
           //YHeader yHeader;
           //YHeader yHeaderCopy;
           packet->PeekPacketTag (tagCopy);
           //packet->PeekHeader (yHeaderCopy);
           // the copy and the original are the same !
           //if ((tagCopy.GetSimpleValue () == tag.GetSimpleValue ()) && (yHeaderCopy.GetData () == yHeader.GetData ()))
           if (tagCopy.GetSimpleValue () == tag.GetSimpleValue ())
             {
               NS_LOG_UNCOND (PrintReceivedPacket (from));
             }
         }
     }
 }


 //calculate hmac using md5, sha256, sha512 - in python
 // message - 8 bytes = 64 bit, tag (md5) - 16 bit -> 2 packets sent
        //char* message = strdup("12345678");
        //char* hmac = strdup("611ee570bcae2eec8287d97efebd4b12");


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
       MyTag tag;
       tag.SetSimpleValue (0x5);
       packet->AddPacketTag (tag);

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

/*
void rdtscl(unsigned long long *ll)
{
    unsigned int lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));                        
    *ll = ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );  
}*/


 int
 main (int argc, char *argv[])
 {
   /*
   LogComponentEnable ("EnergySource", LOG_LEVEL_DEBUG);
   LogComponentEnable ("BasicEnergySource", LOG_LEVEL_DEBUG);
   LogComponentEnable ("DeviceEnergyModel", LOG_LEVEL_DEBUG);
   LogComponentEnable ("WifiRadioEnergyModel", LOG_LEVEL_DEBUG);
    */
  
   LogComponentEnable ("EnergyExample", LogLevel (LOG_PREFIX_TIME | LOG_PREFIX_NODE | LOG_LEVEL_INFO));
  
   std::string phyMode ("DsssRate1Mbps");
   double Prss = -80;            // dBm
   uint32_t PpacketSize = 1;   // bytes - packet size = 2 to 125B(uplink) an 2 to 85B(downlink)
   bool verbose = false;

   std::string dataRate = "180kbps";
  
   // simulation parameters
   uint32_t numPackets = 1;  // number of packets to send
   double interval = 1;          // seconds
   double startTime = 0.0;       // seconds
   double distanceToRx = 100.0;  // meters

   /*
    * This is a magic number used to set the transmit power, based on other
    * configuration.
    */
   //double offset = 81;
  
   CommandLine cmd (__FILE__);
   cmd.AddValue ("phyMode", "Wifi Phy mode", phyMode);
   cmd.AddValue ("Prss", "Intended primary RSS (dBm)", Prss);
   cmd.AddValue ("PpacketSize", "size of application packet sent", PpacketSize);
   cmd.AddValue ("numPackets", "Total number of packets to send", numPackets);
   cmd.AddValue ("startTime", "Simulation start time", startTime);
   cmd.AddValue ("distanceToRx", "X-Axis distance between nodes", distanceToRx);
   cmd.AddValue ("verbose", "Turn on all device log components", verbose);
   cmd.Parse (argc, argv);
  
   // Convert to time object
   Time interPacketInterval = Seconds (interval);
  
   // disable fragmentation for frames below 72 bytes
   Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold",
                       StringValue ("125"));
   // turn off RTS/CTS for frames below 72 bytes
   Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold",
                       StringValue ("125"));
   // Fix non-unicast data rate to be the same as that of unicast
   Config::SetDefault ("ns3::WifiRemoteStationManager::NonUnicastMode",
                       StringValue (phyMode));
 
 

 
   NodeContainer c;
   c.Create (2);     // create 2 nodes
   NodeContainer networkNodes;
   networkNodes.Add (c.Get (0));
   networkNodes.Add (c.Get (1));

   PointToPointHelper p2p;
   p2p.SetDeviceAttribute ("DataRate", StringValue ("180kbps"));
   p2p.SetChannelAttribute ("Delay", StringValue ("2ms"));

   NetDeviceContainer p2pDevices;
   p2pDevices = p2p.Install (c);

  
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
  
   NetDeviceContainer devices = wifi.Install (wifiPhy, wifiMac, networkNodes);
  
   MobilityHelper mobility;
   Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
   positionAlloc->Add (Vector (0.0, 0.0, 0.0));
   positionAlloc->Add (Vector (2 * distanceToRx, 0.0, 0.0));
   mobility.SetPositionAllocator (positionAlloc);
   mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
   mobility.Install (c);


    ///// memory usage
   using std::cout;
   using std::endl;

   double vm, rss;
   process_mem_usage(vm, rss);
   std::cout << "VM: " << vm << "; RSS: " << rss << std::endl;
   /////

  
   /***************************************************************************/
   /* energy source */
   BasicEnergySourceHelper basicSourceHelper;
   // configure energy source
   basicSourceHelper.Set ("BasicEnergySourceInitialEnergyJ", DoubleValue (3.6)); //https://tech-journal.semtech.com/analyzing-nb-iot-and-lorawan-sensor-battery-life - battery is 1000-2000mAh, volt is 3.6V

   // install source
   EnergySourceContainer sources = basicSourceHelper.Install (c);
   /* device energy model */
   WifiRadioEnergyModelHelper radioEnergyHelper;
   // configure radio energy model
   radioEnergyHelper.Set ("TxCurrentA", DoubleValue (0.0000217)); //https://waviot.com/catalog/electric-meters/waviot-single-phase-electricity-meter/ - 5mW, 230V
   //radioEnergyHelper.Set ("RxCurrentA", DoubleValue (0.0000217));
   // install device model
   DeviceEnergyModelContainer deviceModels = radioEnergyHelper.Install (devices, sources);
   /***************************************************************************/
  
   InternetStackHelper internet;
   internet.Install (networkNodes);
  
   Ipv4AddressHelper ipv4;
   NS_LOG_INFO ("Assign IP Addresses.");
   ipv4.SetBase ("10.1.1.0", "255.255.255.0");
   Ipv4InterfaceContainer i = ipv4.Assign (devices);
  
   TypeId tid = TypeId::LookupByName ("ns3::UdpSocketFactory");
   Ptr<Socket> recvSink = Socket::CreateSocket (networkNodes.Get (1), tid);  // node 1, receiver
   InetSocketAddress local = InetSocketAddress (Ipv4Address::GetAny (), 80);
   recvSink->Bind (local);
   recvSink->SetRecvCallback (MakeCallback (&ReceivePacket));
  
   Ptr<Socket> source = Socket::CreateSocket (networkNodes.Get (0), tid);    // node 0, sender
   InetSocketAddress remote = InetSocketAddress (Ipv4Address::GetBroadcast (), 90);
   source->SetAllowBroadcast (true);
   source->Connect (remote);

   //uint16_t sinkPort = 8080;
   //Address sinkAddress (InetSocketAddress(interfaces.GetAddress (1), sinkPort));

  
   /***************************************************************************/
   // all sources are connected to node 1
   // energy source
   Ptr<BasicEnergySource> basicSourcePtr = DynamicCast<BasicEnergySource> (sources.Get (1));
   basicSourcePtr->TraceConnectWithoutContext ("RemainingEnergy", MakeCallback (&RemainingEnergy));
   // device energy model
   Ptr<DeviceEnergyModel> basicRadioModelPtr =
     basicSourcePtr->FindDeviceEnergyModels ("ns3::WifiRadioEnergyModel").Get (0);
   NS_ASSERT (basicRadioModelPtr != NULL);
   basicRadioModelPtr->TraceConnectWithoutContext ("TotalEnergyConsumption", MakeCallback (&TotalEnergy));
   /***************************************************************************/
  
  
   ///// Start clock
   auto start = high_resolution_clock::now();
   /////

   // start traffic
   Simulator::Schedule (Seconds (startTime), &GenerateTraffic, source, PpacketSize,
                        networkNodes.Get (0), numPackets, interPacketInterval);
/*
   ///// memory usage
   using std::cout;
   using std::endl;

   double vm, rss;
   process_mem_usage(vm, rss);
   std::cout << "VM: " << vm << "; RSS: " << rss << std::endl;
   /////
*/
   Simulator::Stop (Seconds (20.0));
   Simulator::Run ();
  
   for (DeviceEnergyModelContainer::Iterator iter = deviceModels.Begin (); iter != deviceModels.End (); iter ++)
     {
       double energyConsumed = (*iter)->GetTotalEnergyConsumption ();
       NS_LOG_UNCOND ("End of simulation (" << Simulator::Now ().GetSeconds ()
                      << "s) Total energy consumed by radio = " << energyConsumed << "J");
       //NS_ASSERT (energyConsumed <= 0.1);
     }


   ///// Stop clock
   auto stop = high_resolution_clock::now();
   auto duration = duration_cast<microseconds>(stop - start);
   cout << "Time=" << duration.count()/1000 << "milliseconds" << endl;
   /////

 cout<<rdtscl()<<endl;

   Simulator::Destroy ();
  
   return 0;
 }


