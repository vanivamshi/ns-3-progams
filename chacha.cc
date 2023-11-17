//// Cha Cha

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


//#pragma once

// This is high quality software because the includes are sorted alphabetically.
#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>



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


//// functions for Blake

struct Chacha20Block {
    // This is basically a random number generator seeded with key and nonce.
    // Generates 64 random bytes every time count is incremented.

    uint32_t state[16];

    static uint32_t rotl32(uint32_t x, int n){
        return (x << n) | (x >> (32 - n));
    }

    static uint32_t pack4(const uint8_t *a){
        return
            uint32_t(a[0] << 0*8) |
            uint32_t(a[1] << 1*8) |
            uint32_t(a[2] << 2*8) |
            uint32_t(a[3] << 3*8);
    }

    static void unpack4(uint32_t src, uint8_t *dst){
        dst[0] = (src >> 0*8) & 0xff;
        dst[1] = (src >> 1*8) & 0xff;
        dst[2] = (src >> 2*8) & 0xff;
        dst[3] = (src >> 3*8) & 0xff;
    }

    Chacha20Block(const uint8_t key[32], const uint8_t nonce[8]){
        const uint8_t *magic_constant = (uint8_t*)"expand 32-byte k";
        state[ 0] = pack4(magic_constant + 0*4);
        state[ 1] = pack4(magic_constant + 1*4);
        state[ 2] = pack4(magic_constant + 2*4);
        state[ 3] = pack4(magic_constant + 3*4);
        state[ 4] = pack4(key + 0*4);
        state[ 5] = pack4(key + 1*4);
        state[ 6] = pack4(key + 2*4);
        state[ 7] = pack4(key + 3*4);
        state[ 8] = pack4(key + 4*4);
        state[ 9] = pack4(key + 5*4);
        state[10] = pack4(key + 6*4);
        state[11] = pack4(key + 7*4);
        // 64 bit counter initialized to zero by default.
        state[12] = 0;
        state[13] = 0;
        state[14] = pack4(nonce + 0*4);
        state[15] = pack4(nonce + 1*4);
    }

    void set_counter(uint64_t counter){
        // Want to process many blocks in parallel?
        // No problem! Just set the counter to the block you want to process.
        state[12] = uint32_t(counter);
        state[13] = counter >> 32;
    }

    void next(uint32_t result[16]){
        // This is where the crazy voodoo magic happens.
        // Mix the bytes a lot and hope that nobody finds out how to undo it.
        for (int i = 0; i < 16; i++) result[i] = state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

        for (int i = 0; i < 10; i++){
            CHACHA20_QUARTERROUND(result, 0, 4, 8, 12)
            CHACHA20_QUARTERROUND(result, 1, 5, 9, 13)
            CHACHA20_QUARTERROUND(result, 2, 6, 10, 14)
            CHACHA20_QUARTERROUND(result, 3, 7, 11, 15)
            CHACHA20_QUARTERROUND(result, 0, 5, 10, 15)
            CHACHA20_QUARTERROUND(result, 1, 6, 11, 12)
            CHACHA20_QUARTERROUND(result, 2, 7, 8, 13)
            CHACHA20_QUARTERROUND(result, 3, 4, 9, 14)
        }

        for (int i = 0; i < 16; i++) result[i] += state[i];

        uint32_t *counter = state + 12;
        // increment counter
        counter[0]++;
        if (0 == counter[0]){
            // wrap around occured, increment higher 32 bits of counter
            counter[1]++;
            // Limited to 2^64 blocks of 64 bytes each.
            // If you want to process more than 1180591620717411303424 bytes
            // you have other problems.
            // We could keep counting with counter[2] and counter[3] (nonce),
            // but then we risk reusing the nonce which is very bad.
            assert(0 != counter[1]);
        }
    }
    
    void next(uint8_t result8[64]){
        uint32_t temp32[16];
        
        next(temp32);
        
        for (size_t i = 0; i < 16; i++) unpack4(temp32[i], result8 + i*4);
    }
};

struct Chacha20 {
    // XORs plaintext/encrypted bytes with whatever Chacha20Block generates.
    // Encryption and decryption are the same operation.
    // Chacha20Blocks can be skipped, so this can be done in parallel.
    // If keys are reused, messages can be decrypted.
    // Known encrypted text with known position can be tampered with.
    // See https://en.wikipedia.org/wiki/Stream_cipher_attack

    Chacha20Block block;
    uint8_t keystream8[64];
    size_t position;

    Chacha20(
        const uint8_t key[32],
        const uint8_t nonce[8],
        uint64_t counter = 0
    ): block(key, nonce), position(64){
        block.set_counter(counter);
    }

    void crypt(uint8_t *bytes, size_t n_bytes){
        for (size_t i = 0; i < n_bytes; i++){
            if (position >= 64){
                block.next(keystream8);
                position = 0;
            }
            bytes[i] ^= keystream8[position];
            position++;
        }
    }
};



typedef std::vector<uint8_t> Bytes;

uint8_t char_to_uint[256];
const char uint_to_char[10 + 26 + 1] = "0123456789abcdefghijklmnopqrstuvwxyz";

Bytes str_to_bytes(const char *src){
    return Bytes(src, src + strlen(src));
}

Bytes hex_to_raw(const Bytes &src){
    size_t n = src.size();
    assert(n % 2 == 0);
    Bytes dst(n/2);
    for (size_t i = 0; i < n/2; i++){
        uint8_t hi = char_to_uint[src[i*2 + 0]];
        uint8_t lo = char_to_uint[src[i*2 + 1]];
        dst[i] = (hi << 4) | lo;
    }
    return dst;
}

Bytes raw_to_hex(const Bytes &src){
    size_t n = src.size();
    Bytes dst(n*2);
    for (size_t i = 0; i < n; i++){
        uint8_t hi = (src[i] >> 4) & 0xf;
        uint8_t lo = (src[i] >> 0) & 0xf;
        dst[i*2 + 0] = uint_to_char[hi];
        dst[i*2 + 1] = uint_to_char[lo];
    }
    return dst;
}

bool operator == (const Bytes &a, const Bytes &b){
    size_t na = a.size();
    size_t nb = b.size();
    if (na != nb) return false;
    return memcmp(a.data(), b.data(), na) == 0;
}

void test_keystream(
    const char *text_key,
    const char *text_nonce,
    const char *text_keystream
){
    Bytes key       = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce     = hex_to_raw(str_to_bytes(text_nonce));
    Bytes keystream = hex_to_raw(str_to_bytes(text_keystream));

    // Since Chacha20 just XORs the plaintext with the keystream,
    // we can feed it zeros and we will get the keystream.
    Bytes zeros(keystream.size(), 0);
    Bytes result(zeros);

    Chacha20 chacha(key.data(), nonce.data());
    chacha.crypt(&result[0], result.size());

    assert(result == keystream);
}

void test_crypt(
    const char *text_key,
    const char *text_nonce,
    const char *text_plain,
    const char *text_encrypted,
    uint64_t counter
){
    Bytes key       = hex_to_raw(str_to_bytes(text_key));
    Bytes nonce     = hex_to_raw(str_to_bytes(text_nonce));
    Bytes plain     = hex_to_raw(str_to_bytes(text_plain));
    Bytes encrypted = hex_to_raw(str_to_bytes(text_encrypted));

    Chacha20 chacha(key.data(), nonce.data(), counter);

    Bytes result(plain);
    // Encryption and decryption are the same operation.
    chacha.crypt(&result[0], result.size());

    assert(result == encrypted);
}

uint32_t adler32(const uint8_t *bytes, size_t n_bytes){
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < n_bytes; i++){
        a = (a + bytes[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

void test_encrypt_decrypt(uint32_t expected_adler32_checksum){
    // Encrypt and decrypt a megabyte of [0, 1, 2, ..., 255, 0, 1, ...].
    Bytes bytes(1024 * 1024);
    for (size_t i = 0; i < bytes.size(); i++) bytes[i] = i & 255;
    
    // Encrypt
    
    // Best password by consensus.
    uint8_t key[32] = {1, 2, 3, 4, 5, 6};
    // Really does not matter what this is, except that it is only used once.
    uint8_t nonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    Chacha20 chacha(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());
    
    // Verify by checksum that the encrypted text is as expected.
    // Note that the adler32 checksum is not cryptographically secure.
    // It is only used for testing here.
    uint32_t checksum = adler32(bytes.data(), bytes.size());
    assert(checksum == expected_adler32_checksum);
    
    // Decrypt
    
    // Reset ChaCha20 de/encryption object.
    chacha = Chacha20(key, nonce);
    chacha.crypt(bytes.data(), bytes.size());
    
    // Check if crypt(crypt(input)) == input.
    for (size_t i = 0; i < bytes.size(); i++) assert(bytes[i] == (i & 255));
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
   //////////////////////////////////////////////////////////////////////////////
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


  //// Blake hash generation

 // Initialize lookup table
    for (int i = 0; i < 10; i++) char_to_uint[i + '0'] = i;
    for (int i = 0; i < 26; i++) char_to_uint[i + 'a'] = i + 10;
    for (int i = 0; i < 26; i++) char_to_uint[i + 'A'] = i + 10;

    // From rfc7539.txt
    test_crypt("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586", 0);
    test_crypt("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000002", "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f", "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221", 1);
    test_crypt("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "0000000000000002", "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e", "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1", 42);
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000", "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000", "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275ae546963");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000001", "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3");
    test_keystream("0000000000000000000000000000000000000000000000000000000000000000", "0100000000000000", "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb0041b2f586b");
    test_keystream("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0001020304050607", "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9");
    
    test_encrypt_decrypt(3934073876);
    
    puts("Success! Tests passed.");



  
  ////  




  //// formation of message+tag
  
  // message + tag
  std::string m1 = "abcdefghabcdefg";
  uint64_t out = 12345678;
  
  stringstream ss;
  ss<<out;
  string s;
  ss>>s;
  
  std::string M1 = m1+s;          //24B
  ////


  // store variables received at server in stack
  stack<std::string> servermessages; 


/*
   //////////////////////////////////////////////////////////////////////////////
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

  //cout<<rdtscl()<<endl;

  Simulator::Destroy ();
  return 0;
}
