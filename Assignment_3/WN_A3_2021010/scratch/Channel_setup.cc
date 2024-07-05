// #include "ns3/core-module.h"
// #include "ns3/network-module.h"
// #include "ns3/mobility-module.h"
// #include "ns3/wifi-module.h"
// #include "ns3/internet-module.h"
// #include "ns3/applications-module.h"

// using namespace ns3;

// int main(int argc, char* argv[]) {
//     // Enable logging
//     LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
//     LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

//     // Create nodes
//     NodeContainer wifiStaNodes;
//     wifiStaNodes.Create(10); // 10 stations

//     NodeContainer wifiApNode;
//     wifiApNode.Create(1); // 1 AP

//     // Set up the Wi-Fi channel and PHY parameters
//     YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
//     YansWifiPhyHelper phy = YansWifiPhyHelper::Default();
//     phy.SetChannel(channel.Create());
//     phy.Set("GuardInterval", TimeValue(NanoSeconds(3200))); // Set the guard interval to 3200ns

//     // Wi-Fi helper
//     WifiHelper wifi;
//     wifi.SetStandard(WIFI_PHY_STANDARD_80211n_5GHZ);
//     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("HtMcs11"), "ControlMode", StringValue("HtMcs11"));


//     // Set up MAC and SSID
//     Ssid ssid = Ssid("ns-3-ssid");
//     wifi.SetStandard(WIFI_PHY_STANDARD_80211n_5GHZ);
//     wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("HtMcs11"));

//     // Install Wi-Fi devices to stations and the AP
//     NetDeviceContainer wifiStaDevices = wifi.Install(phy, wifi.GetMac(), wifiStaNodes);
//     NetDeviceContainer wifiApDevices = wifi.Install(phy, wifi.GetMac(), wifiApNode);

//     // Set up mobility for stations and the AP
//     MobilityHelper mobility;
//     mobility.SetPositionAllocator("ns3::RandomDiscPositionAllocator",
//                                   "X", DoubleValue(0.0),
//                                   "Y", DoubleValue(0.0),
//                                   "Rho", DoubleValue(5.0)); // Stations are within 5 meters of the AP
//     mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
//     mobility.Install(wifiStaNodes);
//     mobility.Install(wifiApNode);

//     // Internet stack for all nodes
//     InternetStackHelper stack;
//     stack.Install(wifiStaNodes);
//     stack.Install(wifiApNode);

//     // Assign IP addresses to Wi-Fi devices
//     Ipv4AddressHelper address;
//     address.SetBase("10.1.1.0", "255.255.255.0");
//     Ipv4InterfaceContainer wifiStaInterfaces = address.Assign(wifiStaDevices);
//     address.SetBase("10.1.2.0", "255.255.255.0");
//     Ipv4InterfaceContainer wifiApInterfaces = address.Assign(wifiApDevices);

//     // Create UDP echo server
//     UdpEchoServerHelper echoServer(9);
//     ApplicationContainer serverApps = echoServer.Install(wifiApNode.Get(0));
//     serverApps.Start(Seconds(1.0));
//     serverApps.Stop(Seconds(10.0));

//     // Create UDP echo clients
//     UdpEchoClientHelper echoClient(wifiApInterfaces.GetAddress(0), 9);
//     echoClient.SetAttribute("MaxPackets", UintegerValue(6000)); // MAC queue of 6000 packets
//     echoClient.SetAttribute("Interval", TimeValue(Seconds(0.001))); // Packet sending interval
//     echoClient.SetAttribute("PacketSize", UintegerValue(1000)); // Packet size of 1000 bytes
//     ApplicationContainer clientApps = echoClient.Install(wifiStaNodes);
//     clientApps.Start(Seconds(2.0));
//     clientApps.Stop(Seconds(10.0));

//     // Run the simulation for 10 seconds
//     Simulator::Stop(Seconds(10.0));
//     Simulator::Run();
//     Simulator::Destroy();

//     return 0;
// }
















#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"

using namespace ns3;

int main(int argc, char* argv[]) {
    // Enable logging
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);

    // Create nodes
    NodeContainer wifiStaNodes;
    wifiStaNodes.Create(10); // 10 stations

    NodeContainer wifiApNode;
    wifiApNode.Create(1); // 1 AP

    // Set up the Wi-Fi channel and PHY parameters for OFDM
    YansWifiChannelHelper ofdmChannel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper ofdmPhy = YansWifiPhyHelper::Default();
    ofdmPhy.SetChannel(ofdmChannel.Create());
    ofdmPhy.Set("GuardInterval", TimeValue(NanoSeconds(3200))); // Set the guard interval to 3200ns

    // Set up the Wi-Fi channel and PHY parameters for OFDMA
    YansWifiChannelHelper ofdmaChannel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper ofdmaPhy = YansWifiPhyHelper::Default();
    ofdmaPhy.SetChannel(ofdmaChannel.Create());
    ofdmaPhy.Set("GuardInterval", TimeValue(NanoSeconds(3200))); // Set the guard interval to 3200ns

    // Wi-Fi helper for OFDM
    WifiHelper ofdmWifi;
    ofdmWifi.SetStandard(WIFI_PHY_STANDARD_80211n_5GHZ);
    ofdmWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("ErpOfdmRate54Mbps"));

    // Wi-Fi helper for OFDMA
    WifiHelper ofdmaWifi;
    ofdmaWifi.SetStandard(WIFI_PHY_STANDARD_80211ax_5GHZ); // 802.11ax for OFDMA
    ofdmaWifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("ErpOfdmRate54Mbps"));

    // Set up MAC and SSID for both OFDM and OFDMA
    Ssid ssid = Ssid("ns-3-ssid");

    // Install Wi-Fi devices to stations and the AP for OFDM
    NetDeviceContainer ofdmStaDevices = ofdmWifi.Install(ofdmPhy, ofdmWifi.GetMac(), wifiStaNodes);
    NetDeviceContainer ofdmApDevices = ofdmWifi.Install(ofdmPhy, ofdmWifi.GetMac(), wifiApNode);

    // Install Wi-Fi devices to stations and the AP for OFDMA
    NetDeviceContainer ofdmaStaDevices = ofdmaWifi.Install(ofdmaPhy, ofdmaWifi.GetMac(), wifiStaNodes);
    NetDeviceContainer ofdmaApDevices = ofdmaWifi.Install(ofdmaPhy, ofdmaWifi.GetMac(), wifiApNode);

    // Set up mobility for stations and the AP
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::RandomDiscPositionAllocator",
                                  "X", DoubleValue(0.0),
                                  "Y", DoubleValue(0.0),
                                  "Rho", DoubleValue(5.0)); // Stations are within 5 meters of the AP
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiStaNodes);
    mobility.Install(wifiApNode);

    // Internet stack for all nodes
    InternetStackHelper stack;
    stack.Install(wifiStaNodes);
    stack.Install(wifiApNode);

    // Assign IP addresses to Wi-Fi devices for OFDM
    Ipv4AddressHelper ofdmAddress;
    ofdmAddress.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer ofdmStaInterfaces = ofdmAddress.Assign(ofdmStaDevices);
    ofdmAddress.SetBase("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer ofdmApInterfaces = ofdmAddress.Assign(ofdmApDevices);

    // Assign IP addresses to Wi-Fi devices for OFDMA
    Ipv4AddressHelper ofdmaAddress;
    ofdmaAddress.SetBase("10.1.3.0", "255.255.255.0");
    Ipv4InterfaceContainer ofdmaStaInterfaces = ofdmaAddress.Assign(ofdmaStaDevices);
    ofdmaAddress.SetBase("10.1.4.0", "255.255.255.0");
    Ipv4InterfaceContainer ofdmaApInterfaces = ofdmaAddress.Assign(ofdmaApDevices);

    // Create UDP echo server for OFDM
    UdpEchoServerHelper ofdmEchoServer(9);
    ApplicationContainer ofdmServerApps = ofdmEchoServer.Install(wifiApNode.Get(0));
    ofdmServerApps.Start(Seconds(1.0));
    ofdmServerApps.Stop(Seconds(10.0));

    // Create UDP echo server for OFDMA
    UdpEchoServerHelper ofdmaEchoServer(9);
    ApplicationContainer ofdmaServerApps = ofdmaEchoServer.Install(wifiApNode.Get(0));
    ofdmaServerApps.Start(Seconds(1.0));
    ofdmaServerApps.Stop(Seconds(10.0));

    // Create UDP echo clients for OFDM
    UdpEchoClientHelper ofdmEchoClient(ofdmApInterfaces.GetAddress(0), 9);
    ofdmEchoClient.SetAttribute("MaxPackets", UintegerValue(6000)); // MAC queue of 6000 packets
    ofdmEchoClient.SetAttribute("Interval", TimeValue(Seconds(0.001))); // Packet sending interval
    ofdmEchoClient.SetAttribute("PacketSize", UintegerValue(1000)); // Packet size of 1000 bytes
    ApplicationContainer ofdmClientApps = ofdmEchoClient.Install(wifiStaNodes);
    ofdmClientApps.Start(Seconds(2.0));
    ofdmClientApps.Stop(Seconds(10.0));

    // Create UDP echo clients for OFDMA
    UdpEchoClientHelper ofdmaEchoClient(ofdmaApInterfaces.GetAddress(0), 9);
    ofdmaEchoClient.SetAttribute("MaxPackets", UintegerValue(6000)); // MAC queue of 6000 packets
    ofdmaEchoClient.SetAttribute("Interval", TimeValue(Seconds(0.001))); // Packet sending interval
    ofdmaEchoClient.SetAttribute("PacketSize", UintegerValue(1000)); // Packet size of 1000 bytes
    ApplicationContainer ofdmaClientApps = ofdmaEchoClient.Install(wifiStaNodes);
    ofdmaClientApps.Start(Seconds(2.0));
    ofdmaClientApps.Stop(Seconds(10.0));

    // Run the simulation for 10 seconds for OFDM
    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    // Run the simulation for 10 seconds for OFDMA
    Simulator::Stop(Seconds(10.0));
    Simulator::Run();
    Simulator::Destroy();

    // Calculate and compare metrics for both OFDM and OFDMA (packet latency distribution and median TCP RTT)

    return 0;
}
