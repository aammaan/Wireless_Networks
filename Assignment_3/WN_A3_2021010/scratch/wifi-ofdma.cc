/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2019
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
 * Authors: Stefano Avallone <stavallo@unina.it>
 *          Sébastien Deronne <sebastien.deronne@gmail.com>
 */

#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/string.h"
#include "ns3/pointer.h"
#include "ns3/log.h"
#include "ns3/spectrum-wifi-helper.h"
#include "ns3/ssid.h"
#include "ns3/mobility-helper.h"
#include "ns3/wifi-net-device.h"
#include "ns3/sta-wifi-mac.h"
#include "ns3/ap-wifi-mac.h"
#include "ns3/qos-txop.h"
#include "ns3/internet-stack-helper.h"
#include "ns3/ipv4-address-helper.h"
#include "ns3/application-container.h"
#include "ns3/packet-sink-helper.h"
#include "ns3/packet-sink.h"
#include "ns3/on-off-helper.h"
#include "ns3/v4ping-helper.h"
#include "ns3/multi-model-spectrum-channel.h"
#include "ns3/wifi-mac-queue.h"
#include "ns3/wifi-psdu.h"
#include "ns3/ctrl-headers.h"
#include "ns3/traffic-control-helper.h"
#include "ns3/traffic-control-layer.h"
#include "ns3/he-configuration.h"
#include "ns3/wifi-acknowledgment.h"
#include "ns3/rng-seed-manager.h"
#include "ns3/he-phy.h"
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <numeric>
#include <fstream>
#include <algorithm>
#include <type_traits>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("WifiOfdmaExample");

/**
 * \brief Example to test DL/UL OFDMA
 *
 * This example creates an 11ax BSS (the BSS under test) and a configurable
 * number of overlapping BSSes made of stations of a given technology (11n,
 * 11ac or 11ax).
 *
 * Usage: ./waf --run "wifi-ofdma [options]"
 *
 * The available options can be listed by typing:
 *
 * ./waf --run "wifi-ofdma --help"
 *
 * It is mandatory to pass a text file (via the trafficFile option) specifying
 * the traffic flows to generate. Empty lines or lines beginning with '#'
 * in such text file are ignored. The syntax of a line is:
 *
 * <START_STA_ID> [<END_STA_ID>] <AC> <L4PROTO> <DIR> <PKTSIZE> IDT|CBR <VALUE>
 *
 * where:
 *
 * - START_STA_ID is the ID of the non-AP STA which is the sender/receiver
 *   (depending on the traffic direction) of this flow. IDs start at 1.
 * - if END_STA_ID (>= START_STA_ID) is specified, flows will be generated
 *   for every station having ID included in START_STA_ID..END_STA_ID.
 * - AC is the Access Category ('BE', 'BK', 'VI' or 'VO').
 * - L4PROTO is the transport layer protocol ('UDP' or 'TCP').
 * - DIR can be 'DL' for a single downlink flow, 'UL' for a single uplink flow
 *   and 'DL+UL' for two symmetric flows (downlink and uplink).
 * - PKTSIZE is the packet size in bytes.
 * - if 'IDT' is specified, VALUE represents the inter-departure time (in
 *   milliseconds) between two consecutive packets. If 'CBR' is specified,
 *   VALUE represents the data rate (in Mbps).
 */
class WifiOfdmaExample
{
public:
  // Helper class to store min, max, avg and count statistics
  template <typename T>
  struct Stats
  {
    Stats (uint16_t val = 0) {}   // to allow init to 0 (in PrintStatsWithTotal)
    void AddSample (T value);
    void RemoveSample (T value);
    Stats<T>& operator+= (const Stats<T>& rhs);  // merge samples

    std::multiset<T> m_samples;
  };

  struct Flow
  {
    enum
    {
      DOWNLINK,
      UPLINK
    } m_direction;
    enum
    {
      TCP,
      UDP
    } m_l4Proto;
    AcIndex m_ac;
    uint16_t m_stationId;     // starting at 1
    uint16_t m_dstPort;
    uint32_t m_payloadSize;   // bytes
    double m_dataRate;        // b/s
    /* Measured end-to-end metrics */
    Stats<double> m_latency;
    uint64_t m_txBytes {0};
    uint64_t m_txPackets {0};
    uint64_t m_packetsRejectedBySocket{0};
    uint64_t m_rxBytes {0};
    uint64_t m_rxPackets {0};
    uint64_t m_prevRxBytes {0};
    /*
     * For UDP flows, map packet's UID to the time it was transmitted. For TCP flows,
     * map the total amount of bytes transmitted at the time a packet was sent to
     * the time the packet was transmitted.
     */
    std::unordered_map<uint64_t, Time> m_inFlightPackets;
  };

  /**
   * Create an example instance.
   */
  WifiOfdmaExample ();
  virtual ~WifiOfdmaExample ();
  /**
   * Parse the options provided through command line.
   */
  void Config (int argc, char *argv[]);
  /**
   * Read the specs of the traffic flows to generate.
   */
  void ReadTrafficSpecs (std::string filename);
  /**
   * Setup nodes, devices and internet stacks.
   */
  void Setup (void);
  /**
   * Run simulation.
   */
  void Run (void);
  /**
   * Print results.
   */
  void PrintResults (std::ostream& os);
  /**
   * Make the current station associate with the AP.
   */
  void StartAssociation (void);
  /**
   * Make the AP establish a BA agreement with the current station.
   */
  void EstablishBaAgreement (Mac48Address bssid);
  /**
   * Start a client application.
   */
  void StartClient (OnOffHelper client, std::size_t i, Ptr<Node> node);
  /**
   * Start an OBSS client application.
   */
  void StartObssClient (OnOffHelper client, uint16_t bss, Ptr<Node> node);
  /**
   * Delay the start of traffic generation.
   */
  void DelayStart (void);
  /**
   * Start generating traffic.
   */
  void StartTraffic (void);
  /**
   * Start collecting statistics.
   */
  void StartStatistics (void);
  /**
   * Stop collecting statistics.
   */
  void StopStatistics (void);
  /**
   * Report that an MPDU was not correctly received.
   */
  void NotifyTxFailed (Ptr<const WifiMpdu> mpdu);
  /**
   * Report that the lifetime of an MSDU expired.
   */
  void NotifyMsduExpired (Ptr<const WifiMpdu> item);
  /**
   * Report that an MSDU was dropped before enqueue into EDCA queue.
   */
  void NotifyMsduRejected (Ptr<const WifiMpdu> item);
  /**
   * Report that a packet was transmitted by the i-th application.
   */
  void NotifyAppTx (std::size_t i, Ptr<const Packet> packet);
  /**
   * Report that a packet was received by the i-th application.
   */
  void NotifyAppRx (std::size_t i, Ptr<const Packet> packet, const Address &address);
  /**
   * Report that a packet was enqueued in an EDCA queue.
   */
  void NotifyEdcaEnqueue (Ptr<const WifiMpdu> item);
  /**
   * Report that the MAC layer is forwarding up a received packet.
   */
  void NotifyMacForwardUp (Ptr<const Packet> p);
  /**
   * Report that an MSDU was dequeued from the EDCA queue.
   */
  void NotifyMsduDequeuedFromEdcaQueue (Time maxDelay, Ptr<const WifiMpdu> item);
  /**
   * Report that PSDUs were forwarded down to the PHY.
   */
  void NotifyPsduForwardedDown (WifiConstPsduMap psduMap, WifiTxVector txVector, double txPowerW);
  /**
   * Report the TXOP duration when a TXOP ends.
   */
  void NotifyTxopDuration (uint32_t nodeId, AcIndex ac, Time startTime, Time duration, uint8_t linkId);
  /**
   * Report the sojourn time of a packet dequeued from a qdisc
   */
  void NotifySojournTime (std::size_t nodeId, AcIndex ac, Time sojournTime);
  /**
   * Report that a packet has been dropped after dequeue
   */
  void NotifyDropAfterDequeue (std::size_t nodeId, AcIndex ac, Ptr<const QueueDiscItem> item, const char* reason);
  /**
   * Store the per-flow amount of bytes received so far
   */
  void StoreCumulativeRxBytes (void);
  /**
   * Parse context strings of the form "/NodeList/x/DeviceList/y/" to extract the NodeId
   */
  uint32_t ContextToNodeId (const std::string & context);

  static const std::map<AcIndex, std::string> m_aciToString;
  static uint16_t m_nEcdfSamples;       // by default, minimum, median and maximum

private:
  template <typename T>
  void ReadParamList (std::string s, std::vector<T>& vec);

  template <typename T, typename FUNC>
  void PrintStatsWithTotal (std::vector<std::map<AcIndex, T>> v, FUNC select,
                            std::ostream& os, std::string s, std::string s0 = "");
  template <typename T, typename FUNC>
  void PrintStats (std::vector<std::map<AcIndex, T>> v, FUNC select,
                   std::ostream& os, std::string s, std::string s0 = "");

  /* Parameters */
  double m_simulationTime {5};          // seconds
  double m_startInterval {10};        // duration of the interval in which apps can start sending packets (ms)
  std::vector<uint64_t> m_rngValues {1, 40}; // values to initialize the RNG
  uint16_t m_nHeStations {4};
  uint16_t m_nVhtStations {0};
  uint16_t m_nStations;                 // number of non-AP stations in the BSS under test
  uint16_t m_nObss {0};                  // number of overlapping BSSs
  uint16_t m_nStationsPerObss {0};      // number of non-AP stations per each OBSS
  WifiStandard m_obssStandard;
  double m_radius {5};                 // meters
  bool m_enableDlOfdma {true};
  bool m_forceDlOfdma {true};
  bool m_enableUlOfdma {true};
  bool m_enableTxopSharing {false};
  bool m_enableBsrp {true};
  bool m_useCentral26TonesRus {false};
  uint32_t m_ulPsduSize {500};          // bytes
  uint16_t m_channelWidth {40};         // channel bandwidth (MHz)
  uint8_t m_channelNumber {36};
  WifiPhyBand m_band {WIFI_PHY_BAND_UNSPECIFIED};
  uint16_t m_guardInterval {3200};      // GI in nanoseconds
  bool m_enableObssPd {false};
  double m_obssPdThresholdBss {-99.0};
  double m_obssPdThresholdMinBss {-82.0};
  double m_obssPdThresholdMaxBss {-62.0};
  bool m_enableThresholdPreambleDetection {true};
  uint32_t m_obssDlPayload {1400};      // bytes
  uint32_t m_obssUlPayload {1400};      // bytes
  double m_obssDlAggregateRate {0.0};   // Mbps
  double m_obssUlAggregateRate {0.0};   // Mbps
  double m_powerSta {17.0};             // dBm
  double m_powerAp {23.0};              // dBm
  double m_psdLimitation {10.0};        // dBm/MHz
  double m_ccaThresholdSta {-62};       // dBm
  double m_ccaThresholdAp {-62};        // dBm
  double m_txGain {0.0};                // dBi
  double m_rxGain {0.0};                // dBi
  double m_rxSensitivity {-91.0};
  uint16_t m_maxNRus {18};               // max number of RUs per MU PPDU  //change1
  std::string m_heRate {"ideal"};       // "ideal" or MCS value
  uint16_t m_beMaxAmsduSize {7500};     // maximum A-MSDU size for BE
  uint16_t m_bkMaxAmsduSize {7500};     // maximum A-MSDU size for BK
  uint16_t m_viMaxAmsduSize {7500};     // maximum A-MSDU size for VI
  uint16_t m_voMaxAmsduSize {7500};     // maximum A-MSDU size for VO
  uint32_t m_beMaxAmpduSize {8388607u}; // maximum A-MPDU size for BE
  uint32_t m_bkMaxAmpduSize {8388607u}; // maximum A-MPDU size for BK
  uint32_t m_viMaxAmpduSize {8388607u}; // maximum A-MPDU size for VI
  uint32_t m_voMaxAmpduSize {8388607u}; // maximum A-MPDU size for VO
  uint32_t m_obssMaxAmpduSize {65535};  // maximum A-MPDU size for overlapping BSSes
  double m_beTxopLimit {5440};          // microseconds
  double m_bkTxopLimit {5440};          // microseconds
  double m_viTxopLimit {5440};          // microseconds
  double m_voTxopLimit {5440};          // microseconds
  double m_obssTxopLimit {5440};        // microseconds
  uint32_t m_macQueueSize {6000};       // packets
  uint32_t m_beMsduLifetime {500};      // milliseconds
  uint32_t m_bkMsduLifetime {500};      // milliseconds
  uint32_t m_viMsduLifetime {500};      // milliseconds
  uint32_t m_voMsduLifetime {500};      // milliseconds
  bool m_useExplicitBar {true};         // use explicit BAR after missed Block Ack
  uint16_t m_muBeAifsn {0};
  uint16_t m_muBkAifsn {0};
  uint16_t m_muViAifsn {0};
  uint16_t m_muVoAifsn {0};
  uint16_t m_muBeCwMin {15};
  uint16_t m_muBkCwMin {15};
  uint16_t m_muViCwMin {15};
  uint16_t m_muVoCwMin {15};
  uint16_t m_muBeCwMax {1023};
  uint16_t m_muBkCwMax {1023};
  uint16_t m_muViCwMax {1023};
  uint16_t m_muVoCwMax {1023};
  uint32_t m_beMuEdcaTimer {2088960};   // microseconds
  uint32_t m_bkMuEdcaTimer {2088960};   // microseconds
  uint32_t m_viMuEdcaTimer {2088960};   // microseconds
  uint32_t m_voMuEdcaTimer {2088960};   // microseconds
  bool m_enableRts {false};
  std::string m_dlAckSeqType {"ACK-SU-FORMAT"};
  uint16_t m_baBufferSize {64};
  std::string m_queueDisc {"default"};
  bool m_enablePcap {false};
  double m_warmup {0.5};                // duration of the warmup period (seconds)
  uint32_t m_tcpSegmentSize {1500};        // TCP maximum segment size (0 = use default)
  uint32_t m_tcpInitialCwnd {0};        // TCP initial congestion window size (segments, 0 = use default)
  uint32_t m_tcpMinRto {0};             // TCP minimum retransmit timeout (milliseconds, 0 = use default)
  std::string m_trafficFile;            // name of file describing traffic flows to generate
  bool m_verbose {false};
  uint16_t m_nIntervals {20};           // number of intervals in which the simulation time is divided
  uint16_t m_elapsedIntervals {0};

  std::string m_ssidPrefix {"network-"};
  std::vector<double> m_apDistances, m_apThetas;
  NodeContainer m_apNodes;
  NodeContainer m_staNodes;
  std::vector<NodeContainer> m_obssStaNodes;
  NetDeviceContainer m_apDevices;
  NetDeviceContainer m_staDevices;
  std::vector<NetDeviceContainer> m_obssStaDevices;
  Ipv4InterfaceContainer m_apInterfaces;
  Ipv4InterfaceContainer m_staInterfaces;
  std::vector<Ipv4InterfaceContainer> m_obssStaInterfaces;
  uint16_t m_currentSta {0};         // index of the current station
  ApplicationContainer m_sinkApps;
  std::vector<ApplicationContainer> m_obssSinkApps;
  std::vector<Ptr<Application>> m_clientApps;
  std::vector<ApplicationContainer> m_obssClientApps;
  std::vector<Flow> m_flows;

  std::vector<uint64_t> m_obssDlRxStart, m_obssDlRxStop;
  std::vector<uint64_t> m_obssUlRxStart, m_obssUlRxStop;
  Stats<double> m_dlMuCompleteness; // ratio of actual amount of bytes to max amount of bytes
                                    // (given its duration) carried in a DL MU PPDU
  Stats<double> m_dlMuPpduDuration; // TX duration (ms) of DL MU PPDUs
  uint64_t m_nBasicTriggerFramesSent {0};
  uint64_t m_nFailedBasicTriggerFrames {0};  // no station responded (with a QoS Data or BAR frame)
  uint64_t m_nBsrpTriggerFramesSent {0};
  uint64_t m_nFailedBsrpTriggerFrames {0};  // no station responded with a QoS Null frame
  Stats<double> m_heTbCompleteness; // ratio of sum of durations of A-MPDUs carrying QoS Data/BAR frames in
                                    // an HE TB PPDU to sum of durations granted by Basic Trigger Frame
  Time m_tfUlLength {Seconds (0)};  // TX duration coded in UL Length subfield of Trigger Frame
  Stats<double> m_heTbPpduDuration; // TX duration (ms) coded in UL Length subfield of Basic TFs
  Time m_overallTimeGrantedByTf {Seconds (0)}; // m_tfUlLength times the number of addressed stations
  Time m_durationOfResponsesToLastBasicTf {Seconds (0)}; // sum of the durations of the HE TB PPDUs (excluding
                                                         // QoS Null frames) in response to the last Basic TF
  uint64_t m_countOfNullResponsesToLastTf {0}; // count of QoS Null frames sent in response to the last TF
  TriggerFrameType m_lastTfType;   // type of the last Trigger Frame sent (Basic or Bsrp)

  // Metrics that can be measured (sender side) for each (AP,STA) pair (DL) or
  // (STA,AP) pair (UL) and for each Access Category
  struct PairwisePerAcStats
  {
    uint64_t expired {0};
    uint64_t rejected {0};          // dropped before enqueue into EDCA queue
    uint64_t failed {0};
    Stats<double> l2Latency;
    Time lastTxTime {Seconds (0)};
    Stats<double> pairwiseHol;      // pairwise Head-of-Line delay *DL only*
    Stats<uint32_t> ampduSize;      // size (bytes) of MPDUs sent to/received from each STAs
    Stats<double> ampduRatio;       // ratio of the duration of the A-MPDU sent to (for DL) or received
                                    // from (for UL) a STA to the duration of the DL MU PPDU or HE TB PPDU
  };
  std::vector<std::map<AcIndex, PairwisePerAcStats>> m_dlPerStaAcStats;   // A vector element per station (DL)
  std::vector<std::map<AcIndex, PairwisePerAcStats>> m_ulPerStaAcStats;   // A vector element per station (UL)

  // Metrics that can be measured (sender side) for each Access Category
  // and are independent of the receiver
  struct PerAcStats
  {
    Stats<double> txopDuration;
    Stats<double> queueDiscSojournTime;
    uint32_t droppedByQueueDisc {0};
    Time lastTxTime {Seconds (0)};
    Stats<double> aggregateHoL;     // aggregate Head-of-Line delay
  };
  std::vector<std::map<AcIndex, PerAcStats>> m_perAcStats;  // first vector element for the AP, then one per STA

  struct InFlightPacketInfo
  {
    Mac48Address m_srcAddress;
    Mac48Address m_dstAddress;
    AcIndex m_ac;
    Ptr<const Packet> m_ptrToPacket;
    Time m_edcaEnqueueTime {Seconds (0)};  // time the packet was enqueued into an EDCA queue
  };
  std::unordered_map<uint64_t /* UID */, std::list<InFlightPacketInfo>> m_inFlightPacketMap;
  
  std::vector<uint64_t> m_nSolicitingBasicTriggerFrames;

  // Function object to compute the hash of a MAC address
  struct MacAddressHash
  {
    std::size_t operator()(const Mac48Address& address) const;
  };

  std::unordered_map <Mac48Address, uint32_t, MacAddressHash> m_staMacAddressToNodeId;

  /**
   * Return the ID of the node containing the device having the given address.
   */
  uint32_t MacAddressToNodeId (Mac48Address address);
  /**
   * Return an iterator to the PairwisePerAcStats object corresponding to the given MPDU header.
   */
  std::pair<std::map<AcIndex, PairwisePerAcStats>::iterator, bool>
    GetPairwisePerAcStats (const WifiMacHeader& hdr, AcIndex = AC_UNDEF);
  /**
   * Return the OBSS id and the index of station having the given id.
   */
  std::pair<uint16_t, std::size_t> StationIdToBssIndexPair (std::size_t id);
};

const std::map<AcIndex, std::string> WifiOfdmaExample::m_aciToString = { {AC_BE, "BE"}, {AC_BK, "BK"},
                                                                         {AC_VI, "VI"}, {AC_VO, "VO"}, };

uint16_t WifiOfdmaExample::m_nEcdfSamples = 3;       // by default, minimum, median and maximum

template <typename T>
void
WifiOfdmaExample::Stats<T>::AddSample (T value)
{
  m_samples.insert (value);
}

template <typename T>
void
WifiOfdmaExample::Stats<T>::RemoveSample (T value)
{
  auto it = m_samples.find (value);
  if (it != m_samples.end ())
    {
      m_samples.erase (it);
    }
}

template <typename T>
WifiOfdmaExample::Stats<T>&
WifiOfdmaExample::Stats<T>::operator+= (const Stats<T>& rhs)
{
  this->m_samples.insert (rhs.m_samples.begin (), rhs.m_samples.end ());
  return *this;
}

template <typename T>
std::ostream& operator<< (std::ostream& os, const WifiOfdmaExample::Stats<T> &stats)
{
//   os << std::fixed << std::setprecision (3)
//      << "(" << stats.m_min << ", " << stats.m_avg << ", " << stats.m_max << ", " << stats.m_count << ") ";
  os << std::fixed << std::setprecision (3) << "(";
  uint16_t m = WifiOfdmaExample::m_nEcdfSamples - 1;   // number of sub-intervals of [0,1]
  std::size_t pos = 0, count = stats.m_samples.size ();

  if (count > 0)
    {
      auto it = stats.m_samples.begin ();
      for (uint8_t i = 0; i <= m; i++)
        {
          std::advance (it, pos);
          os << *it << (i < m ? ", " : "");
          pos = (i + 1) * (count - 1) / m - i * (count - 1) / m;
        }
    }
  os <<  ")[" << count << "]";
  return os;
}

std::ostream& operator<< (std::ostream& os, const WifiOfdmaExample::Flow &flow)
{
  os << "{staId=" << flow.m_stationId
     << (flow.m_direction == WifiOfdmaExample::Flow::DOWNLINK ? " DL " : " UL ")
     << "AC=" << WifiOfdmaExample::m_aciToString.at (flow.m_ac)
     << (flow.m_l4Proto == WifiOfdmaExample::Flow::TCP ? " TCP " : " UDP ")
     << flow.m_payloadSize << "B "
     << std::defaultfloat << flow.m_dataRate << "bps}";
  return os;
}

std::size_t
WifiOfdmaExample::MacAddressHash::operator()(const Mac48Address& address) const
{
  uint8_t buffer[6];
  address.CopyTo (buffer);
  std::string s (buffer, buffer+6);
  return std::hash<std::string>{}(s);
}

std::pair<uint16_t, std::size_t>
WifiOfdmaExample::StationIdToBssIndexPair (std::size_t id)
{
  NS_ABORT_MSG_IF (id < m_nStations, "Station is part of the BSS under test");
  return std::make_pair ((id - m_nStations) / m_nStationsPerObss + 1,
                         (id - m_nStations) % m_nStationsPerObss);
}

template <typename T>
void
WifiOfdmaExample::ReadParamList (std::string s, std::vector<T>& vec)
{
  std::size_t start = 0, end;
  do
    {
      end = s.find_first_of (",", start);
      std::stringstream ss (s.substr (start, end));
      T tmp;
      NS_ABORT_MSG_IF (!(ss >> tmp), "Unexpected value " << ss.str ());
      vec.push_back (tmp);
      if (end != std::string::npos)
        {
          start = end + 1;
        }
    } while (end != std::string::npos);
}

WifiOfdmaExample::WifiOfdmaExample ()
{
}

WifiOfdmaExample::~WifiOfdmaExample ()
{
  m_dlPerStaAcStats.clear ();
  m_ulPerStaAcStats.clear ();
  m_perAcStats.clear ();
  m_inFlightPacketMap.clear ();
}

void
WifiOfdmaExample::Config (int argc, char *argv[])
{
  NS_LOG_FUNCTION (this);
  std::string simScheduler ("map");
  std::string obssStandard = "11ax";
  std::string psdLimitRegulator = "FCC";
  std::string apDistance, apTheta, rngInit;

  CommandLine cmd;
  cmd.AddValue ("simScheduler", "Simulator scheduler (map, list, heap, cal)", simScheduler);
  cmd.AddValue ("simulationTime", "Simulation time in seconds", m_simulationTime);
  cmd.AddValue ("startInterval", "Duration of the interval (ms) in which all apps can send the first packet", m_startInterval);
  cmd.AddValue ("rngInit", "Comma separated (no spaces) list of RNG seed and run", rngInit);
  cmd.AddValue ("nHeStations", "Number of non-AP HE stations in the BSS under test", m_nHeStations);
  cmd.AddValue ("nVhtStations", "Number of non-AP VHT stations in the BSS under test", m_nVhtStations);
  cmd.AddValue ("nObss", "Number of overlapping BSSs", m_nObss);
  cmd.AddValue ("nStationsPerObss", "Number of non-AP stations in each overlapping BSS", m_nStationsPerObss);
  cmd.AddValue ("obssStandard", "Standard (11ax, 11ac, 11n) used for each overlapping BSS", obssStandard);
  cmd.AddValue ("radius", "Radius of the disc centered in the AP and containing all the non-AP STAs", m_radius);
  cmd.AddValue ("apDistance", "Comma separated (no spaces) list of distances for OBSS APs", apDistance);
  cmd.AddValue ("apTheta", "Comma separated (no spaces) list of angles for OBSS APs", apTheta);
  cmd.AddValue ("forceDlOfdma", "The RR scheduler always returns DL OFDMA", m_forceDlOfdma);
  cmd.AddValue ("dlAckType", "Ack sequence type for DL OFDMA (NO-OFDMA, ACK-SU-FORMAT, MU-BAR, AGGR-MU-BAR)",
                m_dlAckSeqType);
  cmd.AddValue ("enableUlOfdma", "The RR scheduler returns UL OFDMA after DL OFDMA", m_enableUlOfdma);
  cmd.AddValue ("enableTxopSharing", "The RR scheduler allows A-MPDUs of distinct TIDs in a DL MU PPDU", m_enableTxopSharing);
  cmd.AddValue ("enableBsrp", "A BSRP Trigger Frame is sent before each HE TB PPDU", m_enableBsrp);
  cmd.AddValue ("ulPsduSize", "Max size in bytes of HE TB PPDUs", m_ulPsduSize);
  cmd.AddValue ("useCentral26TonesRus", "Whether to use the central 26-tone RUs", m_useCentral26TonesRus);
  cmd.AddValue ("channelWidth", "Channel bandwidth (20, 40, 80, 160)", m_channelWidth);
  cmd.AddValue ("guardInterval", "Guard Interval (800, 1600, 3200)", m_guardInterval);
  cmd.AddValue ("enableObssPd", "Enable OBSS_PD (forced to false if obssStandard is not 11ax)", m_enableObssPd);
  cmd.AddValue ("obssPdThresholdBss", "Energy threshold (dBm) of received signal below which the PHY layer can avoid declaring CCA BUSY for inter-BSS frames.", m_obssPdThresholdBss);
  cmd.AddValue ("obssPdThresholdMinBss", "Minimum value (dBm) of OBSS PD level", m_obssPdThresholdMinBss);
  cmd.AddValue ("obssPdThresholdMaxBss", "Maximum value (dBm) of OBSS PD level", m_obssPdThresholdMaxBss);
  cmd.AddValue ("enableThresholdPreambleDetection", "Enable or disable threshold-based preamble detection (if not set, preamble detection is always successful)", m_enableThresholdPreambleDetection);
  cmd.AddValue ("powerSta", "Power of STA (dBm)", m_powerSta);
  cmd.AddValue ("powerAp", "Power of AP (dBm)", m_powerAp);
  cmd.AddValue ("psdLimitRegulator", "Regulation organism to use for PSD limitations (FCC or ETSI)", psdLimitRegulator);
  cmd.AddValue ("txGain", "Transmission gain (dB)", m_txGain);
  cmd.AddValue ("rxGain", "Reception gain (dB)", m_rxGain);
  cmd.AddValue ("ccaThrSta", "CCA Threshold of STA (dBm)", m_ccaThresholdSta);
  cmd.AddValue ("ccaThrAp", "CCA Threshold of AP (dBm)", m_ccaThresholdAp);
  cmd.AddValue ("rxSensitivity", "Receiver Sensitivity (dBm)", m_rxSensitivity);
  cmd.AddValue ("obssDlPayload", "Payload size of downlink packets in overlapping BSSes [bytes]", m_obssDlPayload);
  cmd.AddValue ("obssUlPayload", "Payload size of uplink packets in overlapping BSSes [bytes]", m_obssUlPayload);
  cmd.AddValue ("obssDlRate", "Aggregate downlink load in each overlapping BSS [Mbps]", m_obssDlAggregateRate);
  cmd.AddValue ("obssUlRate", "Aggregate uplink load in each overlapping BSS [Mbps]", m_obssUlAggregateRate);
  cmd.AddValue ("maxRus", "Maximum number of RUs allocated per DL MU PPDU", m_maxNRus);
  cmd.AddValue ("heRate", "'ideal' or the constant MCS value to transmit HE PPDUs", m_heRate);
  cmd.AddValue ("beMaxAmsduSize", "Maximum A-MSDU size for BE", m_beMaxAmsduSize);
  cmd.AddValue ("bkMaxAmsduSize", "Maximum A-MSDU size for BK", m_bkMaxAmsduSize);
  cmd.AddValue ("viMaxAmsduSize", "Maximum A-MSDU size for VI", m_viMaxAmsduSize);
  cmd.AddValue ("voMaxAmsduSize", "Maximum A-MSDU size for VO", m_voMaxAmsduSize);
  cmd.AddValue ("beMaxAmpduSize", "Maximum A-MPDU size for BE", m_beMaxAmpduSize);
  cmd.AddValue ("bkMaxAmpduSize", "Maximum A-MPDU size for BK", m_bkMaxAmpduSize);
  cmd.AddValue ("viMaxAmpduSize", "Maximum A-MPDU size for VI", m_viMaxAmpduSize);
  cmd.AddValue ("voMaxAmpduSize", "Maximum A-MPDU size for VO", m_voMaxAmpduSize);
  cmd.AddValue ("obssMaxAmpduSize", "Maximum A-MPDU size for OBSSes", m_obssMaxAmpduSize);
  cmd.AddValue ("beTxopLimit", "TXOP duration for BE in microseconds", m_beTxopLimit);
  cmd.AddValue ("bkTxopLimit", "TXOP duration for BK in microseconds", m_bkTxopLimit);
  cmd.AddValue ("viTxopLimit", "TXOP duration for VI in microseconds", m_viTxopLimit);
  cmd.AddValue ("voTxopLimit", "TXOP duration for VO in microseconds", m_voTxopLimit);
  cmd.AddValue ("obssTxopLimit", "TXOP duration for OBSSes in microseconds", m_obssTxopLimit);
  cmd.AddValue ("queueSize", "Maximum size of a WifiMacQueue (packets)", m_macQueueSize);
  cmd.AddValue ("beMsduLifetime", "Maximum MSDU lifetime for BE in milliseconds", m_beMsduLifetime);
  cmd.AddValue ("bkMsduLifetime", "Maximum MSDU lifetime for BK in milliseconds", m_bkMsduLifetime);
  cmd.AddValue ("viMsduLifetime", "Maximum MSDU lifetime for VI in milliseconds", m_viMsduLifetime);
  cmd.AddValue ("voMsduLifetime", "Maximum MSDU lifetime for VO in milliseconds", m_voMsduLifetime);
  cmd.AddValue ("useExplicitBar", "Use explicit BAR after missed Block Ack", m_useExplicitBar);
  cmd.AddValue ("muBeAifsn", "AIFSN used by BE EDCA when the MU EDCA Timer is running", m_muBeAifsn);
  cmd.AddValue ("muBkAifsn", "AIFSN used by BK EDCA when the MU EDCA Timer is running", m_muBkAifsn);
  cmd.AddValue ("muViAifsn", "AIFSN used by VI EDCA when the MU EDCA Timer is running", m_muViAifsn);
  cmd.AddValue ("muVoAifsn", "AIFSN used by VO EDCA when the MU EDCA Timer is running", m_muVoAifsn);
  cmd.AddValue ("muBeCwMin", "CWmin used by BE EDCA when the MU EDCA Timer is running", m_muBeCwMin);
  cmd.AddValue ("muBkCwMin", "CWmin used by BK EDCA when the MU EDCA Timer is running", m_muBkCwMin);
  cmd.AddValue ("muViCwMin", "CWmin used by VI EDCA when the MU EDCA Timer is running", m_muViCwMin);
  cmd.AddValue ("muVoCwMin", "CWmin used by VO EDCA when the MU EDCA Timer is running", m_muVoCwMin);
  cmd.AddValue ("muBeCwMax", "CWmax used by BE EDCA when the MU EDCA Timer is running", m_muBeCwMax);
  cmd.AddValue ("muBkCwMax", "CWmax used by BK EDCA when the MU EDCA Timer is running", m_muBkCwMax);
  cmd.AddValue ("muViCwMax", "CWmax used by VI EDCA when the MU EDCA Timer is running", m_muViCwMax);
  cmd.AddValue ("muVoCwMax", "CWmax used by VO EDCA when the MU EDCA Timer is running", m_muVoCwMax);
  cmd.AddValue ("beMuEdcaTimer", "MU EDCA Timer used by BE EDCA in microseconds", m_beMuEdcaTimer);
  cmd.AddValue ("bkMuEdcaTimer", "MU EDCA Timer used by BK EDCA in microseconds", m_bkMuEdcaTimer);
  cmd.AddValue ("viMuEdcaTimer", "MU EDCA Timer used by VI EDCA in microseconds", m_viMuEdcaTimer);
  cmd.AddValue ("voMuEdcaTimer", "MU EDCA Timer used by VO EDCA in microseconds", m_voMuEdcaTimer);
  cmd.AddValue ("baBufferSize", "Block Ack buffer size", m_baBufferSize);
  cmd.AddValue ("enableRts", "Enable or disable RTS/CTS", m_enableRts);
  cmd.AddValue ("tcpSegmentSize", "TCP maximum segment size in bytes", m_tcpSegmentSize);
  cmd.AddValue ("tcpInitialCwnd", "TCP initial congestion window size (segments)", m_tcpInitialCwnd);
  cmd.AddValue ("tcpMinRto", "TCP minimum retransmit timeout (milliseconds)", m_tcpMinRto);
  cmd.AddValue ("trafficFile", "Name of the file describing the traffic flows to generate", m_trafficFile);
  cmd.AddValue ("queueDisc", "Queuing discipline to install on the AP (default/none)", m_queueDisc);
  cmd.AddValue ("warmup", "Duration of the warmup period (seconds)", m_warmup);
  cmd.AddValue ("enablePcap", "Enable PCAP trace file generation.", m_enablePcap);
  cmd.AddValue ("verbose", "Enable/disable all Wi-Fi debug traces", m_verbose);
  cmd.AddValue ("nEcdfSamples", "Number of ECDF samples (by default, minimum, median and maximum)", m_nEcdfSamples);
  cmd.Parse (argc, argv);

  ObjectFactory factory;

  if (simScheduler == "map")
    {
      factory.SetTypeId ("ns3::MapScheduler");
    }
  else if (simScheduler == "list")
    {
      factory.SetTypeId ("ns3::ListScheduler");
    }
  else if (simScheduler == "heap")
    {
      factory.SetTypeId ("ns3::HeapScheduler");
    }
  else if (simScheduler == "cal")
    {
      factory.SetTypeId ("ns3::CalendarScheduler");
    }
  else
    {
      NS_ABORT_MSG ("Unknown simulator scheduler: " << simScheduler);
    }
  Simulator::SetScheduler (factory);

  if (!rngInit.empty ())
    {
      m_rngValues.clear ();
      ReadParamList (rngInit, m_rngValues);
    }

  NS_ABORT_MSG_IF (m_rngValues.size () != 2, "Invalid list of values for RNG initialization");
  RngSeedManager::SetSeed (static_cast<uint32_t> (m_rngValues[0]));
  RngSeedManager::SetRun (m_rngValues[1]);

  NS_ABORT_MSG_IF (m_nVhtStations > 0 && m_heRate != "ideal",
                   "Cannot use constant rate manager when both VHT and HE stations are present");

  if (m_maxNRus == 0)
    {
      // we do not want to use OFDMA
      m_dlAckSeqType = "NO-OFDMA";
    }

  m_enableDlOfdma = (m_dlAckSeqType != "NO-OFDMA");

  switch (m_channelWidth)
    {
    case 20:
      m_channelNumber = 36;
      break;
    case 40:
      m_channelNumber = 38;
      break;
    case 80:
      m_channelNumber = 42;
      break;
    case 160:
      m_channelNumber = 50;
      break;
    default:
      NS_ABORT_MSG ("Invalid channel bandwidth (must be 20, 40, 80 or 160)");
    }

  if (obssStandard == "11ax")
    {
      m_obssStandard = WIFI_STANDARD_80211ax;
    }
  else if (obssStandard == "11ac")
    {
      m_obssStandard = WIFI_STANDARD_80211ac;
    }
  else if (obssStandard == "11n")
    {
      m_obssStandard = WIFI_STANDARD_80211n;
    }
  else
    {
      NS_ABORT_MSG ("Invalid standard for OBSS (choose among 11ax, 11ac, 11n)");
    }

  if (m_obssStandard != WIFI_STANDARD_80211ax)
    {
      m_enableObssPd = false;
    }

  if (psdLimitRegulator == "FCC")
    {
      m_psdLimitation = 11.0; // 11 dBm/MHz, FCC limit for 5150 to 5350 MHz range for STAs
    }
  else if (psdLimitRegulator == "ETSI")
    {
      m_psdLimitation = 10.0; // 10 dBm/MHz, ETSI limit for 5150 to 5350 MHz range
    }
  else
    {
      NS_ABORT_MSG ("Invalid regulation body for PSD limitation (choose among FCC, ETSI)");
    }

  m_nStations = m_nHeStations + m_nVhtStations;

  ReadTrafficSpecs (m_trafficFile);
  NS_ABORT_MSG_IF (m_flows.empty (), "No traffic flow specified!");

  if (!apDistance.empty ())
    {
      ReadParamList (apDistance, m_apDistances);
    }
  NS_ABORT_MSG_IF (m_apDistances.size () != m_nObss,
                   "The size of the AP distance vector (" << m_apDistances.size ()
                   << ") does not match the number of overlapping BSSes (" << m_nObss << ")");

  if (!apTheta.empty ())
    {
      ReadParamList (apTheta, m_apThetas);
    }
  NS_ABORT_MSG_IF (m_apThetas.size () != m_nObss,
                   "The size of the AP theta vector (" << m_apThetas.size ()
                   << ") does not match the number of overlapping BSSes (" << m_nObss << ")");

  std::cout << "Channel bw = " << m_channelWidth << " MHz" << std::endl
            << (m_heRate == "ideal" ? "Ideal rate manager" : "HE MCS = " + m_heRate) << std::endl
            << "Number of stations = " << m_nStations << std::endl
            << "EDCA queue max size = " << m_macQueueSize << " MSDUs" << std::endl
            << "MSDU lifetime = " << m_beMsduLifetime << " ms [BE]  "
                                  << m_bkMsduLifetime << " ms [BK]  "
                                  << m_viMsduLifetime << " ms [VI]  "
                                  << m_voMsduLifetime << " ms [VO]  " << std::endl
            << "BA buffer size = " << m_baBufferSize << std::endl;
  if (m_enableDlOfdma)
    {
      std::cout << "Ack sequence = " << m_dlAckSeqType << std::endl;
    }
  else
    {
      std::cout << "No OFDMA" << std::endl;
    }
  std::cout << std::endl;
}

void
WifiOfdmaExample::ReadTrafficSpecs (std::string filename)
{
  std::fstream fs;

  fs.open (filename);

  if (!fs.is_open ())
    {
      return;
    }

  uint16_t dstPort = 7000;
  std::string line;
  while (std::getline (fs, line))
    {
      std::stringstream inbuf (line);
      std::string str, direction;
      uint16_t beginStaId = 0, endStaId = 0;
      Flow flow;
      if (!(inbuf >> beginStaId))
        {
          // skip lines that do not begin with a stationId
          continue;
        }
      // read the Id of the first station of the range
      NS_ABORT_MSG_IF (beginStaId == 0 || beginStaId > m_nStations,
                       "Invalid begin station ID: " << beginStaId);
      // the next field may be either the AC or the last station of the range
      if (inbuf >> endStaId)
        {
          NS_ABORT_MSG_IF (endStaId == 0 || endStaId > m_nStations || endStaId < beginStaId,
                           "Invalid end station ID: " << endStaId);
        }
      else
        {
          inbuf.clear ();
          endStaId = beginStaId;
        }

      NS_ABORT_MSG_IF (!(inbuf >> str), "No AC found");
      if (str == "BE")
        {
          flow.m_ac = AC_BE;
        }
      else if (str == "BK")
        {
          flow.m_ac = AC_BK;
        }
      else if (str == "VI")
        {
          flow.m_ac = AC_VI;
        }
      else if (str == "VO")
        {
          flow.m_ac = AC_VO;
        }
      else
        {
          NS_ABORT_MSG ("Invalid AC: " << str);
        }

      // read the L4 protocol
      NS_ABORT_MSG_IF (!(inbuf >> str), "No L4 protocol found");
      if (str == "TCP" || str == "Tcp" || str == "tcp")
        {
          flow.m_l4Proto = Flow::TCP;
        }
      else if (str == "UDP" || str == "Udp" || str == "udp")
        {
          flow.m_l4Proto = Flow::UDP;
        }
      else
        {
          NS_ABORT_MSG ("Invalid L4 protocol: " << str);
        }

      // read the direction
      NS_ABORT_MSG_IF (!(inbuf >> direction)
                       || (direction != "DL" && direction != "UL" && direction != "DL+UL"),
                       "Invalid direction: " << direction);

      // read payload size
      NS_ABORT_MSG_IF (!(inbuf >> flow.m_payloadSize), "No payload size found");

      // read inter-departure time (ms) or constant bit rate (Mbps)
      double value;
      NS_ABORT_MSG_IF (!(inbuf >> str) || (str != "IDT" && str != "CBR"), "Unexpected token: " << str);
      NS_ABORT_MSG_IF (!(inbuf >> value) || value <= 0.0, "Invalid IDT/CBR value: " << value);
      if (str == "CBR")
        {
          flow.m_dataRate = value * 1e6;
        }
      else
        {
          flow.m_dataRate = (flow.m_payloadSize * 8) / (value * 1e-3);
        }

      for (uint16_t staId = beginStaId; staId <= endStaId; staId++)
        {
          flow.m_stationId = staId;
          if (direction == "DL" || direction == "DL+UL")
            {
              flow.m_direction = Flow::DOWNLINK;
              flow.m_dstPort = dstPort++;
              NS_LOG_DEBUG ("Adding flow " << flow);
              m_flows.push_back (flow);
            }
          if (direction == "UL" || direction == "DL+UL")
            {
              flow.m_direction = Flow::UPLINK;
              flow.m_dstPort = dstPort++;
              NS_LOG_DEBUG ("Adding flow " << flow);
              m_flows.push_back (flow);
            }
        }
    }
}

void
WifiOfdmaExample::Setup (void)
{
  NS_LOG_FUNCTION (this);

  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", m_enableRts ? StringValue ("0") : StringValue ("999999"));
  Config::SetDefault ("ns3::WifiRemoteStationManager::MaxSsrc", UintegerValue (999999));
  Config::SetDefault ("ns3::WifiRemoteStationManager::MaxSlrc", UintegerValue (999999));
  Config::SetDefault ("ns3::HeConfiguration::GuardInterval", TimeValue (NanoSeconds (m_guardInterval)));
  Config::SetDefault ("ns3::WifiPhy::PowerDensityLimit", DoubleValue (m_psdLimitation));
  Config::SetDefault ("ns3::ArpCache::AliveTimeout", TimeValue (Seconds (3600 * 24))); // ARP cache entries expire after one day
  Config::SetDefault ("ns3::WifiMacQueue::MaxSize", QueueSizeValue (QueueSize (PACKETS, m_macQueueSize)));
  Config::SetDefault ("ns3::HeConfiguration::MpduBufferSize", UintegerValue (m_baBufferSize));
  Config::SetDefault ("ns3::QosTxop::UseExplicitBarAfterMissedBlockAck", BooleanValue (m_useExplicitBar));
  Config::SetDefault ("ns3::HeConfiguration::MuBeAifsn", UintegerValue (m_muBeAifsn));
  Config::SetDefault ("ns3::HeConfiguration::MuBkAifsn", UintegerValue (m_muBkAifsn));
  Config::SetDefault ("ns3::HeConfiguration::MuViAifsn", UintegerValue (m_muViAifsn));
  Config::SetDefault ("ns3::HeConfiguration::MuVoAifsn", UintegerValue (m_muVoAifsn));
  Config::SetDefault ("ns3::HeConfiguration::MuBeCwMin", UintegerValue (m_muBeCwMin));
  Config::SetDefault ("ns3::HeConfiguration::MuBkCwMin", UintegerValue (m_muBkCwMin));
  Config::SetDefault ("ns3::HeConfiguration::MuViCwMin", UintegerValue (m_muViCwMin));
  Config::SetDefault ("ns3::HeConfiguration::MuVoCwMin", UintegerValue (m_muVoCwMin));
  Config::SetDefault ("ns3::HeConfiguration::MuBeCwMax", UintegerValue (m_muBeCwMax));
  Config::SetDefault ("ns3::HeConfiguration::MuBkCwMax", UintegerValue (m_muBkCwMax));
  Config::SetDefault ("ns3::HeConfiguration::MuViCwMax", UintegerValue (m_muViCwMax));
  Config::SetDefault ("ns3::HeConfiguration::MuVoCwMax", UintegerValue (m_muVoCwMax));
  Config::SetDefault ("ns3::HeConfiguration::BeMuEdcaTimer", TimeValue (MicroSeconds (m_beMuEdcaTimer)));
  Config::SetDefault ("ns3::HeConfiguration::BkMuEdcaTimer", TimeValue (MicroSeconds (m_bkMuEdcaTimer)));
  Config::SetDefault ("ns3::HeConfiguration::ViMuEdcaTimer", TimeValue (MicroSeconds (m_viMuEdcaTimer)));
  Config::SetDefault ("ns3::HeConfiguration::VoMuEdcaTimer", TimeValue (MicroSeconds (m_voMuEdcaTimer)));

  // Try to minimize the chances of collision among flows
  Config::SetDefault ("ns3::FqCoDelQueueDisc::Perturbation", UintegerValue (9973));
  Config::SetDefault ("ns3::FqCoDelQueueDisc::EnableSetAssociativeHash", BooleanValue (true));

  if (m_tcpSegmentSize != 0)
    {
      Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (m_tcpSegmentSize));
    }
  if (m_tcpInitialCwnd != 0)
    {
      Config::SetDefault ("ns3::TcpSocket::InitialCwnd", UintegerValue (m_tcpInitialCwnd));
    }
  if (m_tcpMinRto != 0)
    {
      Config::SetDefault ("ns3::TcpSocketBase::MinRto", TimeValue (MilliSeconds (m_tcpMinRto)));
    }


  Ptr<MultiModelSpectrumChannel> spectrumChannel = CreateObject<MultiModelSpectrumChannel> ();
  Ptr<FriisPropagationLossModel> lossModel = CreateObject<FriisPropagationLossModel> ();
  spectrumChannel->AddPropagationLossModel (lossModel);
  Ptr<ConstantSpeedPropagationDelayModel> delayModel = CreateObject<ConstantSpeedPropagationDelayModel> ();
  spectrumChannel->SetPropagationDelayModel (delayModel);

  for (uint16_t bss = 0; bss < m_nObss + 1; bss++)
    {
      NodeContainer apNode, heStaNodes, vhtStaNodes, obssStaNodes;

      apNode.Create (1);
      m_apNodes.Add (apNode);   // AP of the BSS under test is Node 0

      if (bss == 0)
        {
          // BSS under test
          heStaNodes.Create (m_nHeStations);
          m_staNodes.Add (heStaNodes); // it should be 10 stations
          vhtStaNodes.Create (m_nVhtStations);
          m_staNodes.Add (vhtStaNodes);
        }
      else
        {
          // Overlapping BSS
          obssStaNodes.Create (m_nStationsPerObss);
          m_obssStaNodes.push_back (obssStaNodes);
        }

      SpectrumWifiPhyHelper phy;
      phy.SetPcapDataLinkType (WifiPhyHelper::DLT_IEEE802_11_RADIO);
      phy.SetErrorRateModel ("ns3::NistErrorRateModel");
      phy.SetChannel (spectrumChannel);
      std::string cn = std::to_string (m_channelNumber);
      std::string cw = std::to_string (m_channelWidth);
      // it seems the input "band" from user was ignored
      std::string channelSetting = "{" + cn + ", " +  cw + ", BAND_5GHZ, 0}";
      phy.Set("ChannelSettings", StringValue(channelSetting));
      if (m_enableThresholdPreambleDetection)
        {
          phy.SetPreambleDetectionModel ("ns3::ThresholdPreambleDetectionModel");
        }
      phy.Set ("TxGain", DoubleValue (m_txGain));
      phy.Set ("RxGain", DoubleValue (m_rxGain));
      phy.Set ("RxSensitivity", DoubleValue (m_rxSensitivity));

      WifiHelper wifi;
      if (bss == 0 && m_verbose)
        {
          wifi.EnableLogComponents ();
        }
      if (bss > 0 || m_heRate == "ideal")
        {
          wifi.SetRemoteStationManager ("ns3::IdealWifiManager");
        }
      else
        {
          NS_ASSERT (m_nVhtStations == 0);
          uint8_t mcs = std::stoul (m_heRate);
          std::string ctrlRate = mcs == 0 ? "OfdmRate6Mbps"
                                          : (mcs < 3 ? "OfdmRate12Mbps" : "OfdmRate24Mbps");
          wifi.SetRemoteStationManager ("ns3::ConstantRateWifiManager",
                                        "DataMode", StringValue ("HeMcs" + m_heRate),
                                        "ControlMode", StringValue (ctrlRate));
        }

      if (m_dlAckSeqType == "ACK-SU-FORMAT")
        {
          Config::SetDefault ("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                              EnumValue (WifiAcknowledgment::DL_MU_BAR_BA_SEQUENCE));
        }
      else if (m_dlAckSeqType == "MU-BAR")
        {
          Config::SetDefault ("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                              EnumValue (WifiAcknowledgment::DL_MU_TF_MU_BAR));
        }
      else if (m_dlAckSeqType == "AGGR-MU-BAR")
        {
          Config::SetDefault ("ns3::WifiDefaultAckManager::DlMuAckSequenceType",
                              EnumValue (WifiAcknowledgment::DL_MU_AGGREGATE_TF));
        }
      else if (m_dlAckSeqType != "NO-OFDMA")
        {
          NS_ABORT_MSG ("Invalid DL ack sequence type (must be NO-OFDMA, ACK-SU-FORMAT, MU-BAR or AGGR-MU-BAR)");
        }

      WifiMacHelper mac;
      if (bss == 0 && m_enableDlOfdma)    // OFDMA only allowed for BSS under test
        {
          mac.SetMultiUserScheduler ("ns3::RrMultiUserScheduler",
                                     "NStations", UintegerValue (m_maxNRus),
                                     "ForceDlOfdma", BooleanValue (m_forceDlOfdma),
                                     "EnableUlOfdma", BooleanValue (m_enableUlOfdma),
                                     "EnableTxopSharing", BooleanValue (m_enableTxopSharing),
                                     "EnableBsrp", BooleanValue (m_enableBsrp),
                                     "UlPsduSize", UintegerValue (m_ulPsduSize),
                                     "UseCentral26TonesRus", BooleanValue (m_useCentral26TonesRus));
        }

      if (m_enableObssPd)
        {
          wifi.SetObssPdAlgorithm ("ns3::ConstantObssPdAlgorithm",
                                   "ObssPdLevelMin", DoubleValue (m_obssPdThresholdMinBss),
                                   "ObssPdLevelMax", DoubleValue (m_obssPdThresholdMaxBss),
                                   "ObssPdLevel", DoubleValue (m_obssPdThresholdBss));
        }

      mac.SetType ("ns3::StaWifiMac",
                  "Ssid", SsidValue (Ssid ("non-existing-ssid")));  // prevent stations from automatically associating
      phy.Set ("TxPowerStart", DoubleValue (m_powerSta));
      phy.Set ("TxPowerEnd", DoubleValue (m_powerSta));
      phy.Set ("CcaEdThreshold", DoubleValue (m_ccaThresholdSta));

      NetDeviceContainer staDevices, apDevice;

      if (bss == 0)
        {
          wifi.SetStandard (WIFI_STANDARD_80211ax);
          staDevices.Add (wifi.Install (phy, mac, heStaNodes));

          wifi.SetStandard (WIFI_STANDARD_80211ac);
          staDevices.Add (wifi.Install (phy, mac, vhtStaNodes));

          m_staDevices.Add (staDevices);
        }
      else
        {
          wifi.SetStandard (m_obssStandard);
          staDevices = wifi.Install (phy, mac, obssStaNodes);
          m_obssStaDevices.push_back (staDevices);
        }

      wifi.SetStandard (bss == 0 ? WIFI_STANDARD_80211ax : m_obssStandard);
      mac.SetType ("ns3::ApWifiMac",
                  "Ssid", SsidValue (Ssid (m_ssidPrefix + std::to_string (bss))));
      phy.Set ("TxPowerStart", DoubleValue (m_powerAp));
      phy.Set ("TxPowerEnd", DoubleValue (m_powerAp));
      phy.Set ("CcaEdThreshold", DoubleValue (m_ccaThresholdAp));

      apDevice = wifi.Install (phy, mac, apNode);
      m_apDevices.Add (apDevice);

      // The below statements may be simplified in a future HeConfigurationHelper
      if ((m_enableObssPd))
        {
          Ptr<HeConfiguration> heConfiguration = DynamicCast<WifiNetDevice> (apDevice.Get (0))->GetHeConfiguration ();
          heConfiguration->SetAttribute ("BssColor", UintegerValue (bss + 1));
        }

      if (m_enablePcap)
        {
          phy.EnablePcap ("STA_pcap", staDevices);
          phy.EnablePcap ("AP_pcap", apDevice);
        }
    }

  int64_t streamNumber = 100;

  // Assign fixed streams to random variables in use
  WifiHelper wifi;
  streamNumber += wifi.AssignStreams (m_apDevices, streamNumber);
  streamNumber += wifi.AssignStreams (m_staDevices, streamNumber);
  for (const auto& devices : m_obssStaDevices)
    {
      streamNumber += wifi.AssignStreams (devices, streamNumber);
    }

  // Configure max A-MSDU size and max A-MPDU size on the AP of the BSS under test
  Ptr<WifiNetDevice> dev = DynamicCast<WifiNetDevice> (m_apDevices.Get (0));
  dev->GetMac ()->SetAttribute ("BE_MaxAmsduSize", UintegerValue (m_beMaxAmsduSize));
  dev->GetMac ()->SetAttribute ("BK_MaxAmsduSize", UintegerValue (m_bkMaxAmsduSize));
  dev->GetMac ()->SetAttribute ("VI_MaxAmsduSize", UintegerValue (m_viMaxAmsduSize));
  dev->GetMac ()->SetAttribute ("VO_MaxAmsduSize", UintegerValue (m_voMaxAmsduSize));
  dev->GetMac ()->SetAttribute ("BE_MaxAmpduSize", UintegerValue (m_beMaxAmpduSize));
  dev->GetMac ()->SetAttribute ("BK_MaxAmpduSize", UintegerValue (m_bkMaxAmpduSize));
  dev->GetMac ()->SetAttribute ("VI_MaxAmpduSize", UintegerValue (m_viMaxAmpduSize));
  dev->GetMac ()->SetAttribute ("VO_MaxAmpduSize", UintegerValue (m_voMaxAmpduSize));
  m_band = dev->GetPhy ()->GetPhyBand ();
  // Configure TXOP Limit and MSDU lifetime on the AP
  PointerValue ptr;
  dev->GetMac ()->GetAttribute ("BE_Txop", ptr);
  ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_beTxopLimit));
  ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_beMsduLifetime));
  dev->GetMac ()->GetAttribute ("BK_Txop", ptr);
  ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_bkTxopLimit));
  ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_bkMsduLifetime));
  dev->GetMac ()->GetAttribute ("VI_Txop", ptr);
  ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_viTxopLimit));
  ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_viMsduLifetime));
  dev->GetMac ()->GetAttribute ("VO_Txop", ptr);
  ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_voTxopLimit));
  ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_voMsduLifetime));

  // Configure max A-MSDU size, max A-MPDU size, TXOP Limit and MSDU lifetime on the stations
  // of the BSS under test
  for (uint32_t i = 0; i < m_staNodes.GetN (); i++)
    {
      dev = DynamicCast<WifiNetDevice> (m_staDevices.Get (i));
      dev->GetMac ()->SetAttribute ("BE_MaxAmsduSize", UintegerValue (m_beMaxAmsduSize));
      dev->GetMac ()->SetAttribute ("BK_MaxAmsduSize", UintegerValue (m_bkMaxAmsduSize));
      dev->GetMac ()->SetAttribute ("VI_MaxAmsduSize", UintegerValue (m_viMaxAmsduSize));
      dev->GetMac ()->SetAttribute ("VO_MaxAmsduSize", UintegerValue (m_voMaxAmsduSize));
      dev->GetMac ()->SetAttribute ("BE_MaxAmpduSize", UintegerValue (m_beMaxAmpduSize));
      dev->GetMac ()->SetAttribute ("BK_MaxAmpduSize", UintegerValue (m_bkMaxAmpduSize));
      dev->GetMac ()->SetAttribute ("VI_MaxAmpduSize", UintegerValue (m_viMaxAmpduSize));
      dev->GetMac ()->SetAttribute ("VO_MaxAmpduSize", UintegerValue (m_voMaxAmpduSize));
      dev->GetMac ()->GetAttribute ("BE_Txop", ptr);
      ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_beTxopLimit));
      ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_beMsduLifetime));
      dev->GetMac ()->GetAttribute ("BK_Txop", ptr);
      ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_bkTxopLimit));
      ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_bkMsduLifetime));
      dev->GetMac ()->GetAttribute ("VI_Txop", ptr);
      ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_viTxopLimit));
      ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_viMsduLifetime));
      dev->GetMac ()->GetAttribute ("VO_Txop", ptr);
      ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_voTxopLimit));
      ptr.Get<QosTxop> ()->GetWifiMacQueue ()->SetMaxDelay (MilliSeconds (m_voMsduLifetime));
    }

  // Configure max A-MPDU size and TXOP Limit for APs and stations of the overlapping BSSes
  for (uint16_t bss = 0; bss < m_nObss; bss++)
    {
      dev = DynamicCast<WifiNetDevice> (m_apDevices.Get (bss + 1));
      dev->GetMac ()->SetAttribute ("BE_MaxAmpduSize", UintegerValue (m_obssMaxAmpduSize));
      dev->GetMac ()->GetAttribute ("BE_Txop", ptr);
      ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_obssTxopLimit));

      for (std::size_t i = 0; i < m_nStationsPerObss; i++)
        {
          dev = DynamicCast<WifiNetDevice> (m_obssStaDevices.at (bss).Get (i));
          dev->GetMac ()->SetAttribute ("BE_MaxAmpduSize", UintegerValue (m_obssMaxAmpduSize));
          dev->GetMac ()->GetAttribute ("BE_Txop", ptr);
          ptr.Get<QosTxop> ()->SetTxopLimit (MicroSeconds (m_obssTxopLimit));
        }
    }

  // Setting mobility model
  for (uint16_t bss = 0; bss < m_nObss + 1; bss++)
    {
      MobilityHelper mobility;
      mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");

      Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
      Vector apPos (0.0, 0.0, 0.0);  // initialized to the position of the AP of the BSS under test

      if (bss > 0)
        {
          // position of the AP of an overlapping BSS
          apPos = Vector (m_apDistances.at (bss - 1) * std::cos (m_apThetas.at (bss - 1) * M_PI / 180),
                          m_apDistances.at (bss - 1) * std::sin (m_apThetas.at (bss - 1) * M_PI / 180),
                          0.0);
        }
      positionAlloc->Add (apPos);
      mobility.SetPositionAllocator (positionAlloc);
      mobility.Install (m_apNodes.Get (bss));

      Ptr<UniformDiscPositionAllocator> staPositionAlloc =
        CreateObjectWithAttributes<UniformDiscPositionAllocator> ("rho", DoubleValue (m_radius),
                                                                  "X", DoubleValue (apPos.x),
                                                                  "Y", DoubleValue (apPos.y));
      streamNumber += staPositionAlloc->AssignStreams (streamNumber);
      mobility.SetPositionAllocator (staPositionAlloc);

      if (bss == 0)
        {
          mobility.Install (m_staNodes);
        }
      else
        {
          mobility.Install (m_obssStaNodes.at (bss - 1));
        }
    }

  /* Internet stack */
  InternetStackHelper stack;
  stack.Install (m_apNodes);
  stack.Install (m_staNodes);
  for (auto& nodes : m_obssStaNodes)
    {
      stack.Install (nodes);
    }

  Ipv4AddressHelper address;
  address.SetBase ("10.1.0.0", "255.255.0.0");
  m_staInterfaces = address.Assign (m_staDevices);
  m_apInterfaces = address.Assign (m_apDevices.Get (0));

  for (uint16_t bss = 0; bss < m_nObss; bss++)
    {
      address.SetBase (std::string ("10." + std::to_string (bss + 2) + ".0.0").c_str (), "255.255.0.0");
      m_apInterfaces.Add (address.Assign (m_apDevices.Get (bss + 1)));
      m_obssStaInterfaces.push_back (address.Assign (m_obssStaDevices.at (bss)));
    }

  /* Traffic Control layer */
  TrafficControlHelper tch;
  if (m_queueDisc.compare ("default") != 0)
    {
      // Uninstall the root queue disc on all the devices
      tch.Uninstall (m_apDevices);
      tch.Uninstall (m_staDevices);
      for (auto& devices : m_obssStaDevices)
        {
          tch.Uninstall (devices);
        }
    }

  m_clientApps.resize (m_flows.size ());
  m_obssClientApps.resize (m_nObss);

  /* Install applications (receiver side) */
  for (auto& flow : m_flows)
    {
      std::string socketType = (flow.m_l4Proto == Flow::TCP
                                ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory");
      PacketSinkHelper packetSinkHelper (socketType, InetSocketAddress (Ipv4Address::GetAny (),
                                                                        flow.m_dstPort));
      if (flow.m_direction == Flow::DOWNLINK)
        {
          m_sinkApps.Add (packetSinkHelper.Install (m_staNodes.Get (flow.m_stationId - 1)));
        }
      else
        {
          m_sinkApps.Add (packetSinkHelper.Install (m_apNodes.Get (0)));
        }
    }

  m_sinkApps.Stop (Seconds (m_warmup + m_simulationTime + 100)); // let the servers be active for a long time

  m_obssSinkApps.resize (m_nObss);

  if (m_obssDlAggregateRate > 0)
    {
      // install receivers on stations of overlapping BSSes
      PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 7000));
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          m_obssSinkApps.at (bss).Add (packetSinkHelper.Install (m_obssStaNodes.at (bss)));
        }
    }

  if (m_obssUlAggregateRate > 0)
    {
      // install receivers on the APs of overlapping BSSes
      PacketSinkHelper packetSinkHelper ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), 7000));
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          m_obssSinkApps.at (bss).Add (packetSinkHelper.Install (m_apNodes.Get (bss + 1)));
        }
    }

  for (auto& obssSinkApps : m_obssSinkApps)
    {
      obssSinkApps.Stop (Seconds (m_warmup + m_simulationTime + 100)); // let the servers be active for a long time
    }

  /* Init statistics */
  m_obssDlRxStart.assign (m_nObss, 0.0);
  m_obssUlRxStart.assign (m_nObss, 0.0);
  m_obssDlRxStop.assign (m_nObss, 0.0);
  m_obssUlRxStop.assign (m_nObss, 0.0);

  // per-AC and pairwise per-AC statistics
  m_perAcStats.resize (m_nStations + 1);
  m_dlPerStaAcStats.resize (m_nStations);
  m_ulPerStaAcStats.resize (m_nStations);
  m_nSolicitingBasicTriggerFrames.assign (m_nStations, 0);

  for (auto& flow : m_flows)
    {
      if (flow.m_direction == Flow::DOWNLINK || flow.m_l4Proto == Flow::TCP)
        {
          if (flow.m_direction == Flow::DOWNLINK)
            {
              m_dlPerStaAcStats[flow.m_stationId - 1][flow.m_ac] = PairwisePerAcStats ();
              m_perAcStats[0][flow.m_ac] = PerAcStats ();
            }
          else
            {
              // TCP uplink flow -> BE downlink flow comprising TCP acks
              m_dlPerStaAcStats[flow.m_stationId - 1][AC_BE] = PairwisePerAcStats ();
              m_perAcStats[0][AC_BE] = PerAcStats ();
            }
        }
      if (flow.m_direction == Flow::UPLINK || flow.m_l4Proto == Flow::TCP)
        {
          if (flow.m_direction == Flow::UPLINK)
            {
              m_ulPerStaAcStats[flow.m_stationId - 1][flow.m_ac] = PairwisePerAcStats ();
              m_perAcStats[flow.m_stationId][flow.m_ac] = PerAcStats ();
            }
          else
            {
              // TCP downlink flow -> BE uplink flow comprising TCP acks
              m_ulPerStaAcStats[flow.m_stationId - 1][AC_BE] = PairwisePerAcStats ();
              m_perAcStats[flow.m_stationId][AC_BE] = PerAcStats ();
            }
        }
    }

  Config::ConnectWithoutContext ("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Mac/$ns3::StaWifiMac/Assoc",
                                 MakeCallback (&WifiOfdmaExample::EstablishBaAgreement, this));

  // populate m_staMacAddressToNodeId map
  for (auto it = m_staDevices.Begin (); it != m_staDevices.End (); it++)
    {
      m_staMacAddressToNodeId[Mac48Address::ConvertFrom ((*it)->GetAddress ())] = (*it)->GetNode ()->GetId ();
    }
}

void
WifiOfdmaExample::Run (void)
{
  NS_LOG_FUNCTION (this);

  // Start the setup phase by having the first station associate with the AP
  Simulator::ScheduleNow (&WifiOfdmaExample::StartAssociation, this);

  Simulator::Run ();
}


template <typename T, typename FUNC>
void
WifiOfdmaExample::PrintStatsWithTotal (std::vector<std::map<AcIndex, T>> v, FUNC select,
                                       std::ostream& os, std::string s, std::string s0)
{
  std::size_t i;
  auto ac = m_aciToString.begin ();
  decltype (select (std::declval<T> ())) sum {0}, totalSum {0}, ap {0};

  auto print = [&](const std::map<AcIndex, T>& x, std::string str = "")
               {
                 auto it = x.find (ac->first);
                 if (it != x.end ())
                   {
                     os << (str.empty () ? s + std::to_string (i) : s0) 
                        << ": " << select (it->second) << " ";
                     sum += select (it->second);
                   }
                  i++;
               };

  os << "------------------------------" << std::endl;
  for (; ac != m_aciToString.end (); ac++ )
    {
      // check if at least one station exchanged traffic of this AC
      if (std::find_if (v.begin (), v.end (), [&ac](const std::map<AcIndex, T>& map)
                                              { return map.find (ac->first) != map.end (); })
          == v.end ())
        {
          continue;
        }

      os << "[" << ac->second << "] ";
      auto it = v.begin ();
      if (!s0.empty ())
        {
          i = 0;
          print (*it, "AP");
          it++;
          ap = sum;
          sum = 0;
        }
      i = 1;
      std::for_each (it, v.end (), print);
      os << std::endl;
      if (!s0.empty ())
        {
          os << "[" << ac->second << "] TotalDL: " << ap << std::endl
             << "[" << ac->second << "] TotalUL: " << sum << std::endl;
        }
      else
        {
          os << "[" << ac->second << "] Total: " << sum << std::endl;
        }
      totalSum += sum;
      totalSum += ap;
      sum = 0;
      ap = 0;
    }
  os << "TOTAL: " << totalSum << std::endl << std::endl;
}

template <typename T, typename FUNC>
void
WifiOfdmaExample::PrintStats (std::vector<std::map<AcIndex, T>> v, FUNC select,
                              std::ostream& os, std::string s, std::string s0)
{
  std::size_t i;
  auto ac = m_aciToString.begin ();

  auto print = [&](const std::map<AcIndex, T>& x, std::string str = "")
               {
                 auto it = x.find (ac->first);
                 if (it != x.end ())
                   {
                     os << (str.empty () ? s + std::to_string (i) : s0) 
                        << ": " << select (it->second) << " ";
                   }
                  i++;
               };

  os << "------------------------------" << std::endl;
  for (; ac != m_aciToString.end (); ac++ )
    {
      // check if at least one station exchanged traffic of this AC
      if (std::find_if (v.begin (), v.end (), [&ac](const std::map<AcIndex, T>& map)
                                              { return map.find (ac->first) != map.end (); })
          == v.end ())
        {
          continue;
        }

      os << "[" << ac->second << "] ";
      auto it = v.begin ();
      if (!s0.empty ())
        {
          i = 0;
          print (*it, "AP");
          it++;
        }
      i = 1;
      std::for_each (it, v.end (), print);
      os << std::endl;
    }
  os << std::endl;
}


void
WifiOfdmaExample::PrintResults (std::ostream& os)
{
  NS_LOG_FUNCTION (this);

  os << "PER-FLOW statistics" << std::endl << "************************" << std::endl;
  std:: ofstream odfma_output;
  ofdma_output.open("ofdma.txt",std::ios::out);

  int check=0;
  for (std::size_t i = 0; i < m_flows.size (); i++)
    {

      os << "FLOW " << m_flows[i] << std::endl
         << std::fixed << std::setprecision (3)
         int flag1=0;
         int flag2=0;
         for(std::pair<uint64_t,double> pkt:m_flows[i].appLatencies.m_samples){
            flag1+=pkt.second;
            flag2++;
         }
         double flag3=(double)flag1/flag2;
         
         odfma_output << flag3 <<std::endl;
         ofdma.close();
         << "Throughput: " << (m_flows[i].m_rxBytes * 8.) / (m_simulationTime * 1e6) << std::endl
         << "Expected data rate: " << m_flows[i].m_dataRate / 1e6 << std::endl
         << "Actual data rate: " << (m_flows[i].m_txBytes * 8.) / (m_simulationTime * 1e6) << std::endl
         << "Packet loss rate: " << static_cast<double> (m_flows[i].m_txPackets
                                                         + m_flows[i].m_packetsRejectedBySocket
                                                         - m_flows[i].m_rxPackets)
                                    / (m_flows[i].m_txPackets + m_flows[i].m_packetsRejectedBySocket)
         << std::endl
         << "Dropped packets (app layer): " << m_flows[i].m_packetsRejectedBySocket << std::endl
         << "Latency: " << m_flows[i].m_latency << std::endl << std::endl;
    }


  for (uint16_t bss = 0; bss < m_nObss; bss++)
    {
      os << "OBSS " << bss + 1 << std::endl;
      if (m_obssDlAggregateRate > 0)
        {
          os << "DL Throughput: " << ((m_obssDlRxStop[bss] - m_obssDlRxStart[bss]) * 8.) / (m_simulationTime * 1e6)
             << std::endl;
        }
      if (m_obssUlAggregateRate > 0)
        {
          os << "UL Throughput: " << ((m_obssUlRxStop[bss] - m_obssUlRxStart[bss]) * 8.) / (m_simulationTime * 1e6)
             << std::endl;
        }
      os << std::endl;
    }

  /* Per-AC statistics from per-flow statistics */
  std::vector<std::map<AcIndex, double>> dlTput (m_nStations), ulTput (m_nStations);
  std::vector<std::map<AcIndex, Stats<double>>> dlLatency (m_nStations), ulLatency (m_nStations);
  std::vector<std::map<AcIndex, uint64_t>> dlSentPkts (m_nStations), ulSentPkts (m_nStations),
                                           dlRecvPkts (m_nStations), ulRecvPkts (m_nStations);

  for (std::size_t i = 0; i < m_flows.size (); i++)
    {
      std::vector<std::map<AcIndex, double>>::iterator tputVecIt;
      std::vector<std::map<AcIndex, Stats<double>>>::iterator latencyVecIt;
      std::vector<std::map<AcIndex, uint64_t>>::iterator sentVecIt, recvVecIt;

      if (m_flows[i].m_direction == Flow::DOWNLINK)
        {
          tputVecIt = std::next (dlTput.begin (), m_flows[i].m_stationId - 1);
          latencyVecIt = std::next (dlLatency.begin (), m_flows[i].m_stationId - 1);
          sentVecIt = std::next (dlSentPkts.begin (), m_flows[i].m_stationId - 1);
          recvVecIt = std::next (dlRecvPkts.begin (), m_flows[i].m_stationId - 1);
        }
      else
        {
          tputVecIt = std::next (ulTput.begin (), m_flows[i].m_stationId - 1);
          latencyVecIt = std::next (ulLatency.begin (), m_flows[i].m_stationId - 1);
          sentVecIt = std::next (ulSentPkts.begin (), m_flows[i].m_stationId - 1);
          recvVecIt = std::next (ulRecvPkts.begin (), m_flows[i].m_stationId - 1);
        }

      auto mapIt = tputVecIt->insert ({m_flows[i].m_ac, 0.0}).first;
      mapIt->second += (m_flows[i].m_rxBytes * 8.) / (m_simulationTime * 1e6);

      auto mapIt2 = latencyVecIt->insert ({m_flows[i].m_ac, 0}).first;
      mapIt2->second += m_flows[i].m_latency;

      auto mapIt3 = sentVecIt->insert ({m_flows[i].m_ac, 0.0}).first;
      mapIt3->second += (m_flows[i].m_txPackets + m_flows[i].m_packetsRejectedBySocket);

      mapIt3 = recvVecIt->insert ({m_flows[i].m_ac, 0.0}).first;
      mapIt3->second += m_flows[i].m_rxPackets;
    }

  os << "PAIRWISE PER-AC statistics" << std::endl << "************************" << std::endl;

  os << "Throughput (Mbps) [DL]" << std::endl;
  PrintStatsWithTotal (dlTput, [](const double& t) { return t; }, os, "To_STA_");
  os << "Throughput (Mbps) [UL]" << std::endl;
  PrintStatsWithTotal (ulTput, [](const double& t) { return t; }, os, "From_STA_");

  os << "E2e latency (ms) [DL]" << std::endl;
  PrintStatsWithTotal (dlLatency, [](const Stats<double>& t) { return t; }, os, "To_STA_");
  os << "E2e latency (ms) [UL]" << std::endl;
  PrintStatsWithTotal (ulLatency, [](const Stats<double>& t) { return t; }, os, "From_STA_");

  os << "Transmitted packets [DL]" << std::endl;
  PrintStatsWithTotal (dlSentPkts, [](const uint64_t& t) { return t; }, os, "To_STA_");
  os << "Transmitted packets [UL]" << std::endl;
  PrintStatsWithTotal (ulSentPkts, [](const uint64_t& t) { return t; }, os, "From_STA_");

  os << "Received packets [DL]" << std::endl;
  PrintStatsWithTotal (dlRecvPkts, [](const uint64_t& t) { return t; }, os, "To_STA_");
  os << "Received packets [UL]" << std::endl;
  PrintStatsWithTotal (ulRecvPkts, [](const uint64_t& t) { return t; }, os, "From_STA_");

  /* EXPIRED MSDUs */
  os << "MSDUs expired at the AP [DL]" << std::endl;
  PrintStatsWithTotal (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.expired; },
                       os, "To_STA_");
  os << "MSDUs expired at the STAs [UL]" << std::endl;
  PrintStatsWithTotal (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.expired; },
                       os, "From_STA_");
  
  /* REJECTED MSDUs */
  os << "MSDUs rejected at the AP [DL]" << std::endl;
  PrintStatsWithTotal (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.rejected; },
                       os, "To_STA_");
  os << "MSDUs rejected at the STAs [UL]" << std::endl;
  PrintStatsWithTotal (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.rejected; },
                       os, "From_STA_");

  /* FAILED MPDUs */
  os << "TX failures at the AP [DL]" << std::endl;
  PrintStatsWithTotal (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.failed; },
                       os, "To_STA_");
  os << "TX failures at the STAs [UL]" << std::endl;
  PrintStatsWithTotal (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.failed; },
                       os, "From_STA_");

  /* A-MPDU SIZE */
  os << "A-MPDU size (min/avg/max/count) [DL]" << std::endl;
  PrintStats (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.ampduSize; },
              os, "To_STA_");
  os << "A-MPDU size (min/avg/max/count) [UL]" << std::endl;
  PrintStats (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.ampduSize; },
              os, "From_STA_");

  /* A-MPDU DURATION TO DL/UL MU PPDU DURATION RATIO */
  os << "A-MPDU duration to DL MU PPDU duration ratio (min/avg/max/count) [DL]" << std::endl;
  PrintStats (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.ampduRatio; },
              os, "To_STA_");
  os << "A-MPDU duration to Basic TF's UL Length ratio (min/avg/max/count) [UL]" << std::endl;
  PrintStats (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.ampduRatio; },
              os, "From_STA_");

  /* L2 LATENCY */
  os << "L2 latency (percentiles[count]) [DL]" << std::endl;
  PrintStatsWithTotal (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.l2Latency; },
                       os, "To_STA_");
  os << "L2 latency (percentiles[count]) [UL]" << std::endl;
  PrintStatsWithTotal (m_ulPerStaAcStats, [](const PairwisePerAcStats& s) { return s.l2Latency; },
                       os, "From_STA_");

  /* HEAD-OF-LINE DELAY */
  os << "Pairwise Head-of-Line delay (percentiles[count]) at the AP [DL]" << std::endl;
  PrintStatsWithTotal (m_dlPerStaAcStats, [](const PairwisePerAcStats& s) { return s.pairwiseHol; },
                       os, "To_STA_");

  os << "PER-AC statistics" << std::endl << "************************" << std::endl;

  os << "Aggregate Head-of-Line delay (percentiles[count])" << std::endl;
  PrintStats (m_perAcStats, [](const PerAcStats& s) { return s.aggregateHoL; },
              os, "STA_", "AP");

  /* QUEUE DISC SOJOURN TIME AND PACKET DROPPED  */
  os << "Sojourn time in the queue disc associated with each AC" << std::endl;
  PrintStatsWithTotal (m_perAcStats, [](const PerAcStats& s) { return s.queueDiscSojournTime; },
                       os, "STA_", "AP");

  os << "Packets dropped by the queue disc associated with each AC" << std::endl;
  PrintStatsWithTotal (m_perAcStats, [](const PerAcStats& s) { return s.droppedByQueueDisc; },
                       os, "STA_", "AP");

  /* TXOP DURATION */
  os << "TXOP duration (percentiles[count])" << std::endl;
  PrintStats (m_perAcStats, [](const PerAcStats& s) { return s.txopDuration; },
              os, "STA_", "AP");

  os << "PER-STA statistics" << std::endl << "************************" << std::endl;

  os << "DL MU PPDU completeness (percentiles[count])" << std::endl
     << "------------------------------" << std::endl
     << m_dlMuCompleteness << std::endl << std::endl;

  os << "HE TB PPDU completeness (percentiles[count])" << std::endl
     << "------------------------------" << std::endl
     << m_heTbCompleteness << std::endl << std::endl;

  os << "DL MU PPDU duration (percentiles[count])" << std::endl
     << "------------------------------" << std::endl
     << m_dlMuPpduDuration << std::endl << std::endl;

  os << "HE TB PPDU duration (percentiles[count])" << std::endl
     << "------------------------------" << std::endl
     << m_heTbPpduDuration << std::endl << std::endl;

  os << "Basic Trigger Frames (failed/sent)" << std::endl
     << "------------------------------" << std::endl
     << "(" << m_nFailedBasicTriggerFrames << ", "
     << m_nBasicTriggerFramesSent << ")" << std::endl << std::endl;

  os << "BSRP Trigger Frames (failed/sent)" << std::endl
     << "------------------------------" << std::endl
     << "(" << m_nFailedBsrpTriggerFrames << ", "
     << m_nBsrpTriggerFramesSent << ")" << std::endl << std::endl;

  os << "Unresponded Basic TFs ratio" << std::endl
     << "------------------------------" << std::endl;
  for (uint16_t i = 0; i < m_nStations; i++)
    {
      uint64_t heTbPPduCount = 0;  // for i-th STA
      for (auto& acStats : m_ulPerStaAcStats.at (i))
        {
          heTbPPduCount += acStats.second.ampduRatio.m_samples.size ();
        }
      os << "STA_" << i + 1 << ": "
         << static_cast<double> (m_nSolicitingBasicTriggerFrames.at (i) - heTbPPduCount)
            / m_nSolicitingBasicTriggerFrames.at (i) << " ";
    }
  os << std::endl << std::endl;
}

void
WifiOfdmaExample::StartAssociation (void)
{
  NS_LOG_FUNCTION (this << m_currentSta);
  NS_ASSERT (m_currentSta < m_nStations + m_nObss * m_nStationsPerObss);

  Ptr<WifiNetDevice> dev;
  uint16_t bss = 0;

  if (m_currentSta < m_nStations)
    {
      dev = DynamicCast<WifiNetDevice> (m_staDevices.Get (m_currentSta));
    }
  else
    {
      auto pair = StationIdToBssIndexPair (m_currentSta);
      bss = pair.first;
      dev = DynamicCast<WifiNetDevice> (m_obssStaDevices.at (bss - 1).Get (pair.second));
    }

  NS_ASSERT (dev != nullptr);
   // this will lead the station to associate with the AP
  dev->GetMac ()->SetSsid (Ssid (m_ssidPrefix + std::to_string (bss)));
}

void
WifiOfdmaExample::EstablishBaAgreement (Mac48Address bssid)
{
  NS_LOG_FUNCTION (this << bssid << m_currentSta);

  // Now that the current station is associated with the AP, let's trigger the creation
  // of an entry in the ARP cache (of both the AP and the STA) and the establishment of
  // Block Ack agreements between the AP and the STA (and viceversa) for the relevant
  // TIDs. This is done by having the AP send 4 ICMP Echo Requests to the STA
  uint16_t pingInterval = 50;  // milliseconds

  std::map<AcIndex, uint8_t> acTos = {{AC_BE, 0x00 /* CS0 */}, {AC_BK, 0x28 /* AF11 */},
                                      {AC_VI, 0xb8 /* EF */}, {AC_VO, 0xc0 /* CS7 */}};
  Ipv4Address staAddress;
  Ptr<Node> apNode;
  uint16_t bss = 0;

  if (m_currentSta < m_nStations)
    {
      staAddress = m_staInterfaces.GetAddress (m_currentSta);
      apNode = m_apNodes.Get (0);
    }
  else
    {
      auto pair = StationIdToBssIndexPair (m_currentSta);
      bss = pair.first;
      staAddress = m_obssStaInterfaces.at (bss - 1).GetAddress (pair.second);
      apNode = m_apNodes.Get (bss);
    }

  V4PingHelper ping (staAddress);
  void (*addPingApp)(V4PingHelper, Ptr<Node>);  // function pointer
  addPingApp = [](V4PingHelper helper, Ptr<Node> node)
               {
                 ApplicationContainer apps = helper.Install (node);
                 apps.Stop (MilliSeconds (10)); // send just one Echo Request
               };

  if (m_verbose)
    {
      ping.SetAttribute ("Verbose", BooleanValue (true));
    }
  for (auto& ac : acTos)
    {
      ping.SetAttribute ("Tos", UintegerValue (ac.second));
      Simulator::Schedule (MilliSeconds (pingInterval * static_cast<uint16_t> (ac.first)),
                           addPingApp, ping, apNode);
    }

  // set the duration of the "On" interval to zero for all client applications so that,
  // once started, they will stay quiet (i.e., no packet is transmitted) and wake at the
  // end of every "Off" interval to check if the "On" period has become non-zero.
  // The start of all the client applications is aligned to an integer multiple of
  // pingInterval (also referred to as a "slot"),

  // convert pingInterval to time units
  int64_t slotUnits = pingInterval * std::pow (10, (Time::GetResolution () - Time::MS) * 3);
  // the start time is 4 pingIntervals from now and aligned to the next slot boundary
  int64_t startTime = ((Simulator::Now ().GetTimeStep () + 4 * slotUnits) / slotUnits + 1) * slotUnits;
  Time startDelay = TimeStep (startTime) - Simulator::Now ();
  NS_ASSERT (startDelay.IsStrictlyPositive ());

  std::size_t i = 0;
  for (auto& flow : m_flows)
    {
      // Install a client application for each flow involving the current station.
      // In case of TCP traffic, this will trigger the establishment of a TCP connection.
      if (flow.m_stationId == m_currentSta + 1)
        {
          std::string socketType = (flow.m_l4Proto == Flow::TCP
                                    ? "ns3::TcpSocketFactory" : "ns3::UdpSocketFactory");
          OnOffHelper client (socketType, Ipv4Address::GetAny ());
          client.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
          client.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant="
                                                       + std::to_string (pingInterval / 1000.) + "]"));
          client.SetAttribute ("DataRate", DataRateValue (DataRate (flow.m_dataRate)));
          client.SetAttribute ("PacketSize", UintegerValue (flow.m_payloadSize));

          Ipv4Address destAddress;
          Ptr<Node> srcNode;
          if (flow.m_direction == Flow::DOWNLINK)
            {
              destAddress = m_staInterfaces.GetAddress (m_currentSta);
              srcNode = m_apNodes.Get (0);
            }
          else
            {
              destAddress = m_apInterfaces.GetAddress (0);
              srcNode = m_staNodes.Get (m_currentSta);
            }
          InetSocketAddress dest (destAddress, flow.m_dstPort);
          dest.SetTos (acTos.at (flow.m_ac));
          client.SetAttribute ("Remote", AddressValue (dest));

          Simulator::Schedule (startDelay,
                               &WifiOfdmaExample::StartClient, this, client, i, srcNode);
        }
      i++;
    }

  // Install client applications in the OBSSes
  if (m_currentSta >= m_nStations && m_obssDlAggregateRate > 0)
    {
      OnOffHelper client ("ns3::UdpSocketFactory", Ipv4Address::GetAny ());
      client.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
      client.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant="
                                                   + std::to_string (pingInterval / 1000.) + "]"));
      client.SetAttribute ("DataRate", DataRateValue (DataRate (m_obssDlAggregateRate * 1e6 / m_nStationsPerObss)));
      client.SetAttribute ("PacketSize", UintegerValue (m_obssDlPayload));
      client.SetAttribute ("Remote", AddressValue (InetSocketAddress (staAddress, 7000)));

      Simulator::Schedule (startDelay,
                           &WifiOfdmaExample::StartObssClient, this, client, bss, apNode);
    }

  if (m_currentSta >= m_nStations && m_obssUlAggregateRate > 0)
    {
      OnOffHelper client ("ns3::UdpSocketFactory", Ipv4Address::GetAny ());
      client.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
      client.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant="
                                                   + std::to_string (pingInterval / 1000.) + "]"));
      client.SetAttribute ("DataRate", DataRateValue (DataRate (m_obssUlAggregateRate * 1e6 / m_nStationsPerObss)));
      client.SetAttribute ("PacketSize", UintegerValue (m_obssUlPayload));
      client.SetAttribute ("Remote", AddressValue (InetSocketAddress (m_apInterfaces.GetAddress (bss),
                                                                      7000)));

      auto pair = StationIdToBssIndexPair (m_currentSta);

      Simulator::Schedule (startDelay,
                           &WifiOfdmaExample::StartObssClient, this, client, bss,
                           m_obssStaNodes.at (bss - 1).Get (pair.second));
    }

  // continue with the next station, if any is remaining
  if (++m_currentSta < m_nStations + m_nObss * m_nStationsPerObss)
    {
      Simulator::Schedule (startDelay + MilliSeconds (pingInterval), &WifiOfdmaExample::StartAssociation, this);
    }
  else
    {
      // call DelayStart (which changes the duration of the last "Off" period) 1 ms
      // before a slot boundary
      Simulator::Schedule (startDelay + MilliSeconds (pingInterval - 1), &WifiOfdmaExample::DelayStart, this);
    }
}

void
WifiOfdmaExample::StartClient (OnOffHelper client, std::size_t i, Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node->GetId ());

  m_clientApps[i] = client.Install (node).Get (0);
  m_clientApps[i]->SetStopTime (Seconds (m_warmup + m_simulationTime + 100)); // let clients be active for a long time
}

void
WifiOfdmaExample::StartObssClient (OnOffHelper client, uint16_t bss, Ptr<Node> node)
{
  NS_LOG_FUNCTION (this << node->GetId ());

  Ptr<Application> app = client.Install (node).Get (0);
  app->SetStopTime (Seconds (m_warmup + m_simulationTime + 100)); // let clients be active for a long time
  m_obssClientApps.at (bss - 1).Add (app);
}

void
WifiOfdmaExample::DelayStart (void)
{
  NS_LOG_FUNCTION (this);

  // OnOffApplication clients send the first packet an inter-departure time after the
  // beginning of the first "On" period. Compute the maximum IDT among all the flows
  double maxIdt = 0.;  // seconds
  for (auto& flow : m_flows)
    {
      maxIdt = std::max (maxIdt, (flow.m_payloadSize * 8 / flow.m_dataRate));
    }
  if (m_nStationsPerObss > 0 && m_obssDlAggregateRate > 0)
    {
      maxIdt = std::max (maxIdt, (m_obssDlPayload * 8 / (m_obssDlAggregateRate * 1e6 / m_nStationsPerObss)));
    }
  if (m_nStationsPerObss > 0 && m_obssUlAggregateRate > 0)
    {
      maxIdt = std::max (maxIdt, (m_obssUlPayload * 8 / (m_obssUlAggregateRate * 1e6 / m_nStationsPerObss)));
    }

  // for each client application 'c', the last "Off" period lasts maxIdt + startDelay(c) - IDT(c)
  // so that every client application transmits the first packet after maxIdt + startDelay(c)
  Ptr<UniformRandomVariable> startDelayRV;
  startDelayRV = CreateObjectWithAttributes<UniformRandomVariable> ("Min", DoubleValue (0.0),
                                                                    "Max", DoubleValue (m_startInterval));
  UintegerValue pktSize;
  DataRateValue cbrRate;
  bool found;
  double offTime;

  for (auto& clientApp : m_clientApps)
    {
      found = clientApp->GetAttributeFailSafe ("PacketSize", pktSize);
      NS_ABORT_IF (!found);
      found = clientApp->GetAttributeFailSafe ("DataRate", cbrRate);
      NS_ABORT_IF (!found);
      offTime = maxIdt + (startDelayRV->GetValue () / 1000.)
                - (pktSize.Get () * 8. / cbrRate.Get ().GetBitRate ()) + 50e-9;
      // we add 50 nanoseconds to offTime to prevent it from being zero, which
      // happens if m_startInterval is zero and all the flows have the same IDT.
      // In such a case, at the next slot boundary both the "On" and the "Off"
      // periods would be zero and this would cause an infinite loop
      NS_ASSERT (offTime > 0);

      std::stringstream ss;
      ss << "ns3::ConstantRandomVariable[Constant=" << std::fixed << std::setprecision (10) << offTime << "]";
      clientApp->SetAttribute ("OffTime", StringValue (ss.str ()));
    }

  for (auto& obssClientApp : m_obssClientApps)
    {
      for (auto appIt = obssClientApp.Begin (); appIt != obssClientApp.End (); appIt++)
        {
          found = (*appIt)->GetAttributeFailSafe ("PacketSize", pktSize);
          NS_ABORT_IF (!found);
          found = (*appIt)->GetAttributeFailSafe ("DataRate", cbrRate);
          NS_ABORT_IF (!found);
          offTime = maxIdt + (startDelayRV->GetValue () / 1000.)
                    - (pktSize.Get () * 8. / cbrRate.Get ().GetBitRate ()) + 50e-9;
          NS_ASSERT (offTime > 0);

          std::stringstream ss;
          ss << "ns3::ConstantRandomVariable[Constant=" << std::fixed << std::setprecision (10) << offTime << "]";
          (*appIt)->SetAttribute ("OffTime", StringValue (ss.str ()));
        }
    }

  // StartTraffic sets the "Off" time to zero and the "On" time to the simulation
  // duration. Therefore, it must be called after the next slot boundary (when
  // the last "Off" period must be scheduled) and before the last "Off" period
  // expires. The next slot boundary is in one millisecond and the minimum
  // duration of the last "Off" period is 50 nanoseconds.
  Simulator::Schedule (MilliSeconds (1) + NanoSeconds (30), &WifiOfdmaExample::StartTraffic, this);
}

void
WifiOfdmaExample::StartTraffic (void)
{
  NS_LOG_FUNCTION (this);

  std::string onTime = std::to_string (m_warmup + m_simulationTime);

  for (auto& clientApp : m_clientApps)
    {
      clientApp->SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant="
                                                      + onTime + "]"));
      clientApp->SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
    }

  for (auto& obssClientApp : m_obssClientApps)
    {
      for (auto appIt = obssClientApp.Begin (); appIt != obssClientApp.End (); appIt++)
        {
          (*appIt)->SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant="
                                                         + onTime + "]"));
          (*appIt)->SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
        }
    }

  Simulator::Schedule (Seconds (m_warmup), &WifiOfdmaExample::StartStatistics, this);
}

void
WifiOfdmaExample::StartStatistics (void)
{
  NS_LOG_FUNCTION (this);

  /* Connect traces on all the stations (including the AP) and for all the ACs */
  NetDeviceContainer devices = m_staDevices;
  devices.Add (m_apDevices.Get (0));

  for (auto devIt = devices.Begin (); devIt != devices.End (); devIt++)
    {
      Ptr<WifiNetDevice> dev = DynamicCast<WifiNetDevice> (*devIt);
      Ptr<QosTxop> qosTxop;

      for (auto& ac : m_aciToString)
        {
          // get the EDCA on the station for the given AC
          PointerValue ptr;
          dev->GetMac ()->GetAttribute (std::string (ac.second + "_Txop"), ptr);
          qosTxop = ptr.Get<QosTxop> ();
          // trace expired MSDUs
          qosTxop->GetWifiMacQueue ()->TraceConnectWithoutContext ("Expired",
            MakeCallback (&WifiOfdmaExample::NotifyMsduExpired, this));
          // trace rejected MSDUs
          qosTxop->GetWifiMacQueue ()->TraceConnectWithoutContext ("DropBeforeEnqueue",
            MakeCallback (&WifiOfdmaExample::NotifyMsduRejected, this));
          // trace packets enqueued in the EDCA queue
          qosTxop->GetWifiMacQueue ()->TraceConnectWithoutContext ("Enqueue",
            MakeCallback (&WifiOfdmaExample::NotifyEdcaEnqueue, this));
          // trace MSDUs dequeued from the EDCA queue
          qosTxop->GetWifiMacQueue ()->TraceConnectWithoutContext ("Dequeue", 
            MakeCallback (&WifiOfdmaExample::NotifyMsduDequeuedFromEdcaQueue, this)
            .Bind (qosTxop->GetWifiMacQueue ()->GetMaxDelay ()));
          // trace TXOP duration
          qosTxop->TraceConnectWithoutContext ("TxopTrace",
            MakeCallback (&WifiOfdmaExample::NotifyTxopDuration, this)
            .Bind (MacAddressToNodeId (Mac48Address::ConvertFrom (dev->GetAddress ())), ac.first));
        }

      // trace TX failures
      dev->GetMac ()->TraceConnectWithoutContext ("NAckedMpdu", MakeCallback (&WifiOfdmaExample::NotifyTxFailed, this));
      // trace PSDUs forwarded down to the PHY
      dev->GetPhy ()->TraceConnectWithoutContext ("PhyTxPsduBegin", MakeCallback (&WifiOfdmaExample::NotifyPsduForwardedDown, this));
      // trace packets forwarded up by the MAC layer
      dev->GetMac ()->TraceConnectWithoutContext ("MacRx", MakeCallback (&WifiOfdmaExample::NotifyMacForwardUp, this));
    }

  for (std::size_t i = 0; i < m_flows.size (); i++)
    {
      Ptr<OnOffApplication> sender = DynamicCast<OnOffApplication> (m_clientApps[i]);
      NS_ABORT_MSG_IF (sender == nullptr, "Not an OnOffApplication?");
      sender->TraceConnectWithoutContext ("Tx", MakeCallback (&WifiOfdmaExample::NotifyAppTx, this)
                                                .Bind (i));
      m_flows[i].m_packetsRejectedBySocket = sender->GetTotalPacketsFailed ();

      Ptr<PacketSink> sink = DynamicCast<PacketSink> (m_sinkApps.Get (i));
      NS_ABORT_MSG_IF (sink == nullptr, "Not a PacketSink?");
      sink->TraceConnectWithoutContext ("Rx", MakeCallback (&WifiOfdmaExample::NotifyAppRx, this)
                                              .Bind (i));
      m_flows[i].m_prevRxBytes = sink->GetTotalRx ();
    }

  for (std::size_t i = 0; i <= m_nStations; i++)
    {
      Ptr<Node> node = (i == 0 ? m_apNodes.Get (0) : m_staNodes.Get (i - 1));
      Ptr<NetDevice> device = (i == 0 ? m_apDevices.Get (0) : m_staDevices.Get (i - 1));
      Ptr<TrafficControlLayer> tc = node->GetObject<TrafficControlLayer> ();
      NS_ABORT_MSG_IF (tc == nullptr, "No TrafficControlLayer object aggregated to node");

      Ptr<QueueDisc> qdisc = tc->GetRootQueueDiscOnDevice (device);
      if (qdisc != nullptr && qdisc->GetNQueueDiscClasses () == 4)
        {
          Ptr<QueueDisc> child;
          for (auto& acStats : m_perAcStats.at (i))
            {
              child = qdisc->GetQueueDiscClass (static_cast<std::size_t> (acStats.first))->GetQueueDisc ();
              acStats.second.droppedByQueueDisc = child->GetStats ().nTotalDroppedPackets;
              child->TraceConnectWithoutContext ("SojournTime",
                                                 MakeCallback (&WifiOfdmaExample::NotifySojournTime, this)
                                                 .Bind (i, acStats.first));
              child->TraceConnectWithoutContext ("DropAfterDequeue",
                                                 MakeCallback (&WifiOfdmaExample::NotifyDropAfterDequeue, this)
                                                 .Bind (i, acStats.first));
            }
        }
    }

  if (m_obssDlAggregateRate > 0)
    {
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          for (std::size_t i = 0; i < m_nStationsPerObss; i++)
            {
              m_obssDlRxStart.at (bss) += DynamicCast<PacketSink> (m_obssSinkApps.at (bss).Get (i))->GetTotalRx ();
            }
        }
    }

  if (m_obssUlAggregateRate > 0)
    {
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          uint32_t last = m_obssSinkApps.at (bss).GetN () - 1;
          m_obssUlRxStart.at (bss) = DynamicCast<PacketSink> (m_obssSinkApps.at (bss).Get (last))->GetTotalRx ();
        }
    }

  Simulator::Schedule (Seconds (m_simulationTime / m_nIntervals), &WifiOfdmaExample::StoreCumulativeRxBytes, this);
  Simulator::Schedule (Seconds (m_simulationTime), &WifiOfdmaExample::StopStatistics, this);
}

void
WifiOfdmaExample::StoreCumulativeRxBytes (void)
{
#if 0
  Ptr<WifiMacQueue> queue = DynamicCast<RegularWifiMac> (DynamicCast<WifiNetDevice> (m_apDevices.Get (0))->GetMac ())->GetQosTxop (AC_BE)->GetWifiMacQueue ();
  for (auto it = queue->QueuedPacketsBegin (); it != queue->QueuedPacketsEnd (); it++)
    {
      std::cout << "STA " << it->first.first << " : " << it->second << " MSDUs" << std::endl;
    }
#endif
  std::map<AcIndex, double> dlTput, ulTput;
  std::map<AcIndex, double>::iterator mapIt;

  for (std::size_t i = 0; i < m_flows.size (); i++)
    {
      Ptr<PacketSink> sink = DynamicCast<PacketSink> (m_sinkApps.Get (i));
      NS_ABORT_MSG_IF (sink == nullptr, "Not a PacketSink?");

      if (m_flows[i].m_direction == Flow::DOWNLINK)
        {
          mapIt = dlTput.insert ({m_flows[i].m_ac, 0.0}).first;
        }
      else
        {
          mapIt = ulTput.insert ({m_flows[i].m_ac, 0.0}).first;
        }
      mapIt->second += (sink->GetTotalRx () - m_flows[i].m_prevRxBytes) * 8. / (m_simulationTime / m_nIntervals * 1e6);
      m_flows[i].m_prevRxBytes = sink->GetTotalRx ();
    }

  std::cout << "Per-AC throughput in the last time interval (time: " << Simulator::Now () << ")"
            << std::endl << "DOWNLINK" << std::endl;
  for (auto& acMap : dlTput)
    {
      std::cout << "[" << m_aciToString.at (acMap.first) << "] " << acMap.second << std::endl;
    }
  std::cout << "UPLINK" << std::endl;
  for (auto& acMap : ulTput)
    {
      std::cout << "[" << m_aciToString.at (acMap.first) << "] " << acMap.second << std::endl;
    }
  std::cout << std::endl;

  if (++m_elapsedIntervals < m_nIntervals)
    {
      Simulator::Schedule (Seconds (m_simulationTime / m_nIntervals),
                           &WifiOfdmaExample::StoreCumulativeRxBytes, this);
    }
}

void
WifiOfdmaExample::StopStatistics (void)
{
  NS_LOG_FUNCTION (this);

  /* Disconnect traces on all the stations (including the AP) and for all the ACs */
  NetDeviceContainer devices = m_staDevices;
  devices.Add (m_apDevices.Get (0));

  for (auto devIt = devices.Begin (); devIt != devices.End (); devIt++)
    {
      Ptr<WifiNetDevice> dev = DynamicCast<WifiNetDevice> (*devIt);
      Ptr<QosTxop> qosTxop;

      for (auto& ac : m_aciToString)
        {
          // get the EDCA on the station for the given AC
          PointerValue ptr;
          dev->GetMac ()->GetAttribute (std::string (ac.second + "_Txop"), ptr);
          qosTxop = ptr.Get<QosTxop> ();
          // stop tracing expired MSDUs
          qosTxop->GetWifiMacQueue ()->TraceDisconnectWithoutContext ("Expired",
            MakeCallback (&WifiOfdmaExample::NotifyMsduExpired, this));
          // stop tracing rejected MSDUs
          qosTxop->GetWifiMacQueue ()->TraceDisconnectWithoutContext ("DropBeforeEnqueue",
            MakeCallback (&WifiOfdmaExample::NotifyMsduRejected, this));
          // stop tracing packets enqueued in the EDCA queue
          qosTxop->GetWifiMacQueue ()->TraceDisconnectWithoutContext ("Enqueue",
            MakeCallback (&WifiOfdmaExample::NotifyEdcaEnqueue, this));
          // stop tracing MSDUs dequeued from the EDCA queue
          qosTxop->GetWifiMacQueue ()->TraceDisconnectWithoutContext ("Dequeue", 
            MakeCallback (&WifiOfdmaExample::NotifyMsduDequeuedFromEdcaQueue, this)
            .Bind (qosTxop->GetWifiMacQueue ()->GetMaxDelay ()));
          // stop tracing TXOP duration
          qosTxop->TraceDisconnectWithoutContext ("TxopTrace",
            MakeCallback (&WifiOfdmaExample::NotifyTxopDuration, this)
            .Bind (MacAddressToNodeId (Mac48Address::ConvertFrom (dev->GetAddress ())), ac.first));
        }

      // stop tracing TX failures
      dev->GetMac ()->TraceDisconnectWithoutContext ("NAckedMpdu", MakeCallback (&WifiOfdmaExample::NotifyTxFailed, this));
      // stop tracing PSDUs forwarded down to the PHY
      dev->GetPhy ()->TraceDisconnectWithoutContext ("PhyTxPsduBegin", MakeCallback (&WifiOfdmaExample::NotifyPsduForwardedDown, this));
      // stop tracing packets forwarded up by the MAC layer
      dev->GetMac ()->TraceDisconnectWithoutContext ("MacRx", MakeCallback (&WifiOfdmaExample::NotifyMacForwardUp, this));
    }

  for (std::size_t i = 0; i < m_flows.size (); i++)
    {
      Ptr<OnOffApplication> sender = DynamicCast<OnOffApplication> (m_clientApps[i]);
      NS_ABORT_MSG_IF (sender == nullptr, "Not an OnOffApplication?");
      sender->TraceDisconnectWithoutContext ("Tx", MakeCallback (&WifiOfdmaExample::NotifyAppTx, this)
                                                   .Bind (i));
      m_flows[i].m_packetsRejectedBySocket = sender->GetTotalPacketsFailed ()
                                             - m_flows[i].m_packetsRejectedBySocket;

      Ptr<PacketSink> sink = DynamicCast<PacketSink> (m_sinkApps.Get (i));
      NS_ABORT_MSG_IF (sink == nullptr, "Not a PacketSink?");
      sink->TraceDisconnectWithoutContext ("Rx", MakeCallback (&WifiOfdmaExample::NotifyAppRx, this)
                                                 .Bind (i));
    }

  for (std::size_t i = 0; i <= m_nStations; i++)
    {
      Ptr<Node> node = (i == 0 ? m_apNodes.Get (0) : m_staNodes.Get (i - 1));
      Ptr<NetDevice> device = (i == 0 ? m_apDevices.Get (0) : m_staDevices.Get (i - 1));
      Ptr<TrafficControlLayer> tc = node->GetObject<TrafficControlLayer> ();
      NS_ABORT_MSG_IF (tc == nullptr, "No TrafficControlLayer object aggregated to node");

      Ptr<QueueDisc> qdisc = tc->GetRootQueueDiscOnDevice (device);
      if (qdisc != nullptr && qdisc->GetNQueueDiscClasses () == 4)
        {
          Ptr<QueueDisc> child;
          for (auto& acStats : m_perAcStats.at (i))
            {
              child = qdisc->GetQueueDiscClass (static_cast<std::size_t> (acStats.first))->GetQueueDisc ();
              acStats.second.droppedByQueueDisc = child->GetStats ().nTotalDroppedPackets
                                                  - acStats.second.droppedByQueueDisc;
            }
        }
    }

  if (m_obssDlAggregateRate > 0)
    {
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          for (std::size_t i = 0; i < m_nStationsPerObss; i++)
            {
              m_obssDlRxStop.at (bss) += DynamicCast<PacketSink> (m_obssSinkApps.at (bss).Get (i))->GetTotalRx ();
            }
        }
    } 

  if (m_obssUlAggregateRate > 0)
    {
      for (uint16_t bss = 0; bss < m_nObss; bss++)
        {
          uint32_t last = m_obssSinkApps.at (bss).GetN () - 1;
          m_obssUlRxStop.at (bss) = DynamicCast<PacketSink> (m_obssSinkApps.at (bss).Get (last))->GetTotalRx ();
        }
    }

  // (Brutally) stop client applications
  for (auto& clientApp : m_clientApps)
    {
      clientApp->Dispose ();
    }
  for (auto& obssClientApps : m_obssClientApps)
    {
      for (auto appIt = obssClientApps.Begin (); appIt != obssClientApps.End (); appIt++)
        {
          (*appIt)->Dispose ();
        }
    }

  // we are done
  Simulator::Stop ();
}

uint32_t
WifiOfdmaExample::MacAddressToNodeId (Mac48Address address)
{
  if (m_apDevices.Get (0)->GetAddress () == address)
    {
      return m_apNodes.Get (0)->GetId ();
    }

  auto it = m_staMacAddressToNodeId.find (address);
  if (it != m_staMacAddressToNodeId.end ())
    {
      return it->second;
    }

  NS_ABORT_MSG ("Found no node having MAC address " << address);
}

std::pair<std::map<AcIndex, WifiOfdmaExample::PairwisePerAcStats>::iterator, bool>
WifiOfdmaExample::GetPairwisePerAcStats (const WifiMacHeader& hdr, AcIndex ac)
{
  std::map<AcIndex, PairwisePerAcStats>::iterator mapIt;

  if (hdr.IsQosData () && !hdr.GetAddr1 ().IsGroup ())
    {
      ac = QosUtilsMapTidToAc (hdr.GetQosTid ());
    }
  else if (!hdr.IsBlockAckReq () || ac == AC_UNDEF)
    {
      // we need to count BARs transmnitted in HE TB PPDUs
      return std::make_pair (mapIt, false);
    }

  uint32_t srcNodeId = MacAddressToNodeId (hdr.GetAddr2 ());
  uint32_t dstNodeId = MacAddressToNodeId (hdr.GetAddr1 ());
  std::vector<std::map<AcIndex, PairwisePerAcStats>>::iterator vecIt;

  if (srcNodeId == 0)
    {
      // downlink
      vecIt = std::next (m_dlPerStaAcStats.begin (), dstNodeId - 1);
    }
  else
    {
      // uplink
      vecIt = std::next (m_ulPerStaAcStats.begin (), srcNodeId - 1);
    }

  mapIt = vecIt->find (ac);

  return std::make_pair (mapIt, mapIt != vecIt->end ());
}

void
WifiOfdmaExample::NotifyTxFailed (Ptr<const WifiMpdu> mpdu)
{
  if (mpdu->GetHeader ().GetAddr1 ().IsGroup ())
    {
      return;
    }

  auto itPair = GetPairwisePerAcStats (mpdu->GetHeader ());

  if (itPair.second)
    {
      itPair.first->second.failed++;
    }
}

void
WifiOfdmaExample::NotifyMsduExpired (Ptr<const WifiMpdu> item)
{
  if (item->GetHeader ().GetAddr1 ().IsGroup ())
    {
      return;
    }

  auto itPair = GetPairwisePerAcStats (item->GetHeader ());

  if (itPair.second)
    {
      itPair.first->second.expired++;
    }
}

void
WifiOfdmaExample::NotifyMsduRejected (Ptr<const WifiMpdu> item)
{
  if (item->GetHeader ().GetAddr1 ().IsGroup ())
    {
      return;
    }

  auto itPair = GetPairwisePerAcStats (item->GetHeader ());

  if (itPair.second)
    {
      itPair.first->second.rejected++;
    }
}

void
WifiOfdmaExample::NotifyMsduDequeuedFromEdcaQueue (Time maxDelay, Ptr<const WifiMpdu> item)
{
  if (!item->GetHeader ().IsQosData () || item->GetHeader ().GetAddr1 ().IsGroup ()
      || Simulator::Now () > item->GetTimestamp () + maxDelay)
    {
      // the frame is not a unicast QoS data frame or the MSDU lifetime is higher than the
      // max queue delay, hence the MSDU has been discarded. Do nothing in this case.
      return;
    }

  uint32_t srcNodeId = MacAddressToNodeId (item->GetHeader ().GetAddr2 ());

  // update the pairwise HoL delay if this packet is being sent by the AP
  if (srcNodeId == 0)
    {
      auto itPair = GetPairwisePerAcStats (item->GetHeader ());
      
      if (itPair.second)
        {
          // a new HoL sample is stored if this is not the first MSDU being dequeued
          // and if this MSDU is not dequeued to be aggregated to a previously dequeued
          // MSDU (which would give a null sample)
          if (itPair.first->second.lastTxTime.IsStrictlyPositive ()
              && Simulator::Now () > itPair.first->second.lastTxTime)
            {
              double newHolSample = (Simulator::Now () - Max (itPair.first->second.lastTxTime,
                                                              item->GetTimestamp ())).ToDouble (Time::MS);
              itPair.first->second.pairwiseHol.AddSample (newHolSample);
            }
          itPair.first->second.lastTxTime = Simulator::Now ();
        }
    }

  // update the aggregate HoL delay
  auto mapIt = m_perAcStats.at (srcNodeId).find (QosUtilsMapTidToAc (item->GetHeader ().GetQosTid ()));

  if (mapIt == m_perAcStats.at (srcNodeId).end ())
    {
      return;
    }

  // a new HoL sample is stored if this is not the first MSDU being dequeued
  // and if this MSDU is not dequeued to be aggregated to a previously dequeued
  // MSDU (which would give a null sample)
  if (mapIt->second.lastTxTime.IsStrictlyPositive ()
      && Simulator::Now () > mapIt->second.lastTxTime)
    {
      double newHolSample = (Simulator::Now () - Max (mapIt->second.lastTxTime,
                                                      item->GetTimestamp ())).ToDouble (Time::MS);

      mapIt->second.aggregateHoL.AddSample (newHolSample);
    }
  mapIt->second.lastTxTime = Simulator::Now ();
}

void
WifiOfdmaExample::NotifyPsduForwardedDown (WifiConstPsduMap psduMap, WifiTxVector txVector, double txPowerW)
{
  Ptr<WifiNetDevice> dev = DynamicCast<WifiNetDevice> (m_apDevices.Get (0));
  Mac48Address apAddress = dev->GetMac ()->GetAddress ();

  if (psduMap.size () == 1 && psduMap.begin ()->second->GetAddr1 () == apAddress)
    {
      // Uplink frame
      const WifiMacHeader& hdr = psduMap.begin ()->second->GetHeader (0);

      if (txVector.GetPreambleType () == WIFI_PREAMBLE_HE_TB)
        {
          // HE TB PPDU
          if (hdr.HasData () || hdr.IsBlockAckReq ())
            {
              Time txDuration = WifiPhy::CalculateTxDuration (psduMap.begin ()->second->GetSize (),
                                                              txVector, m_band,
                                                              psduMap.begin ()->first);
              m_durationOfResponsesToLastBasicTf += txDuration;
              double currRatio = txDuration.GetSeconds () / m_tfUlLength.GetSeconds ();

              AcIndex ac = AC_UNDEF;
              if (hdr.IsBlockAckReq ())
                {
                  CtrlBAckRequestHeader baReqHdr;
                  psduMap.begin ()->second->GetPayload (0)->PeekHeader (baReqHdr);
                  ac = QosUtilsMapTidToAc (baReqHdr.GetTidInfo ());
                }

              auto itPair = GetPairwisePerAcStats (hdr, ac);
              if (itPair.second)
                {
                  itPair.first->second.ampduRatio.AddSample (currRatio);
                }
            }
          else if (hdr.GetType () == WIFI_MAC_QOSDATA_NULL)
            {
              m_countOfNullResponsesToLastTf++;
            }
        }

      if (hdr.HasData ())
        {
          auto itPair = GetPairwisePerAcStats (hdr);
          if (itPair.second)
            {
              itPair.first->second.ampduSize.AddSample (psduMap.begin ()->second->GetSize ());
            }
        }
    }
  // Downlink frame
  else if (psduMap.begin ()->second->GetHeader (0).IsQosData ())
    {
      for (auto& psdu : psduMap)
        {
          auto itPair = GetPairwisePerAcStats (psdu.second->GetHeader (0));
          if (itPair.second)
            {
              itPair.first->second.ampduSize.AddSample (psdu.second->GetSize ());
            }
        }

      Time dlMuPpduDuration = WifiPhy::CalculateTxDuration (psduMap, txVector, m_band);
      m_dlMuPpduDuration.AddSample (dlMuPpduDuration.ToDouble (Time::MS));

      // DL MU PPDU
      if (txVector.GetPreambleType () == WIFI_PREAMBLE_HE_MU)
        {
          Time dlMuPpduDuration = WifiPhy::CalculateTxDuration (psduMap, txVector, m_band);
          m_dlMuPpduDuration.AddSample (dlMuPpduDuration.ToDouble (Time::MS));
          Time psduDurationSum = Seconds (0);

          for (auto& staIdPsdu : psduMap)
            {
              double currRatio = 0.0;

              if (staIdPsdu.second->GetSize () > 0)
                {
                  Time txDuration = WifiPhy::CalculateTxDuration (staIdPsdu.second->GetSize (),
                                                                  txVector, m_band,
                                                                  staIdPsdu.first);
                  psduDurationSum += txDuration;
                  currRatio = txDuration.GetSeconds () / dlMuPpduDuration.GetSeconds ();
                }

              auto itPair = GetPairwisePerAcStats (staIdPsdu.second->GetHeader (0));
              if (itPair.second)
                {
                  itPair.first->second.ampduRatio.AddSample (currRatio);
                }
            }
          m_dlMuCompleteness.AddSample (psduDurationSum.GetSeconds ()
                                        / (dlMuPpduDuration.GetSeconds () * psduMap.size ()));
        }
    }
  else if (psduMap.size () == 1 && psduMap.begin ()->second->GetHeader (0).IsTrigger ())
    {
      CtrlTriggerHeader trigger;
      psduMap.begin ()->second->GetPayload (0)->PeekHeader (trigger);

      if (m_tfUlLength.IsStrictlyPositive ())
        {
          // This is not the first Trigger Frame being sent
          if (m_lastTfType == ns3::TriggerFrameType::BASIC_TRIGGER)
            {
              if (m_durationOfResponsesToLastBasicTf.IsZero ())
                {
                  // no station responded to the previous TF
                  m_nFailedBasicTriggerFrames++;
                }
              else
                {
                  double currRatio = m_durationOfResponsesToLastBasicTf.GetSeconds ()
                                    / m_overallTimeGrantedByTf.GetSeconds ();
                  m_heTbCompleteness.AddSample (currRatio);
                }
            }
          else if (m_lastTfType == ns3::TriggerFrameType::BSRP_TRIGGER)
            {
              if (m_countOfNullResponsesToLastTf == 0)
                {
                  // no station responded to the previous TF
                  m_nFailedBsrpTriggerFrames++;
                }
            }
        }

      // reset counters
      m_countOfNullResponsesToLastTf = 0;
      m_durationOfResponsesToLastBasicTf = Seconds (0);

      WifiTxVector heTbTxVector = trigger.GetHeTbTxVector (trigger.begin ()->GetAid12 ());
      m_tfUlLength = HePhy::ConvertLSigLengthToHeTbPpduDuration (trigger.GetUlLength (), heTbTxVector, m_band);
      m_overallTimeGrantedByTf = m_tfUlLength * trigger.GetNUserInfoFields ();

      if (trigger.IsBasic ())
        {
          m_lastTfType = ns3::TriggerFrameType::BASIC_TRIGGER;
          m_nBasicTriggerFramesSent++;
          m_heTbPpduDuration.AddSample (m_tfUlLength.ToDouble (Time::MS));

          dev = DynamicCast<WifiNetDevice> (m_apDevices.Get (0));
          Ptr<ApWifiMac> mac = DynamicCast<ApWifiMac> (dev->GetMac ());

          for (auto& userInfo : trigger)
            {
              Mac48Address address = mac->GetStaList (0).at (userInfo.GetAid12 ());
              std::size_t index = MacAddressToNodeId (address) - 1;
              NS_ASSERT (index < m_nSolicitingBasicTriggerFrames.size ());
              m_nSolicitingBasicTriggerFrames[index]++;
            }
        }
      else if (trigger.IsBsrp ())
        {
          m_lastTfType = ns3::TriggerFrameType::BSRP_TRIGGER;
          m_nBsrpTriggerFramesSent++;
        }
    }
}

void
WifiOfdmaExample::NotifyTxopDuration (uint32_t nodeId, AcIndex ac, Time startTime, Time duration, uint8_t linkId)
{
  //currently, linkId is not used
  auto mapIt = m_perAcStats.at (nodeId).find (ac);

  if (mapIt != m_perAcStats.at (nodeId).end ())
    {
      mapIt->second.txopDuration.AddSample (duration.ToDouble (Time::MS));
    }
}

void
WifiOfdmaExample::NotifySojournTime (std::size_t nodeId, AcIndex ac, Time sojournTime)
{
  auto mapIt = m_perAcStats.at (nodeId).find (ac);

  if (mapIt != m_perAcStats.at (nodeId).end ())
    {
      mapIt->second.queueDiscSojournTime.AddSample (sojournTime.ToDouble (Time::MS));
    }
}

void
WifiOfdmaExample::NotifyDropAfterDequeue (std::size_t nodeId, AcIndex ac, Ptr<const QueueDiscItem> item,
                                          const char* reason)
{
  auto mapIt = m_perAcStats.at (nodeId).find (ac);

  if (mapIt != m_perAcStats.at (nodeId).end ())
    {
      double sample = (Simulator::Now () - item->GetTimeStamp ()).ToDouble (Time::MS);
      mapIt->second.queueDiscSojournTime.RemoveSample (sample);
    }
}

void
WifiOfdmaExample::NotifyAppTx (std::size_t i, Ptr<const Packet> packet)
{
  m_flows[i].m_txBytes += packet->GetSize ();
  m_flows[i].m_txPackets++;
  bool inserted;

  if (m_flows[i].m_l4Proto == Flow::UDP)
    {
      inserted = m_flows[i].m_inFlightPackets.insert ({packet->GetUid (), Simulator::Now ()}).second;
      NS_ABORT_MSG_IF (!inserted, "Duplicate UID " << packet->GetUid () << " with UDP?");
    }
  else
    {
      inserted = m_flows[i].m_inFlightPackets.insert ({m_flows[i].m_txBytes, Simulator::Now ()}).second;
      NS_ABORT_MSG_IF (!inserted, "Duplicate total bytes sent " << m_flows[i].m_txBytes << " with TCP?");
    }
}

void
WifiOfdmaExample::NotifyAppRx (std::size_t i, Ptr<const Packet> packet, const Address &address)
{
  m_flows[i].m_rxBytes += packet->GetSize ();
  m_flows[i].m_rxPackets++;

  if (m_flows[i].m_l4Proto == Flow::UDP)
    {
      // there must be a unique packet with the same UID as the received packet
      auto it = m_flows[i].m_inFlightPackets.find (packet->GetUid ());
      if (it == m_flows[i].m_inFlightPackets.end ())
        {
          NS_LOG_WARN ("Packet with UID " << packet->GetUid () << " not found");
          return;
        }

      m_flows[i].m_latency.AddSample ((Simulator::Now () - it->second).ToDouble (Time::MS));
      m_flows[i].m_inFlightPackets.erase (it);
    }
  else
    {
      uint64_t totalBytesReceived = DynamicCast<PacketSink> (m_sinkApps.Get (i))->GetTotalRx ();
      for (auto it = m_flows[i].m_inFlightPackets.begin (); it != m_flows[i].m_inFlightPackets.end (); )
        {
          if (it->first <= totalBytesReceived)
            {
              m_flows[i].m_latency.AddSample ((Simulator::Now () - it->second).ToDouble (Time::MS));
              it = m_flows[i].m_inFlightPackets.erase (it);
            }
          else
            {
              it++;
            }
        }
    }
}

void
WifiOfdmaExample::NotifyEdcaEnqueue (Ptr<const WifiMpdu> item)
{
  if (!item->GetHeader ().IsQosData ())
    {
      return;
    }
  // init a map entry if the packet's UID is not present
  auto mapIt = m_inFlightPacketMap.insert ({item->GetPacket ()->GetUid (),
                                            std::list<InFlightPacketInfo> ()}).first;

  InFlightPacketInfo info;
  info.m_srcAddress = item->GetHeader ().GetAddr2 ();
  info.m_dstAddress = item->GetHeader ().GetAddr1 ();
  info.m_ac = QosUtilsMapTidToAc (item->GetHeader ().GetQosTid ());
  info.m_ptrToPacket = item->GetPacket ();
  info.m_edcaEnqueueTime = Simulator::Now ();

  mapIt->second.insert (mapIt->second.end (), info);
}

void
WifiOfdmaExample::NotifyMacForwardUp (Ptr<const Packet> p)
{
  auto mapIt = m_inFlightPacketMap.find (p->GetUid ());
  if (mapIt == m_inFlightPacketMap.end ())
    {
      NS_LOG_WARN ("No packet with UID " << p->GetUid () << " is currently in flight");
      return;
    }

  auto listIt = std::find_if (mapIt->second.begin (), mapIt->second.end (),
                              [&p](const InFlightPacketInfo& info)
                                { return info.m_ptrToPacket == p; });

  if (listIt == mapIt->second.end ())
    {
      NS_LOG_WARN ("Forwarding up a packet that has not been enqueued?");
      return;
    }

  if (listIt->m_dstAddress.IsGroup ())
    {
      return;
    }

  std::vector<std::map<AcIndex, PairwisePerAcStats>>::iterator vecIt;

  if (MacAddressToNodeId (listIt->m_srcAddress) == 0)
    {
      // downlink
      vecIt = std::next (m_dlPerStaAcStats.begin (), MacAddressToNodeId (listIt->m_dstAddress) - 1);
    }
  else
    {
      // uplink
      vecIt = std::next (m_ulPerStaAcStats.begin (), MacAddressToNodeId (listIt->m_srcAddress) - 1);
    }

  NS_ABORT_MSG_IF (vecIt->find (listIt->m_ac) == vecIt->end (), "AC " << listIt->m_ac << " not found");

  NS_ABORT_MSG_IF (listIt->m_edcaEnqueueTime.IsZero (), "Unknown EDCA enqueue time for the packet");

  vecIt->at (listIt->m_ac).l2Latency.AddSample ((Simulator::Now () - listIt->m_edcaEnqueueTime)
                                                .ToDouble (Time::MS));
  mapIt->second.erase (listIt);
}

uint32_t
WifiOfdmaExample::ContextToNodeId (const std::string & context)
{
  std::string sub = context.substr (10);
  uint32_t pos = sub.find ("/Device");
  uint32_t nodeId = atoi (sub.substr (0, pos).c_str ());
  return nodeId;
}

int main (int argc, char *argv[])
{
  WifiOfdmaExample example;
  example.m_simulationTime=10;
  example.m_heRate="11"
  example.m_nStations =10;
  
  example.nHes
  example.Config (argc, argv);
  example.Setup ();
  example.Run ();
  example.PrintResults (std::cout);

  Simulator::Destroy ();

  return 0;
}
