using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;

namespace ParseFSFB2pcap {
    class ParsePcap {
        ICaptureDevice device;
        static int packetIndex;


        // Open the file to parse
        // returns true if successful, false otherwise
        public bool openPcap(string capFile) {
            try {
                // Get an offline device
                device = new CaptureFileReaderDevice(capFile);

                // Open the device
                device.Open();
            }
            catch (Exception e) {
                Console.WriteLine("Caught exception when opening file" + e.ToString());
                Console.ReadKey();
                return false;
            }

            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            Console.WriteLine();
            Console.WriteLine ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...", capFile);

            // Start capture 'INFINTE' number of packets
            // This method will return when EOF reached.
            device.Capture();

            // Close the pcap device
            device.Close();
            Console.WriteLine("-- End of file reached.");
            Console.Write("Hit 'Enter' to exit...");
            Console.ReadLine();
            return true;
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e) {
            if (e.Packet.LinkLayerType == PacketDotNet.LinkLayers.Ethernet) {
                var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
                var ethernetPacket = (PacketDotNet.EthernetPacket)packet;

                Console.WriteLine("bit 1 is {0}, bit 2 is {1}", e.Packet.Data[0].ToString("X2"), e.Packet.Data[1].ToString("X2"));
                packetIndex++;
            }
        }
    }
}
