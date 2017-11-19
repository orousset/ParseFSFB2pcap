using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace ParseFSFB2pcap {

    public class bitPair {
        public int rank;
        public int state;
        public void setState(int newState) { state = newState; }
    }

    class FSFB2channel {
        public int subnet;
        public int address;
        public Dictionary<String, bitPair> mappingTX;
        public Dictionary<String, bitPair> mappingRX;
        public List<string> indexTX;
        public List<string> indexRX;

        public FSFB2channel() {
            mappingTX = new Dictionary<string, bitPair>();
            mappingRX = new Dictionary<string, bitPair>();
            indexTX = new List<string>();
            indexRX = new List<string>();
        }
    }

    class SIOParsingParameters {
        bool DEBUG = false;
        static int minPacketSize = 0x5D;
        static int[] bitMask = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
        private string[] lines;

        private FSFB2channel ZCchannel = new FSFB2channel(); // The FSFB2 channel for communication with active ZC
        private FSFB2channel PSD1channel = new FSFB2channel(); // The FSFB2 channel for communication with VOBC/PSD1
        private FSFB2channel PSD2channel = new FSFB2channel(); // The FSFB2 channel for communication with VOBC/PSD2
        private string SIOAddessRed; // IP address of the SIO on Red network
        private string SIOAddessBlue; // IP address of the SIO on Blue network

        public bitPair getRxZCState(string bitName) { return (ZCchannel.mappingRX[bitName]); }
        public bitPair getTxZCState(string bitName) { return (ZCchannel.mappingTX[bitName]); }
        public Dictionary<string, bitPair> getRXZCStates() { return ZCchannel.mappingRX; }
        public Dictionary<string, bitPair> getTXZCStates() { return ZCchannel.mappingTX; }
        public string[] getName(string type) {
            string[] returnName = new string[0]; // TODO : not the best solution, to review
            int nbItem;
            if (type == "TX") {
                nbItem = ZCchannel.mappingTX.Count();
                returnName = new string[nbItem];
                for (int cpt = 0; cpt < nbItem; cpt++) {
                    returnName[cpt] = ZCchannel.indexTX[cpt];
                }
            }
            else if (type == "RX") {
                nbItem = ZCchannel.mappingRX.Count();
                returnName = new string[nbItem];
                for (int cpt = 0; cpt < nbItem; cpt++) {
                    returnName[cpt] = ZCchannel.indexRX[cpt];
                }
            }
            return returnName;
        }

        public void setRedIP(string IPaddress) { SIOAddessRed = IPaddress; }
        public void setBlueIP(string IPaddress) { SIOAddessBlue = IPaddress; }
        public string getRedIP() { return SIOAddessRed; }
        public string getBlueIP() { return SIOAddessBlue; }

        public Boolean initialiseMapping(string SIOname) {
            Boolean returnCode = true;
            string HCFinput = SIOname + ".hcf"; // name of the hcf file (*.hcf)
            string CCFinput = SIOname + ".ccf"; // name of the ccf file (*.ccf)
            const string SCregexp = @"^\[(APP_ZC|BUF_TX_APP_ZC|BUF_RX_APP_ZC|APP_VOBC1|BUF_TX_APP_VOBC1|BUF_RX_APP_VOBC1)(\d)?(A|B)?\]$"; // detection of safe computer conf
            const string ADDRESSregexp = @"^(Address = )(\d+)$";
            const string SUBNETregexp = @"^(Subnet = -)(\d+)$";
            const string TXregexp = @"^(Elements = )?(\w+)(\#?)(,?)$";
            const string RXregexp = @"^(Elements = )?(\w+)(: )(\d+)(\.)(\d+)(,?)$";
            const string REDIP = @"[DDL_IPRED_SPLIT_RED]";
            const string BLUEIP = @"[DDL_IPRED_SPLIT_BLUE]";
            const string IPregexp = @"^(LocalAddress = )(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})";
            Boolean APP_ZC, BUF_TX_ZC, BUF_RX_ZC, APP_VOBC1, BUF_TX_VOBC1, BUF_RX_VOBC1, APP_VOBC2, BUF_TX_VOBC2, BUF_RX_VOBC2;
            Boolean RIP, BIP;
            int rank = 0;

            RIP = BIP = false;
            APP_ZC = BUF_TX_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false;

            try {
                lines = System.IO.File.ReadAllLines(@HCFinput);
            }
            catch (System.IO.IOException exp) {
                Console.WriteLine("Exception encountered: {0}", exp); // Error during the opening of the input file
                returnCode = false;
            } finally {
                if (returnCode) {
                    foreach (string line in lines) {
                        if (Regex.IsMatch(line, SCregexp)) {
                            String[] splitString = Regex.Split(line, SCregexp);
                            string prefix = splitString[1];
                            switch (prefix) {
                                case "APP_ZC":
                                    if (splitString[3] == "B") { APP_ZC = BUF_TX_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false; } else {
                                        APP_ZC = true;
                                        BUF_TX_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false;
                                    }
                                    break;
                                case "BUF_TX_APP_ZC":
                                    if (splitString[3] == "B") { APP_ZC = BUF_TX_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false; } else {
                                        BUF_TX_ZC = true;
                                        APP_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false;
                                    }
                                    break;
                                case "BUF_RX_APP_ZC":
                                    if (splitString[3] == "B") { APP_ZC = BUF_TX_ZC = BUF_RX_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false; } else {
                                        BUF_RX_ZC = true;
                                        BUF_TX_ZC = APP_ZC = APP_VOBC1 = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false;
                                    }
                                    break;
                                case "APP_VOBC1":
                                    APP_VOBC1 = true;
                                    APP_ZC = BUF_TX_ZC = BUF_RX_ZC = BUF_TX_VOBC1 = BUF_RX_VOBC1 = APP_VOBC2 = BUF_TX_VOBC2 = BUF_RX_VOBC2 = false;
                                    break;
                                default:
                                    if (APP_ZC || BUF_TX_ZC || BUF_RX_ZC || APP_VOBC1 || BUF_TX_VOBC1 || BUF_RX_VOBC1 || APP_VOBC2 || BUF_TX_VOBC2 || BUF_RX_VOBC2) {
                                    }
                                    break;
                            }
                        }
                        if (APP_ZC) {
                            if (Regex.IsMatch(line, ADDRESSregexp)) {
                                String[] splitString = Regex.Split(line, ADDRESSregexp);
                                ZCchannel.address = Convert.ToInt32(splitString[2]);
                            }
                            if (Regex.IsMatch(line, SUBNETregexp)) {
                                String[] splitString = Regex.Split(line, SUBNETregexp);
                                ZCchannel.subnet = Convert.ToInt32(splitString[2]);
                            }
                        }
                        if (BUF_TX_ZC) {
                            if (Regex.IsMatch(line, TXregexp)) {
                                String[] splitString = Regex.Split(line, TXregexp);
                                string name;

                                if (splitString[1] == "Elements = ") {
                                    name = splitString[2];
                                    rank = 0;
                                } else { name = splitString[1]; }
                                bitPair bitAdd = new bitPair();
                                bitAdd.rank = rank++;
                                bitAdd.state = 0;
                                ZCchannel.mappingTX.Add(name, bitAdd);
                                ZCchannel.indexTX.Add(name);
                            }
                        }
                        if (BUF_RX_ZC) {
                            if (Regex.IsMatch(line, RXregexp)) {
                                String[] splitString = Regex.Split(line, RXregexp);
                                string name;

                                if (splitString[1] == "Elements = ") {
                                    name = splitString[2];
                                    rank = Convert.ToInt32(splitString[6]);
                                } else {
                                    name = splitString[1];
                                    rank = Convert.ToInt32(splitString[5]);
                                }
                                bitPair bitAdd = new bitPair();
                                bitAdd.rank = rank++;
                                bitAdd.state = 0;
                                ZCchannel.mappingRX.Add(name, bitAdd);
                                ZCchannel.indexRX.Add(name);
                            }
                        }
                    }
                }
            }
            try {
                lines = System.IO.File.ReadAllLines(@CCFinput);
            }
            catch (System.IO.IOException exp) {
                Console.WriteLine("Exception encountered: {0}", exp); // Error during the opening of the input file
                returnCode = false;
            } finally {
                if (returnCode) {
                    foreach (string line in lines) {
                        if (line == REDIP) { RIP = true; BIP = false; }
                        if (line == BLUEIP) { BIP = true; RIP = false; }
                        if (RIP && Regex.IsMatch(line, IPregexp)) {
                            string[] IPaddress = Regex.Split(line, IPregexp);
                            setRedIP(IPaddress[2] + "." + IPaddress[3] + "." + IPaddress[4] + "." + IPaddress[5]);
                            RIP = false;
                        }
                        if (BIP && Regex.IsMatch(line, IPregexp)) {
                            string[] IPaddress = Regex.Split(line, IPregexp);
                            setBlueIP(IPaddress[2] + "." + IPaddress[3] + "." + IPaddress[4] + "." + IPaddress[5]);
                            BIP = false;
                        }
                    }
                }
            }
            return (returnCode);
        }

    }
}
