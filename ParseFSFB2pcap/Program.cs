using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace ParseFSFB2pcap {
    class Program {
        private static SIOParsingParameters myFSFB2;
        private static ParsePcap myParse;

        // Interfacing method - returns false when quit order detected, true otherwise
        static bool InterfaceWithUser() {
            var line = Console.ReadLine(); // line typed by user
            string[] words; // array of word in line
            int cpt = 0; // Record the depth of the word in the line
            bool NoQuitOrder = false;
            bool SyntaxError = false;
            bool Load = false;

            // Split the line in words and run through
            words = line.Split();
            foreach (string word in words) {
                // first word
                if (cpt == 0) {
                    // user requires 'help'
                    if (String.Compare(word, "help", StringComparison.OrdinalIgnoreCase) == 0) {
                        showHelp();
                        NoQuitOrder = true;
                    } else if (String.Compare(word, "quit", StringComparison.OrdinalIgnoreCase) == 0) {
                        NoQuitOrder = false;
                    } else if (String.Compare(word, "showTX", StringComparison.OrdinalIgnoreCase) == 0) {
                        showTX();
                        NoQuitOrder = true;
                    } else if (String.Compare(word, "showRx", StringComparison.OrdinalIgnoreCase) == 0) {
                        showRX();
                        NoQuitOrder = true;
                    } else if (String.Compare(word, "showRawRX", StringComparison.OrdinalIgnoreCase) == 0) {
                        showRawRX();
                        NoQuitOrder = true;
                    } else if (String.Compare(word, "load", StringComparison.OrdinalIgnoreCase) == 0) {
                        Load = true;
                    } else {
                        SyntaxError = true;
                        NoQuitOrder = true;
                    }
                }
                // second word
                if (cpt == 1) {
                    if (Load) {
                        loadFile(word);
                    }
                }
                cpt++;
            }
            if (SyntaxError) { Console.WriteLine("Syntax Error"); }
            return NoQuitOrder;
        }

        private static void loadFile(string pCapName) {
            myParse = new ParsePcap();
            myParse.openPcap(pCapName);
        }

        private static void showRawRX() {
            
        }

        private static void showRX() {
            string[] listRXname = myFSFB2.getName("RX");
            foreach (string name in listRXname) {
                Console.Write("[{0}] ", name);
            }
            Console.WriteLine();
        }

        private static void showTX() {
            string[] listTXname = myFSFB2.getName("TX");
            foreach(string name in listTXname) {
                Console.Write("[{0}] ", name);
            }
            Console.WriteLine();
        }

        private static void showHelp() {
            throw new NotImplementedException();
        }

        static void Main(string[] args) {
            // Variables declaration
            string ver = SharpPcap.Version.VersionString;
            string SIOname;
            bool NotQuit = true;

            // Identification of the SIO to parse and initialisation of the parsing structure
            Console.WriteLine("Please indicate what SIO to parse messages from/to: ");
            SIOname = Console.ReadLine();
            myFSFB2 = new SIOParsingParameters();
            myFSFB2.initialiseMapping(SIOname);

            // Interface with user through text based interface until quit command
            while (NotQuit) {
                NotQuit = InterfaceWithUser();
            }

        }
    }
}
