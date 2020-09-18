using System;
using System.Threading;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;

namespace SCANER
{
    class Program
    {
        private static string strConect = "Persist Security Info=False;Integrated Security=SSPI;Initial Catalog=UMN;server=(local)";

        static void Main(string[] args)
        {
            Pinger AD = new Pinger();
            NetworkIP TTK = new NetworkIP(strConect);
            Console.WriteLine("Всего:"+TTK.ALL_Network.Count);
            AD.Ping_Async(TTK.ALL_Network);
            while (AD.Started) { System.Threading.Thread.Sleep(500); }
            TTK.TimeAllPing = AD.ts;
            AD = null; GC.Collect();
            TTK.PrintPingStatus();
            TTK.ClearIPList();
            Console.ReadLine();
        }

    }
}
