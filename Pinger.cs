using System;
using System.Collections.Generic;
using System.Net;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace SCANER
{
    class Pinger
    {
        private int timeout = 2000;
        Stopwatch stopWatch = new Stopwatch();
        public TimeSpan ts;
        public bool Started = false;

        public async void Ping_Async(List<ip_adress> ListIP)
        {
            Started = true;
            var tasks = new List<Task>();
            stopWatch.Start();
            foreach(ip_adress ip in ListIP)
            {
                var task = PingAndUpdateAsync(ip);
                tasks.Add(task);
            }
            await Task.WhenAll(tasks).ContinueWith(t =>
            {
                stopWatch.Stop();
                ts = stopWatch.Elapsed;
                Console.WriteLine("pinge time: {0}", ts);
                Started = false;
            });
        }
        async Task PingAndUpdateAsync(ip_adress ip)
        {
            Ping ping = new Ping();
            var reply = await ping.SendPingAsync(new IPAddress(ip.Adress), timeout);
            ip.Ping_Status = reply.Status;
            ping.Dispose();
        }
    }
}
