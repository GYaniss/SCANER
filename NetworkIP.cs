using System;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Data;
using System.Data.SqlClient;
using System.Text;

namespace SCANER
{
    class NetworkIP
    {
        public TimeSpan TimeAllPing;
        public List<ip_adress> ALL_Network = new List<ip_adress>();
        string Conn = null;
        public NetworkIP(string ConnectionString)
        {
            Conn = ConnectionString;
            Hashtable IPP = new Hashtable();
            DataTable IP_DataAdd = new DataTable();
            using (SqlConnection Conn = new SqlConnection(ConnectionString))
            {
                Conn.Open();
                string sql = "SELECT Mask, A1, A2, A3, A4, B1, B2,B3,B4,Comm FROM SIS_IPList WHERE Del=0 ORDER BY id";
                SqlDataAdapter D_A = new SqlDataAdapter(sql, Conn);
                D_A.Fill(IP_DataAdd);
                Conn.Close();
            }
           
            foreach (DataRow R in IP_DataAdd.Rows)
            {
                string Comm = R["Comm"].ToString();
                string Mask = R["Mask"].ToString();
                string ip1 = string.Format("{0}.{1}.{2}.{3}", R["A1"], R["A2"], R["A3"], R["A4"]);
                string ip2 = string.Format("{0}.{1}.{2}.{3}", R["B1"], R["B2"], R["B3"], R["B4"]);

                List<ip_adress> IP_list = new List<ip_adress>();
                if (Mask == "") { IP_list = GetIPList(ip1, ip2, Comm); } else { IP_list = GetIPListfromSIDR(ip1 + '/' + Mask, Comm); }
                foreach (ip_adress ip in IP_list)
                {
                    if (!IPP.ContainsKey(ip.Adress))
                    {
                        IPP.Add(ip.Adress, ip.Community);
                    }
                }
            }

            DataTable IP_DataDel = new DataTable();
            using (SqlConnection Conn = new SqlConnection(ConnectionString))
            {
                Conn.Open();
                string sql = "SELECT Mask, A1, A2, A3, A4, B1, B2,B3,B4,Comm FROM SIS_IPList WHERE Del=1 ORDER BY id";
                SqlDataAdapter D_A = new SqlDataAdapter(sql, Conn);
                D_A.Fill(IP_DataDel);
                Conn.Close();
            }
            foreach (DataRow R in IP_DataDel.Rows)
            {
                string Comm = R["Comm"].ToString();
                string Mask = R["Mask"].ToString();
                string ip1 = string.Format("{0}.{1}.{2}.{3}", R["A1"], R["A2"], R["A3"], R["A4"]);
                string ip2 = string.Format("{0}.{1}.{2}.{3}", R["B1"], R["B2"], R["B3"], R["B4"]);

                List<ip_adress> IP_list = new List<ip_adress>();
                if (Mask == "") { IP_list = GetIPList(ip1, ip2, Comm); } else { IP_list = GetIPListfromSIDR(ip1 + '/' + Mask, Comm); }
                foreach (ip_adress ip in IP_list)
                {
                    IPP.Remove(ip.Adress);
                }
            }
            ALL_Network.Clear();
            foreach (DictionaryEntry de in IPP)
            {
                ip_adress ip = new ip_adress((uint)de.Key);
                ip.Community = de.Value.ToString();
                ALL_Network.Add(ip);
            }

        }
        List<ip_adress> GetIPList(string ipFrom, string ipTo, string Comm)
        {
            List<ip_adress> ipList = new List<ip_adress>();
            byte[] firstBytesArray = IPAddress.Parse(ipFrom).GetAddressBytes();
            byte[] lastBytesArray = IPAddress.Parse(ipTo).GetAddressBytes();
            Array.Reverse(firstBytesArray);
            Array.Reverse(lastBytesArray);
            uint first= BitConverter.ToUInt32(firstBytesArray, 0);
            uint last = BitConverter.ToUInt32(lastBytesArray, 0);
            for (var i = first; i <= last; i++)
            {
                byte[] bytes = BitConverter.GetBytes(i);
                ip_adress newIp = new ip_adress(new[] { bytes[3], bytes[2], bytes[1], bytes[0] });
                newIp.Ping_Status = IPStatus.Unknown;
                newIp.Community = Comm;
                ipList.Add(newIp);
            }
            return ipList;
        }
        List<ip_adress> GetIPListfromSIDR(string sNetwork, string Comm)
        {
            var ListIP = new List<ip_adress>();
            string[] parts = sNetwork.Split('.', '/');
            uint ipnum = (Convert.ToUInt32(parts[0]) << 24) | (Convert.ToUInt32(parts[1]) << 16) | (Convert.ToUInt32(parts[2]) << 8) | Convert.ToUInt32(parts[3]);

            int maskbits = Convert.ToInt32(parts[4]);
            uint mask = 0xffffffff;
            mask <<= (32 - maskbits);

            uint startIP = ipnum & mask;
            uint endIP = ipnum | (mask ^ 0xffffffff);
            for (var i = startIP+1; i < endIP; i++)
            {
                byte[] bytes = BitConverter.GetBytes(i);
                ip_adress newIp = new ip_adress(new[] { bytes[3], bytes[2], bytes[1], bytes[0] });
                newIp.Ping_Status = IPStatus.Unknown;
                newIp.Community = Comm;
                ListIP.Add(newIp);
            }
            return ListIP;
        }
        
        public void ClearIPList()
        {
            ALL_Network.RemoveAll(x => x.Ping_Status != IPStatus.Success);
        }
        public void PrintPingStatus()
        {
            int _Success = 0;
            int _TimedOut = 0;
            int BadDestination = 0;
            int BadHeader = 0;
            int BadOption = 0;
            int BadRoute = 0;
            int DestinationHostUnreachable = 0;
            int DestinationNetworkUnreachable = 0;
            int DestinationPortUnreachable = 0;
            int DestinationProtocolUnreachable = 0;
            int DestinationScopeMismatch = 0;
            int DestinationUnreachable = 0;
            int HardwareError = 0;
            int IcmpError = 0;
            int NoResources = 0;
            int PacketTooBig = 0;
            int ParameterProblem = 0;
            int SourceQuench = 0;
            int TimeExceeded = 0;
            int TtlExpired = 0;
            int TtlReassemblyTimeExceeded = 0;
            int Unknown = 0;
            int UnrecognizedNextHeader = 0;

            foreach (ip_adress ip in ALL_Network)
            {
                if (ip.Ping_Status == IPStatus.Success) _Success++;
                if (ip.Ping_Status == IPStatus.TimedOut) _TimedOut++;
                if (ip.Ping_Status == IPStatus.BadDestination) BadDestination++;
                if (ip.Ping_Status == IPStatus.BadHeader) BadHeader++;
                if (ip.Ping_Status == IPStatus.BadOption) BadOption++;
                if (ip.Ping_Status == IPStatus.BadRoute) BadRoute++;
                if (ip.Ping_Status == IPStatus.DestinationHostUnreachable) DestinationHostUnreachable++;
                if (ip.Ping_Status == IPStatus.DestinationNetworkUnreachable) DestinationNetworkUnreachable++;
                if (ip.Ping_Status == IPStatus.DestinationPortUnreachable) DestinationPortUnreachable++;
                if (ip.Ping_Status == IPStatus.DestinationProtocolUnreachable) DestinationProtocolUnreachable++;
                if (ip.Ping_Status == IPStatus.DestinationScopeMismatch) DestinationScopeMismatch++;
                if (ip.Ping_Status == IPStatus.DestinationUnreachable) DestinationUnreachable++;
                if (ip.Ping_Status == IPStatus.HardwareError) HardwareError++;
                if (ip.Ping_Status == IPStatus.IcmpError) IcmpError++;
                if (ip.Ping_Status == IPStatus.NoResources) NoResources++;
                if (ip.Ping_Status == IPStatus.PacketTooBig) PacketTooBig++;
                if (ip.Ping_Status == IPStatus.ParameterProblem) ParameterProblem++;
                if (ip.Ping_Status == IPStatus.SourceQuench) SourceQuench++;
                if (ip.Ping_Status == IPStatus.TimeExceeded) TimeExceeded++;
                if (ip.Ping_Status == IPStatus.TtlExpired) TtlExpired++;
                if (ip.Ping_Status == IPStatus.TtlReassemblyTimeExceeded) TtlReassemblyTimeExceeded++;
                if (ip.Ping_Status == IPStatus.Unknown) Unknown++;
                if (ip.Ping_Status == IPStatus.UnrecognizedNextHeader) UnrecognizedNextHeader++;
            }
            Console.WriteLine("Success:" + _Success);
            Console.WriteLine("TimedOut:" + _TimedOut);
            Console.WriteLine("BadDestination:" + BadDestination);
            Console.WriteLine("BadHeader:" + BadHeader);
            Console.WriteLine("BadOption:" + BadOption);
            Console.WriteLine("BadRoute:" + BadRoute);
            Console.WriteLine("DestinationHostUnreachable:" + DestinationHostUnreachable);
            Console.WriteLine("DestinationNetworkUnreachable:" + DestinationNetworkUnreachable);
            Console.WriteLine("DestinationPortUnreachable:" + DestinationPortUnreachable);
            Console.WriteLine("DestinationProtocolUnreachable:" + DestinationProtocolUnreachable);
            Console.WriteLine("DestinationScopeMismatch:" + DestinationScopeMismatch);
            Console.WriteLine("DestinationUnreachable:" + DestinationUnreachable);
            Console.WriteLine("HardwareError:" + HardwareError);
            Console.WriteLine("IcmpError:" + IcmpError);
            Console.WriteLine("NoResources:" + NoResources);
            Console.WriteLine("PacketTooBig:" + PacketTooBig);
            Console.WriteLine("ParameterProblem:" + ParameterProblem);
            Console.WriteLine("SourceQuench:" + SourceQuench);
            Console.WriteLine("TimeExceeded:" + TimeExceeded);
            Console.WriteLine("TtlExpired:" + TtlExpired);
            Console.WriteLine("TtlReassemblyTimeExceeded:" + TtlReassemblyTimeExceeded);
            Console.WriteLine("Unknown:" + Unknown);
            Console.WriteLine("UnrecognizedNextHeader:" + UnrecognizedNextHeader);
            StringBuilder SB = new StringBuilder();
            StringBuilder SB1 = new StringBuilder();
            SB.AppendLine("Кол-во IP:" + ALL_Network.Count.ToString());
            SB.AppendLine("<br />Дата и Время:" +DateTime.Now.ToString());
            SB.AppendLine("<br />Длительность:" + TimeAllPing);
            SB.AppendLine("<br />Success:" + _Success);
            SB.AppendLine("<br />TimedOut:" + _TimedOut);
            SB.AppendLine("<br />BadDestination:" + BadDestination);
            SB.AppendLine("<br />BadHeader:" + BadHeader);
            SB.AppendLine("<br />BadOption:" + BadOption);
            SB.AppendLine("<br />BadRoute:" + BadRoute);
            SB.AppendLine("<br />DestinationHostUnreachable:" + DestinationHostUnreachable);
            SB.AppendLine("<br />DestinationNetworkUnreachable:" + DestinationNetworkUnreachable);
            SB.AppendLine("<br />DestinationPortUnreachable:" + DestinationPortUnreachable);
            SB.AppendLine("<br />DestinationProtocolUnreachable:" + DestinationProtocolUnreachable);
            SB.AppendLine("<br />DestinationScopeMismatch:" + DestinationScopeMismatch);
            SB.AppendLine("<br />DestinationUnreachable:" + DestinationUnreachable);
            SB.AppendLine("<br />HardwareError:" + HardwareError);
            SB.AppendLine("<br />IcmpError:" + IcmpError);
            SB.AppendLine("<br />NoResources:" + NoResources);
            SB.AppendLine("<br />PacketTooBig:" + PacketTooBig);
            SB.AppendLine("<br />ParameterProblem:" + ParameterProblem);
            SB.AppendLine("<br />SourceQuench:" + SourceQuench);
            SB.AppendLine("<br />TimeExceeded:" + TimeExceeded);
            SB.AppendLine("<br />TtlExpired:" + TtlExpired);
            SB.AppendLine("<br />TtlReassemblyTimeExceeded:" + TtlReassemblyTimeExceeded);
            SB.AppendLine("<br />Unknown:" + Unknown);
            SB.AppendLine("<br />UnrecognizedNextHeader:" + UnrecognizedNextHeader);
            //---------------------------------------------------------------------------------------
            foreach (ip_adress ip in ALL_Network)
            {
                if (ip.Ping_Status == IPStatus.BadDestination) SB1.AppendLine(ip.ToString()+ " - BadDestination<br />");
                if (ip.Ping_Status == IPStatus.BadHeader) SB1.AppendLine(ip.ToString() + " - BadHeader<br />");
                if (ip.Ping_Status == IPStatus.BadOption) SB1.AppendLine(ip.ToString() + " - BadOption<br />");
                if (ip.Ping_Status == IPStatus.BadRoute) SB1.AppendLine(ip.ToString() + " - BadRoute<br />");
                if (ip.Ping_Status == IPStatus.DestinationHostUnreachable) SB1.AppendLine(ip.ToString() + " - DestinationHostUnreachable<br />");
                if (ip.Ping_Status == IPStatus.DestinationNetworkUnreachable) SB1.AppendLine(ip.ToString() + " - DestinationNetworkUnreachable<br />");
                if (ip.Ping_Status == IPStatus.DestinationPortUnreachable) SB1.AppendLine(ip.ToString() + " - DestinationPortUnreachable<br />");
                if (ip.Ping_Status == IPStatus.DestinationProtocolUnreachable) SB1.AppendLine(ip.ToString() + " - DestinationProtocolUnreachable<br />");
                if (ip.Ping_Status == IPStatus.DestinationScopeMismatch) SB1.AppendLine(ip.ToString() + " - DestinationScopeMismatch<br />");
                if (ip.Ping_Status == IPStatus.DestinationUnreachable) SB1.AppendLine(ip.ToString() + " - DestinationUnreachable<br />");
                if (ip.Ping_Status == IPStatus.HardwareError) SB1.AppendLine(ip.ToString() + " - HardwareError<br />");
                if (ip.Ping_Status == IPStatus.IcmpError) SB1.AppendLine(ip.ToString() + " - IcmpError<br />");
                if (ip.Ping_Status == IPStatus.NoResources) SB1.AppendLine(ip.ToString() + " - NoResources<br />");
                if (ip.Ping_Status == IPStatus.PacketTooBig) SB1.AppendLine(ip.ToString() + " - PacketTooBig<br />");
                if (ip.Ping_Status == IPStatus.ParameterProblem) SB1.AppendLine(ip.ToString() + " - ParameterProblem<br />");
                if (ip.Ping_Status == IPStatus.SourceQuench) SB1.AppendLine(ip.ToString() + " - SourceQuench<br />");
                if (ip.Ping_Status == IPStatus.TimeExceeded) SB1.AppendLine(ip.ToString() + " - TimeExceeded<br />");
                if (ip.Ping_Status == IPStatus.TtlExpired) SB1.AppendLine(ip.ToString() + " - TtlExpired<br />");
                if (ip.Ping_Status == IPStatus.TtlReassemblyTimeExceeded) SB1.AppendLine(ip.ToString() + " - TtlReassemblyTimeExceeded<br />");
                if (ip.Ping_Status == IPStatus.UnrecognizedNextHeader) SB1.AppendLine(ip.ToString() + " - UnrecognizedNextHeader<br />");
                if (ip.Ping_Status == IPStatus.Unknown) SB1.AppendLine(ip.ToString() + " - Unknown<br />");
            }
            using (SqlConnection Connect = new SqlConnection(Conn))
            {
                Connect.Open();
                string sql = "INSERT SIS_PingStatus (Stat,Err) VALUES('" + SB.ToString() + "','"+SB1.ToString()+"')";
                SqlCommand Comm = new SqlCommand(sql, Connect);
                Comm.ExecuteNonQuery();
                Connect.Close();
            }

        }
    }
}
