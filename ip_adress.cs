using System;
using System.Net;
using System.Net.NetworkInformation;

namespace SCANER
{
    class ip_adress
    {
        public uint Adress { get; set; }
        public string Community { get; set; }
        public IPStatus Ping_Status { get; set; }
        public ip_adress(uint newAdress)
        {
            Community = string.Empty;
            Ping_Status = IPStatus.Unknown;
            Adress = newAdress;
        }
        public ip_adress(byte[] newAdress)
        {
            Community = string.Empty;
            Ping_Status = IPStatus.Unknown;
            Adress = (uint)((int)newAdress[3] << 24 | (int)newAdress[2] << 16 | (int)newAdress[1] << 8 | (int)newAdress[0]) & uint.MaxValue;
        }

        public string ToString()
        {
            return new IPAddress(Adress).ToString();
        }
    }
}
