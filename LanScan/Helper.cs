using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using static System.Text.RegularExpressions.Regex;
using static System.Net.Dns;

namespace LanScan
{
    internal class Helper
    {
        public static List<IpV4Object> GetCurrentIpv4List()
        {
            var ipV4List = new List<IpV4Object>();

            // loop though NICs
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                // only process LAN or WIFI NICs
                if (ni.NetworkInterfaceType != NetworkInterfaceType.Wireless80211 &&
                    ni.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue;

                // loop through each ip on nic and add to list
                foreach (var ip in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ip.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    var gateway = string.Empty;
                    if (ni.GetIPProperties().GatewayAddresses.Count > 0)
                    {
                        gateway = ni.GetIPProperties().GatewayAddresses[0].Address.ToString();
                    }
                    ipV4List.Add(new IpV4Object
                    {
                        Interface = ni.Name,
                        IpV4Address = ip.Address.ToString(),
                        MacAddress =
                            $"{ni.GetPhysicalAddress().ToString().Substring(0, 2)}-{ni.GetPhysicalAddress().ToString().Substring(2, 2)}-{ni.GetPhysicalAddress().ToString().Substring(4, 2)}-{ni.GetPhysicalAddress().ToString().Substring(6, 2)}-{ni.GetPhysicalAddress().ToString().Substring(8, 2)}-{ni.GetPhysicalAddress().ToString().Substring(10, 2)}",
                        Gateway = gateway,
                        Subnet = ip.IPv4Mask.ToString(),
                        Hostname = GetHostName()
                    });
                }
            }
            return ipV4List;
        }

        public static string GetMac(string ip)
        {
            if (GetCurrentIpv4List().FindAll(x => x.IpV4Address.Contains(ip)).Count != 0)
            {
                return GetCurrentIpv4List().Find(x => x.IpV4Address.Contains(ip)).MacAddress;
            }
            if (ip.Length == 0)
                return "No MAC Found";

            var p = Process.Start(new ProcessStartInfo("arp", "-a " + ip)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true
            });
            string i;
            while (p != null && (i = p.StandardOutput.ReadLine()) != null)
            {
                if (!i.Contains("Interface") && !i.Contains("Internet") && !i.Contains("Entries") && i.Length != 0)
                {
                    return Replace(i, @"\s+", " ").Split(' ')[2];
                }
            }
            return "No MAC Found";
        }

        public static void ScanSubnet(string firstIp)
        {
            // validate starting ip address
            var startIp = IPAddress.None;
            IPAddress.TryParse(firstIp, out startIp);
            if (startIp == null)
                return;

            // define ping object and add output header
            var pinger = new Ping();
            Console.WriteLine("IP Address\tMAC Address\t\tHostname");
            for (var i = 1; i <= 254; i++)
            {
                // get subnet to scan
                var ipAddress =
                    $"{startIp.GetAddressBytes()[0]}.{startIp.GetAddressBytes()[1]}.{startIp.GetAddressBytes()[2]}.{i}";
                var ping = pinger.Send(ipAddress, 100);
                if (ping == null || ping.Status != IPStatus.Success) continue;

                // try to get hostname
                var hostname = new IPHostEntry();
                try
                {
                    hostname = GetHostEntry(ipAddress);
                }
                catch (Exception)
                {
                    // ignored
                }

                // output to screen
                Console.WriteLine(hostname.HostName == ipAddress
                    ? $"{ipAddress}\t{GetMac(ipAddress)}"
                    : $"{ipAddress}\t{GetMac(ipAddress)}\t{hostname.HostName}");
            }
        }

        public static void ScanSubnet(string firstIp, string lastIp)
        {
            var startIp = IPAddress.None;
            var endIp = IPAddress.None;
            IPAddress.TryParse(firstIp, out startIp);
            IPAddress.TryParse(lastIp, out endIp);

            if (startIp == null || endIp == null)
                return;

            var pinger = new Ping();
            Console.WriteLine("IP Address\tMAC Address\t\tHostname");
            if (startIp.GetAddressBytes()[2] == endIp.GetAddressBytes()[2])
            {
                for (var i = startIp.GetAddressBytes()[3]; i <= endIp.GetAddressBytes()[3]; i++)
                {
                    var ipAddress =
                        $"{startIp.GetAddressBytes()[0]}.{startIp.GetAddressBytes()[1]}.{startIp.GetAddressBytes()[2]}.{i}";
                    var ping = pinger.Send(ipAddress, 100);
                    if (ping == null || ping.Status != IPStatus.Success) continue;

                    // try to get hostname
                    var hostname = new IPHostEntry();
                    try
                    {
                        hostname = GetHostEntry(ipAddress);
                    }
                    catch (Exception)
                    {
                        // ignored
                    }
                    Console.WriteLine(hostname.HostName == ipAddress
                        ? $"{ipAddress}\t{GetMac(ipAddress)}"
                        : $"{ipAddress}\t{GetMac(ipAddress)}\t{hostname.HostName}");
                }
            }
            else
            {
                for (int i = startIp.GetAddressBytes()[2]; i <= endIp.GetAddressBytes()[2]; i++)
                {
                    for (var j = startIp.GetAddressBytes()[3]; j <= endIp.GetAddressBytes()[3]; j++)
                    {
                        var ipAddress = $"{startIp.GetAddressBytes()[0]}.{startIp.GetAddressBytes()[1]}.{i}.{j}";
                        var ping = pinger.Send(ipAddress, 100);
                        if (ping == null || ping.Status != IPStatus.Success) continue;

                        // try to get hostname
                        var hostname = new IPHostEntry();
                        try
                        {
                            hostname = GetHostEntry(ipAddress);
                        }
                        catch (Exception)
                        {
                            // ignored
                        }
                        Console.WriteLine(hostname.HostName == ipAddress
                            ? $"{ipAddress}\t{GetMac(ipAddress)}"
                            : $"{ipAddress}\t{GetMac(ipAddress)}\t{hostname.HostName}");
                    }
                }
            }
        }
    }
}