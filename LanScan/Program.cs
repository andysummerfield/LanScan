using System;
using System.Net;
using static LanScan.Helper;

namespace LanScan
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            try
            {
                // declare vars
                var firstIp = string.Empty;
                var lastIp = string.Empty;
                var parseTest = IPAddress.None;
                var currentIpList = GetCurrentIpv4List();

                // check for switches
                foreach (var arg in args)
                {
                    if (arg.Length > 7 && arg.Substring(0, 6) == "/first")
                        firstIp = arg.Substring(7);
                    else if (arg.Length > 6 && arg.Substring(0, 5) == "/last")
                        lastIp = arg.Substring(6);
                }

                // validate inputs
                IPAddress.TryParse(firstIp, out parseTest);
                if (firstIp.Length > 0 && !IPAddress.TryParse(firstIp, out parseTest))
                {
                    Console.WriteLine("Invalid first IP");
                    return;
                }
                parseTest = IPAddress.None;
                IPAddress.TryParse(lastIp, out parseTest);
                if (lastIp.Length > 0 && !IPAddress.TryParse(lastIp, out parseTest))
                {
                    Console.WriteLine("Invalid last IP");
                    return;
                }

                // begin scanning based on switchs
                if (firstIp.Length > 0 && lastIp.Length > 0)
                {
                    Console.WriteLine($"\nScan Range:{firstIp} - {lastIp}\n");
                    ScanSubnet(firstIp, lastIp);
                }
                else if (firstIp.Length > 0)
                {
                    Console.WriteLine(
                        $"\nScan Range:{firstIp.Split('.')[0]}.{firstIp.Split('.')[1]}.{firstIp.Split('.')[2]}.0/24\n");
                    ScanSubnet(firstIp);
                }
                else
                {
                    var range = string.Empty;
                    foreach (var ip in currentIpList)
                    {
                        if (
                            $"\nScan Range:{ip.IpV4Address.Split('.')[0]}.{ip.IpV4Address.Split('.')[1]}.{ip.IpV4Address.Split('.')[2]}.0/24\n" ==
                            range)
                            continue;
                        range =
                            $"\nScan Range:{ip.IpV4Address.Split('.')[0]}.{ip.IpV4Address.Split('.')[1]}.{ip.IpV4Address.Split('.')[2]}.0/24\n";
                        Console.WriteLine(range);
                        ScanSubnet(ip.IpV4Address);
                    }
                }

                // Output scanning device details
                Console.WriteLine("\nCurrent Device Details:-");
                foreach (var ip in currentIpList)
                {
                    Console.WriteLine($"Interface:\t{ip.Interface}");
                    Console.WriteLine($"Hostname:\t{ip.Hostname}");
                    Console.WriteLine($"IP Address:\t{ip.IpV4Address}");
                    Console.WriteLine($"MAC Address:\t{ip.MacAddress}");
                    Console.WriteLine($"Subnet Mask:\t{ip.Subnet}");
                    Console.WriteLine($"Gateway Mask:\t{ip.Gateway}\n");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.InnerException);
                throw;
            }
        }
    }
}