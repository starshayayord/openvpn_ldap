using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Configuration;
using System.Text.RegularExpressions;
using Novell.Directory.Ldap;
using Syscert = System.Security.Cryptography.X509Certificates;

namespace Mono_ldap
{
	public class OpenVPNConfig
	{
		public string Domain { get; set;}
		public string[] AccessGroups { get; set; }
		public string[] DeniedGroups { get; set; }
		public string[] DomainControllers { get; set; }
		public int DomainControllerPort { get; set; }
		public bool EnableSSL { get; set; }
		public string Username { get; set; }
		public string Password { get; set; }
		public string DomainDC { get; set; }
		public string DomainUsername { get; set; }


		public OpenVPNConfig(string domain, string accessGroups,  string deniedGroups, string domainControllers, string domainControllerPort, string enableSSL, string username, string password )
		{
			if (String.IsNullOrEmpty(domain)) {
				Console.WriteLine("Auth failed. Reason: cannot parse config file: missing 'domain' argument");
				throw new System.ArgumentException("Missing 'domain' argument in app.config");
			}
			else {
				Domain = domain;
			}
			AccessGroups = String.IsNullOrEmpty(accessGroups) ? new string[] { } : Array.ConvertAll(accessGroups.Split(','), p => p.Trim());
			DeniedGroups = String.IsNullOrEmpty(deniedGroups) ? new string[] { } : Array.ConvertAll(deniedGroups.Split(','), p => p.Trim());
			if (String.IsNullOrEmpty(domainControllers)) {
				Console.WriteLine("Auth failed. Reason: cannot parse config file: missing 'domainControllers' argument");
				throw new System.ArgumentException("Missing 'domainControllers' argument in app.config");
			}
			else {
				DomainControllers = String.IsNullOrEmpty(domainControllers) ? new string[] { } : Array.ConvertAll(domainControllers.Split(','), p => p.Trim());
			}
			EnableSSL = Convert.ToBoolean(enableSSL);
			if (Convert.ToInt32(domainControllerPort) == 0) {
				DomainControllerPort = EnableSSL ? 636 : 389;	
			}
			else {
				DomainControllerPort = Convert.ToInt32(domainControllerPort);
			}
			Username = Regex.Replace(username, @"(.*)\\|@(.*)", "", RegexOptions.None);
			Password = password;
			string domainDC =  Regex.Replace(domain, @"\.", ",DC=");
			domainDC = Regex.Replace(domainDC, "^", "DC=");
			DomainDC = domainDC;
			DomainUsername = String.Concat(Domain, @"\", Username);
		}

	}
	class MainClass
	{
		public static int Main(string[] args)
		{
			string username = Environment.GetEnvironmentVariable("username");
			string password = Environment.GetEnvironmentVariable("password");
            OpenVPNConfig config;
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
			{
				Console.WriteLine("Auth failed. Reason: environment variables username or password undefined.");
				System.Environment.Exit(1);
			}
			/*for testing
			string username = @"domain\testusername";
			string password = "testpassword";
			*/


			try
			{
				config = new OpenVPNConfig(ConfigurationManager.AppSettings["domain"], ConfigurationManager.AppSettings["accessGroups"], ConfigurationManager.AppSettings["deniedGroups"],
											 ConfigurationManager.AppSettings["domainControllers"], ConfigurationManager.AppSettings["domainControllerPort"],
														 ConfigurationManager.AppSettings["enableSSL"], username, password);

            }catch
			{
				Console.WriteLine("Auth failed. Reason: something wrong in the configuration file");
				return 1;
			}


			try
			{
				//create connection to Ldap
				LdapConnection connection = BuildConnection(config);
				//connection succeed, login and password are correct and testing rejectGroup membership
				if (config.DeniedGroups.Length != 0)
				{
					//rejectGroup is not null. Testing												
					if (isUserInGroups(config.Username, connection, config.DomainDC, config.DeniedGroups))
					{
						//user was found in rejectGroup
						//AUTH FAILED. EXIT
						connection.Disconnect();
						Console.WriteLine("Auth failed for: '{0}'. Reason: user was found in the reject group.", config.Username);
						return 1;
					}
				}
				if (config.AccessGroups.Length != 0)
				{
					//permitGroup is not null. Testing												
			    	if (isUserInGroups(config.Username, connection, config.DomainDC, config.AccessGroups))
					{
						//user was found in permit Group
						//AUTH PASSED
						connection.Disconnect();
						Console.WriteLine("Auth success for: '{0}'.", config.Username);
						return 0;

					}
					else {
						//user wasn't found in permitGroup
						//AUTH FAILED. EXIT
						connection.Disconnect();
						Console.WriteLine("Auth failed for: '{0}'. Reason: user wasn't found in the permit group.", config.Username);
						return 1;
					}

				}
				connection.Disconnect();
				//All tests passed.
				//AUTH PASS. SUCCESS.
				Console.WriteLine("Auth success for: '{0}'.", config.Username);
				return 0;
			}
			catch 
			{
				Console.WriteLine("Auth failed for: '{0}'", config.Username);
				return 1;
			}

		}
		public static bool searchGroupEntry(LdapConnection lc, String searchBase, string searchFilter)
		{

			bool status = true;
			int searchScope = LdapConnection.SCOPE_SUB;
			String[] attrList = new String[] { "distinguishedName" };
			LdapSearchConstraints cons = new LdapSearchConstraints();
			cons.TimeLimit = 10000;
			try
			{
				LdapSearchResults searchResults =
					lc.Search(searchBase,
						searchScope,
						searchFilter,
						attrList,
						false,
						cons);            // time out value

				LdapEntry nextEntry = null;

				if ((nextEntry = searchResults.next()) == null)
				{
					status = false;
				}
			}
			catch
			{
				status = false;
			}
			return status;
		}
		public static string lookingForGroupDN(LdapConnection lc, String searchBase, string groupName)
		{
			string searchFilter = String.Concat("(&(objectCategory=Group)(cn=", groupName, "))");
			string dn = "";
			int searchScope = LdapConnection.SCOPE_SUB;
			String[] attrList = new String[] { "distinguishedName" };
			LdapSearchConstraints cons = new LdapSearchConstraints();
			cons.TimeLimit = 10000;
			try
			{
				LdapSearchResults searchResults =
					lc.Search(searchBase,
						searchScope,
						searchFilter,
						attrList,
						false,
						cons);            // time out value

				LdapEntry nextEntry = null;
				if ((nextEntry = searchResults.next()) != null)
				{
					LdapAttributeSet attributeSet = nextEntry.getAttributeSet();
					System.Collections.IEnumerator ienum = attributeSet.GetEnumerator();
					while (ienum.MoveNext())
					{
						LdapAttribute attribute = (LdapAttribute)ienum.Current;
						dn = attribute.StringValue;
					}
				}
			}
			catch (LdapException e)
			{
				
				Console.WriteLine("ERROR: Cannot find the group DN {0} (Maybe wrong groupname? ) ", groupName);
				throw new System.Exception(e.ToString());

			}
			return dn;
		}
		public static bool isUserInGroups(string username, LdapConnection connection, string domainDC, string[] groups)
		{
			string searchFilter = "";
			if (groups.Length == 1)
			{
				string groupDN = lookingForGroupDN(connection, domainDC, groups[0]);
				searchFilter = String.Concat("(&(sAMAccountName=", username, ")(memberOf:1.2.840.113556.1.4.1941:=", groupDN, "))");
			}
			else {
				searchFilter = String.Concat("(&(sAMAccountName=", username, ")(|");
				foreach (string group in groups)
				{
					try
					{
						string groupDN = lookingForGroupDN(connection, domainDC, group);
						searchFilter = String.Concat(searchFilter, "(memberOf:1.2.840.113556.1.4.1941:=", groupDN, ")");
					}
					catch
					{
						throw new System.Exception(String.Concat("Cannot get group DN: ", group));
					}
				}
				searchFilter = String.Concat(searchFilter, "))");
			}
			if (searchGroupEntry(connection, domainDC, searchFilter))
			{
				return true;
			}
			return false;
		}

		public static bool CustomSSLHandler(Syscert.X509Certificate certificate, int[] certificateErrors)
		{
			return true;
		}
		public static LdapConnection BuildConnection(OpenVPNConfig config)
		{
			
			var resultCollection = new ConcurrentBag<LdapConnection>();
			ParallelLoopResult res = Parallel.ForEach(config.DomainControllers, (dcServer, state) =>
			{

				LdapConnection connection = new LdapConnection();
				//add ssl options
				if (config.EnableSSL)
				{
					connection.SecureSocketLayer = true;
					connection.UserDefinedServerCertValidationDelegate += new CertificateValidationCallback(CustomSSLHandler);
				}
				try
				{
					//try to bind connection with credentials
					connection.Connect(dcServer, config.DomainControllerPort);
					connection.Bind(config.DomainUsername, config.Password);
					if (connection.Connected)
					{
						resultCollection.Add(connection);
						state.Stop();
					}

				}
				catch (LdapException)
				{
					//cannot connect to the server. It would be processed later.

				}
			});

				LdapConnection usedConnection;
				resultCollection.TryTake(out usedConnection);
				//disconnect other
				LdapConnection c;
				while (resultCollection.TryTake(out c))
				{
					c.Disconnect();
				}
				if (usedConnection != null)
				{
					return usedConnection;
				}
				else {
					throw new System.Exception("Error: Cannot bind connection to LDAP");
				}
				
		}
	}

}
