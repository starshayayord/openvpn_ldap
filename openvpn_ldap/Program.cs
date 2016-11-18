using System;
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
		public string DomainController { get; set; }
		public int DomainControllerPort { get; set; }
		public bool EnableSSL { get; set; }
		public string Username { get; set; }
		public string Password { get; set; }
		public string DomainDC { get; set; }
		public string DomainUsername { get; set; }


		public OpenVPNConfig(string domain, string accessGroups,  string deniedGroups, string domainController, string domainControllerPort, string enableSSL, string username, string password )
		{
			if (String.IsNullOrEmpty(domain)) {
				Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString()," ", DateTime.Now.ToShortDateString(), " ERROR: Cannot parse config file: missing 'domain' argument"));
				throw new System.ArgumentException("Missing 'domain' argument in app.config");
			}
			else {
				Domain = domain;
			}
			AccessGroups = String.IsNullOrEmpty(accessGroups) ? new string[] { } : Array.ConvertAll(accessGroups.Split(','), p => p.Trim());
			DeniedGroups = String.IsNullOrEmpty(deniedGroups) ? new string[] { } : Array.ConvertAll(deniedGroups.Split(','), p => p.Trim());
			if (String.IsNullOrEmpty(domainController)) {
				Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: Cannot parse config file: missing 'domainController' argument"));
			}
			else {
				DomainController = domainController;
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
			if (String.IsNullOrEmpty(username) || String.IsNullOrEmpty(password))
			{
				Console.WriteLine("environment variables username or password undefined");
				System.Environment.Exit(1);
			}
			/*for testing
			string username = @"domain\testusername";
			string password = "testpassword";
			*/

			try
			{
				OpenVPNConfig config = new OpenVPNConfig(ConfigurationManager.AppSettings["domain"], ConfigurationManager.AppSettings["accessGroups"], ConfigurationManager.AppSettings["deniedGroups"],
											 ConfigurationManager.AppSettings["domainController"], ConfigurationManager.AppSettings["domainControllerPort"],
														 ConfigurationManager.AppSettings["enableSSL"], username, password);
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
							Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), DateTime.Now.ToShortDateString(), " ERROR: User was found in the reject group. Access denied. User: ", config.Username));
							connection.Disconnect();
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
							return 0;

						}
						else {
							//user wasn't found in permitGroup
							//AUTH FAILED. EXIT
							Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: User wasn't found in the permit group. Access denied. User: ", config.Username));
							connection.Disconnect();
							return 1;
						}

					}
					connection.Disconnect();
					//All tests passed.
					//AUTH PASS. SUCCESS.
					return 0;
				}
				catch 
				{
					Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: Exit. User: ", config.Username));
					return 1;
				}
			}
			catch
			{
				Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: Something wrong in the configuration file. Exit"));
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
				Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: Cannot find the group DN: ", groupName ,". (Maybe wrong groupname? ) ", e.ToString()));
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
				connection.Connect(config.DomainController, config.DomainControllerPort);
				connection.Bind(config.DomainUsername, config.Password);
				if (connection.Connected)
				{
					return connection;
				}
				else {
					throw new System.Exception("Error: Cannot bind connection to LDAP");
				}
			}
			catch
			{
				Console.WriteLine(String.Concat(DateTime.Now.ToShortTimeString(), " ", DateTime.Now.ToShortDateString(), " ERROR: Cannot bind connection to LDAP"));
				throw new System.Exception("Error: Cannot bind connection to LDAP");
			}
		}
	}

}
