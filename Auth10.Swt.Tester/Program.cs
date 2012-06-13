using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Collections.Specialized;
using System.Security.Authentication;
using System.IO;
using System.Globalization;
using System.Web.Script.Serialization;
using Auth10.Swt;

namespace Auth10.Swt.Tester
{
    class Program
    {
        const string AcsNamespace =     "...";
        const string ClientId =         "...";
        const string ClientSecret =     "...";
        const string Scope =            "...";
        const string SharedKeyBase64 =  "...";

        const string Issuer = "https://" + AcsNamespace + ".accesscontrol.windows.net/";

        static void Main(string[] args)
        {
            var token = GetSwtTokenFromAcs();
            ConsoleColor defaultColor = Console.ForegroundColor;

            Console.WriteLine("========= Test valid token ============");
            TestValidToken(token);

            Console.ForegroundColor = defaultColor;
            Console.WriteLine("");
            Console.WriteLine("========= Test invalid token ============");
            TestInvalidToken(token);

            Console.ForegroundColor = defaultColor;
            Console.WriteLine("");
            Console.WriteLine("========= Test valid audience ============");
            TestValidAudience(token);

            Console.ForegroundColor = defaultColor;
            Console.WriteLine("");
            Console.WriteLine("========= Test invalid audience ============");
            TestInvalidAudience(token);

            Console.ForegroundColor = defaultColor;
            Console.WriteLine("");
            Console.WriteLine("========= Test valid issuer ============");
            TestValidIssuer(token);

            Console.ForegroundColor = defaultColor;
            Console.WriteLine("");
            Console.WriteLine("========= Test invalid issuer ============");
            TestInvalidIssuer(token);

            Console.ForegroundColor = defaultColor;
            Console.ReadLine();
        }

        private static void TestValidToken(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = SharedKeyBase64;

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static void TestInvalidToken(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = "ERRMwAE1aGd8MbhrUUx+aid+nogvSgeGO2HeGRK8/ps=";

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static void TestValidAudience(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = SharedKeyBase64;
            validator.AllowedAudiences.Add(new Uri(Scope));

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static void TestInvalidAudience(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = SharedKeyBase64;
            validator.AllowedAudiences.Add(new Uri("urn:notvalid"));

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static void TestValidIssuer(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = SharedKeyBase64;
            validator.AllowedIssuer = Issuer;

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static void TestInvalidIssuer(string token)
        {
            var validator = new SimpleWebTokenValidator();
            validator.SharedKeyBase64 = SharedKeyBase64;
            validator.AllowedIssuer = "urn:invalid:issuer";

            SimpleWebToken swt = null;
            try
            {
                swt = validator.ValidateToken(token);
                Console.WriteLine("Valid token");
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.ToString());
            }

            if (swt != null)
            {
                foreach (var claim in swt.Claims)
                {
                    Console.WriteLine(claim.Key + ":" + claim.Value);
                }
            }
        }

        private static string GetSwtTokenFromAcs()
        {
            return GetSwtTokenFromAcs(AcsNamespace, ClientId, ClientSecret, Scope);
        }

        private static string GetSwtTokenFromAcs(string serviceNamespace, string clientId, string clientSecret, string scope)
        {
            WebClient client = new WebClient();

            client.BaseAddress = string.Format(CultureInfo.CurrentCulture,
                                               "https://{0}.{1}",
                                               serviceNamespace,
                                               "accesscontrol.windows.net");

            NameValueCollection values = new NameValueCollection();
            values.Add("grant_type", "client_credentials");
            values.Add("client_id", clientId);
            values.Add("client_secret", clientSecret);
            values.Add("scope", scope);

            byte[] responseBytes = null;
            try
            {
                responseBytes = client.UploadValues("/v2/OAuth2-13", "POST", values);
            }
            catch (WebException ex)
            {
                throw new InvalidOperationException(new StreamReader(ex.Response.GetResponseStream()).ReadToEnd());
            }
            string response = Encoding.UTF8.GetString(responseBytes);

            // Parse the JSON response and return the access token 
            var serializer = new JavaScriptSerializer();

            Dictionary<string, object> decodedDictionary = serializer.DeserializeObject(response) as Dictionary<string, object>;

            return decodedDictionary["access_token"] as string;
        }
    }
}
