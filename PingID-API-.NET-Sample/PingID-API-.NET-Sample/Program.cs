using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Net;
using System.IO;
using System.Web.Script.Serialization;

namespace PingID_API_.NET_Sample
{
    class Program
    {
        //Update with your PingID settings:
        public static string org_alias      = "<< org_alias value from pingid.properties file >>";
        public static string use_base64_key = "<< use_base64_key value from pingid.properties file >>";
        public static string token          = "<< token value from pingid.properties file >>";
        public static string api_version    = "4.6";

        public static string Base64UrlEncodeString(string rawString)
        {
            return Base64UrlEncodeString(Encoding.UTF8.GetBytes(rawString));
        }

        public static string Base64UrlEncodeString(byte[] rawBytes)
        {
            var encodedString = Convert.ToBase64String(rawBytes);

            encodedString = encodedString.Replace('+', '-');
            encodedString = encodedString.Replace('/', '_');
            encodedString = encodedString.TrimEnd(new char[] { '=' });

            return encodedString;
        }

        public static byte[] Base64UrlDecodeString(string encodedString)
        {
            encodedString = encodedString.Replace('-', '+');
            encodedString = encodedString.Replace('_', '/');
            encodedString = encodedString.PadRight(encodedString.Length + (4 - encodedString.Length % 4) % 4, '=');

            return Convert.FromBase64String(encodedString);
        }

        public static string DictionaryToJsonString(Dictionary<string, object> dictionary)
        {
            JavaScriptSerializer jsonSerializer = new JavaScriptSerializer();
            return jsonSerializer.Serialize(dictionary);
        }

        public static string sendToken(Dictionary<string, object> requestBody, string apiEndpoint)
        {
            Dictionary<string, object> jwtHeader = new Dictionary<string, object>();
            jwtHeader.Add("alg", "HS256");
            jwtHeader.Add("org_alias", org_alias);
            jwtHeader.Add("token", token);

            var headerSerialized = DictionaryToJsonString(jwtHeader);
            var headerEncoded = Base64UrlEncodeString(headerSerialized);

            Dictionary<string, object> reqHeaderClaims = new Dictionary<string, object>();
            reqHeaderClaims.Add("locale", "en");
            reqHeaderClaims.Add("orgAlias", org_alias);
            reqHeaderClaims.Add("secretKey", token);
            reqHeaderClaims.Add("timestamp", DateTime.UtcNow);
            reqHeaderClaims.Add("version", api_version);

            Dictionary<string, object> jwtPayload = new Dictionary<string, object>();
            jwtPayload.Add("reqHeader", reqHeaderClaims);
            jwtPayload.Add("reqBody", requestBody);

            var payloadSerialized = DictionaryToJsonString(jwtPayload);
            var payloadEncoded = Base64UrlEncodeString(payloadSerialized);

            var signedComponents = String.Join(".", headerEncoded, payloadEncoded);

            var HMAC = new HMACSHA256(Base64UrlDecodeString(use_base64_key));
            var signatureBytes = HMAC.ComputeHash(Encoding.UTF8.GetBytes(signedComponents));
            var signatureEncoded = Base64UrlEncodeString(signatureBytes);

            var apiToken = String.Join(".", signedComponents, signatureEncoded);

            // Send the JWS
            var response = HttpPost(apiEndpoint, apiToken);

            return response;
        }

        public static string HttpPost(string URI, string jwt)
        {
            WebRequest webRequest = WebRequest.Create(URI);

            webRequest.ContentType = "application/json";
            webRequest.Method = "POST";
            byte[] payload = Encoding.UTF8.GetBytes(jwt);
            webRequest.ContentLength = payload.Length;

            Stream outputStream = webRequest.GetRequestStream();
            outputStream.Write(payload, 0, payload.Length);
            outputStream.Close();

            WebResponse webResponse = webRequest.GetResponse();
            if (webResponse == null) return null;

            StreamReader sr = new StreamReader(webResponse.GetResponseStream());
            return sr.ReadToEnd().Trim();
        }

        static void Main(string[] args)
        {
            // Example call to the GetUserDetails operation

            string userName = "meredith";

            Dictionary<string, object> reqBody = new Dictionary<string, object>();
            reqBody.Add("userName", userName);
            reqBody.Add("getSameDeviceUsers", false);

            var apiEndpoint = "https://idpxnyl3m.pingidentity.com/pingid/rest/4/getuserdetails/do";

            string apiResponse = sendToken(reqBody, apiEndpoint);

            string[] responseComponents = apiResponse.Split(new char[] { '.' });

            string responsePayload = responseComponents[1];
            string responsePayloadDecoded = Encoding.UTF8.GetString(Base64UrlDecodeString(responsePayload));

            Console.WriteLine("Payload: ");
            Console.WriteLine(responsePayloadDecoded);

            Console.WriteLine("Press a key to continue... ");
            Console.ReadLine();
        }
    }
}
