using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Windows.Networking.Sockets;

/**
 * Tinfoil is an RFID Privacy and Security Enhancement library.
 *
 *     Copyright (c) 2005 Joe Foley, MIT AutoID Labs

    Permission is hereby granted, free of charge, to any person obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction, including without limitation 
    the rights to use, copy, modify, merge, publish, distribute, sublicense, 
    and/or sell copies of the Software, and to permit persons to whom the 
    Software is furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
    IN THE SOFTWARE. 
 */

/**
* The Onion Router Java Library routines<br />
* These methods allow us to setup an anonymized TCP socket through 
* the Tor network and do safe anonymized DNS lookups.<br />
* This code was written with the help of Roger Dingledine and Nick Mathewson.<br />
* The code is open-source under the MIT X11 license.
* <ul>
* <li><a href = "http://tor.eff.org"> http://tor.eff.org</a>
* <li><a href = "http://tor.eff.org/cvs/control/doc/howto.txt">http://tor.eff.org/cvs/control/doc/howto.txt</a>
* <li><a href = "http://www.mokabyte.it/2000/06/firewallutil.htm">http://www.mokabyte.it/2000/06/firewallutil.htm</a>
* </ul>
* 
* @author Joe Foley<foley at MIT dot EDU>, MIT AutoID Labs
* @version 1.0
* <p>
*/

/* Original source (java librarie): http://web.mit.edu/foley/www/TinFoil/src/tinfoil/TorLib.java

This library has been ported to the UWP ecosystem by void21
*/

namespace Tor
{
    public class TorLib
    {
        // Default Tor Proxy port
        private static int proxyPort = 9050;

        // Default TOR Proxy hostaddr
        private static String proxyAddr = "localhost";

        // Constant tells SOCKS4/4a to connect
        private const byte TOR_CONNECT = 0x01;

        // Constant tells TOR to do a DNS resolve.
        private const byte TOR_RESOLVE = 0xF0;

        // Constant indicates what SOCKS version are talking
        // Either SOCKS4 or SOCKS4a
        private const byte SOCKS_VERSION = 0x04;

        // SOCKS uses Nulls as field delimiters
        private const byte SOCKS_DELIM = 0x00;

        //Setting the IP field to 0.0.0.1 causes SOCKS4a to be enabled.
        private const int SOCKS4A_FAKEIP = 0x01;

        /// <summary>This method Creates a socket, then sends the inital SOCKS request info. It stops before reading so that other methods may differently interpret the results.It returns the open socket.
        ///<para>targetHostname The hostname of the destination host.</para>
        ///<para>targetPort The port to connect to</para>
        ///<para>req SOCKS/TOR request code</para>
        ///</summary>
        public static async Task<StreamSocket> TorSocketPreAsync(String targetHostname, int targetPort, byte req)
        {
            StreamSocket s = new StreamSocket();
            Windows.Networking.HostName proxyAddrHostName = new Windows.Networking.HostName(proxyAddr);

            await s.ConnectAsync(proxyAddrHostName, proxyPort.ToString());

            BinaryWriter _os = new BinaryWriter(s.OutputStream.AsStreamForWrite());
            _os.Write(SOCKS_VERSION);
            _os.Write(req);
            // 2 bytes
            _os.Write((short)targetPort);
            // 4 bytes, high byte first
            _os.Write(SOCKS4A_FAKEIP);
            _os.Write(SOCKS_DELIM);
            _os.Write(targetHostname);
            _os.Write(SOCKS_DELIM);

            _os.Flush();
            _os.Dispose();

            return s;
        }

        /// <summary>This method creates a socket to the target host and port using TorSocketPre, then reads the SOCKS information.
        ///<para>targetHostname The hostname of the destination host.</para>
        ///<para>targetPort Port on remote destination host.</para>
        ///</summary>
        public static async Task<StreamSocket> TorSocketAsync(String targetHostname, int targetPort)
        {
            StreamSocket s = await TorSocketPreAsync(targetHostname, targetPort, TOR_CONNECT);

            BinaryReader _is = new BinaryReader(s.InputStream.AsStreamForRead());
            byte version = _is.ReadByte();
            byte status = _is.ReadByte();

            if (status != 90)
            {
                throw new IOException(ParseSOCKSStatus(status));
            }

            int port = _is.ReadInt16();
            int ipAddr = _is.ReadInt32();

            _is.Dispose();

            return s;
        }

        /// <summary>This method opens a TOR socket, and does an anonymous DNS resolve through it. Since Tor caches things, this is a very fast lookup if we've already connected there. The resolve does a gethostbyname() on the exit node.
        ///<para>targetHostname String containing the hostname to look up.</para>s
        ///</summary>
        public static async Task<String> TorResolveAsync(String targetHostname)
        {
            int targetPort = 0; // we dont need a port to resolve

            try
            {
                StreamSocket s = await TorSocketPreAsync(targetHostname, targetPort, TOR_RESOLVE);

                BinaryReader _is = new BinaryReader(s.InputStream.AsStreamForRead());
                byte version = _is.ReadByte();
                byte status = _is.ReadByte();

                if (status != 90)
                {
                    throw new IOException(ParseSOCKSStatus(status));
                }

                int port = _is.ReadInt16();

                byte[] ipAddrBytes = _is.ReadBytes(4);
                IPAddress ia = new IPAddress(ipAddrBytes);

                _is.Dispose();

                return ia.ToString();
            }
            catch { }
            return null;
        }

        /// <summary>This helper method allows us to decode the SOCKS4 status codes into Human readible output. Based upon info from http://archive.socks.permeo.com/protocol/socks4.protocol
        ///<para>status Byte containing the status code.</para>s
        ///</summary>
        private static String ParseSOCKSStatus(byte status)
        {
            String retval;

            switch (status)
            {
                case 90:
                    retval = status + " Request granted.";
                    break;
                case 91:
                    retval = status + " Request rejected/failed - unknown reason.";
                    break;
                case 92:
                    retval = status + " Request rejected: SOCKS server cannot connect to identd on the client.";
                    break;
                case 93:
                    retval = status + " Request rejected: the client program and identd report different user-ids.";
                    break;
                default:
                    retval = status + " Unknown SOCKS status code.";
                    break;
            }

            return retval;
        }
    }
}
