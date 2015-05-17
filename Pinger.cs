using System;
using System.Net.NetworkInformation;

namespace Symantec.CWoC {
	class Pinger : QueueWorker {	
		public void RunPing () {
			while (true)  {
				HostData hostdata = GetHostdata();
				if (hostdata.host_name == "" && hostdata.host_guid == "")
					break;
				TestResult testresult = new TestResult();
				try {
					testresult.host_name = hostdata.host_name;
					testresult.host_guid = hostdata.host_guid;
					
					Ping ping = new Ping();
					PingReply result = ping.Send(hostdata.host_name);

					if (result.Status == IPStatus.Success) {
						testresult.status = "1";
						StoreResult(testresult, "ping");
					} else {
						testresult.status = "0";
						StoreResult(testresult, "ping");	
					}
				} catch (Exception e){
					testresult.status = e.Message;
					StoreResult(testresult, "ping");
				}
			}
		}
	}
}
