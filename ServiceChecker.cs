using System;
using System.ServiceProcess;

namespace Symantec.CWoC {
	class ServiceChecker : QueueWorker {
		private string service_name;
		public ServiceChecker(string service) {
			service_name = service;
		}		
		public ServiceChecker() {
			service_name = "AeXNSClient";
		}		
		
		public void RunCheck() {
			while (true)  {
				HostData hostdata = GetHostdata();
				if (hostdata.host_name == "" && hostdata.host_guid == "")
					break;
				TestResult testresult = new TestResult();
				try {
					testresult.host_name = hostdata.host_name;
					testresult.host_guid = hostdata.host_guid;
					ServiceController sc = new ServiceController(service_name, hostdata.host_name);
					if (sc.Status == ServiceControllerStatus.Stopped) {
						// Start the service if it is stopped.
						int i = 0;
						while (i < 5) {
							sc.Start();
							i++;
							sc.Refresh();
							if (sc.Status == ServiceControllerStatus.Running)
								break;
							testresult.status = sc.Status.ToString();
							StoreResult(testresult, "service_check");
						}
						if (i > 4) {
							string status = String.Format("Failed to start the Altiris Agent service {0} times...", (i + 1).ToString());
							testresult.status = status;
							StoreResult(testresult, "service_check");
						}
					} else {
						testresult.status = sc.Status.ToString();
						StoreResult(testresult, "service_check");
					}
				} catch (Exception e) {
					testresult.status = e.Message;
					StoreResult(testresult, "service_check");
				}
			}
		}
	}
}
