using System;
using System.Collections.ObjectModel;
using System.Collections;
using System.ServiceProcess;
using System.Text;
using System.Data;
using System.Threading;
using System.Net.NetworkInformation;
using Altiris.NS.Logging;
using Altiris.NS.Security;
using Symantec.CWoC.APIWrappers;

namespace Symantec.CWoC {
    class PingComputers {
	
		public static readonly string sql = @"
set rowcount 500
SELECT i.fqdn, c.Guid
  FROM [vComputerResource] c
 INNER JOIN (
			select [ResourceGuid], max([ModifiedDate]) as LatestInventoryDate from dbo.ResourceUpdateSummary  
			where InventoryClassGuid = '9E6F402A-6A45-4CBA-9299-C2323F73A506'     
			group by [ResourceGuid]  
		) as dt
	ON c.Guid = dt.ResourceGuid
  LEFT JOIN Inv_AeX_AC_IDentification i
    ON c.Guid = i._ResourceGuid
 WHERE c.IsManaged = 1 
   AND dt.LatestInventoryDate < getdate() - 7
";

		public static void Main() {
			try {
				Timer main_timer = new Timer();
				SecurityContextManager.SetContextData();
				DataTable computers = DatabaseAPI.GetTable(sql);
				
				Pinger pinger = new Pinger();
				
				foreach (DataRow r in computers.Rows) {
					HostData d = new HostData(r[0].ToString(), r[1].ToString());
					pinger.HostQueue.Enqueue(d);
				}

				// Create a thread pool to run the ping task
				ThreadPool pinger_thread_pool = new ThreadPool();
				Thread pinger_status_thread = new Thread(new ThreadStart(pinger.PrintStatus));
				pinger_thread_pool.PoolDepth = pinger.HostQueue.Count / 10;
				pinger.ThreadPoolDepth = pinger_thread_pool.PoolDepth;

				pinger_status_thread.Start();
				
				Timer ping_timer = new Timer();
				pinger_thread_pool.StartAll(pinger.RunPing);
				pinger_status_thread.Join();
				
				Console.WriteLine("Ping task ran for {0} ms.", ping_timer.duration);
				ping_timer.init();
				pinger_thread_pool.JoinAll();
				Console.WriteLine("Thread convergence took {0} ms.", ping_timer.duration);

				Console.WriteLine("\n\rDequeueing results (we have {0} entries)...", pinger.ResultQueue.Count.ToString());
			
				// Move to stage 2: check the Altiris Agent status if possible
				ServiceChecker sc = new ServiceChecker();
				TestResult result = new TestResult();
				HostData hostdata = new HostData();

				while (pinger.ResultQueue.Count > 0) {
					result = (TestResult) pinger.ResultQueue.Dequeue();
					if (result.status == "1") {
						hostdata = new HostData(result.host_name, result.host_guid);
						sc.HostQueue.Enqueue(hostdata);
					}
				}

				ThreadPool sc_thread_pool = new ThreadPool();
				Thread sc_status_thread = new Thread(new ThreadStart(sc.PrintStatus));
				sc_thread_pool.PoolDepth = sc.HostQueue.Count / 5;
				sc.ThreadPoolDepth = sc_thread_pool.PoolDepth;

				sc_status_thread.Start();

				Timer sc_timer = new Timer();
				sc_thread_pool.StartAll(sc.RunCheck);
				sc_status_thread.Join();
				Console.WriteLine("Done processing service control requests (we had {0} entries) in {1} ms...", sc.ResultQueue.Count.ToString(), sc_timer.duration);
				sc_thread_pool.JoinAll();
				
				Console.WriteLine("Processing of {3} entries completed in {0} ms, using {1} threads for ping and {2} threads for service control checks."
					, main_timer.duration
					, pinger_thread_pool.PoolDepth.ToString()
					, sc_thread_pool.PoolDepth.ToString()
					, computers.Rows.Count.ToString()
					);
			} catch (Exception e) {
				EventLog.ReportError(String.Format("{0}\n{1}", e.Message, e.InnerException));
			}
			Console.WriteLine("Waiting for thread and process tear down...");
		}
    }

	class HostData {
		public string host_name;
		public string host_guid;
		
		public HostData() {
			host_name = "";
			host_guid = "";
		}
		
		public HostData(string name, string guid) {
			host_name = name;
			host_guid = guid;
		}
	}
	
	class TestResult : HostData {
		public string status;
		
		public TestResult() {
			status = "";
		}
		
		public TestResult(string _status) {
			status = _status;
		}
	}
	
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

    class Timer {
        private System.Diagnostics.Stopwatch chrono;
		public string duration {
			get {
				return chrono.ElapsedMilliseconds.ToString();
			}
		}
		
		public string tickcount {
			get {
				return chrono.ElapsedTicks.ToString();
			}
		}
		
		public Timer() {
			init();
		}

        public void init() {
            chrono = new System.Diagnostics.Stopwatch();
            chrono.Start();
        }

        public void start() {
            chrono.Start();
        }

        public void stop() {
            chrono.Stop();
        }
    }
	
}
